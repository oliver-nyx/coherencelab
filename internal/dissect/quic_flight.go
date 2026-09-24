package dissect

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// InitialFlightMagic marks a multi-datagram Initial capture (Firefox often
// splits CRYPTO across several Initials; Chromium usually fits in one).
var InitialFlightMagic = []byte("CLQI")

const initialFlightVersion uint16 = 1

// IsInitialFlight reports a length-prefixed multi-Initial capture file.
func IsInitialFlight(b []byte) bool {
	return len(b) >= 8 && bytes.Equal(b[:4], InitialFlightMagic)
}

// EncodeInitialFlight packs one or more UDP datagrams (each may itself be
// coalesced; DecryptInitial truncates to Length).
func EncodeInitialFlight(datagrams [][]byte) ([]byte, error) {
	if len(datagrams) == 0 {
		return nil, fmt.Errorf("quic: empty Initial flight")
	}
	if len(datagrams) > 0xffff {
		return nil, fmt.Errorf("quic: too many datagrams in flight")
	}
	var out []byte
	out = append(out, InitialFlightMagic...)
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:2], initialFlightVersion)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(datagrams)))
	out = append(out, hdr[:]...)
	for _, dg := range datagrams {
		if len(dg) > 0xffffffff {
			return nil, fmt.Errorf("quic: datagram too large")
		}
		var ln [4]byte
		binary.BigEndian.PutUint32(ln[:], uint32(len(dg)))
		out = append(out, ln[:]...)
		out = append(out, dg...)
	}
	return out, nil
}

// DecodeInitialFlight unpacks a CLQI multi-Initial file.
func DecodeInitialFlight(b []byte) ([][]byte, error) {
	if !IsInitialFlight(b) {
		return nil, fmt.Errorf("quic: not an Initial flight (missing CLQI magic)")
	}
	ver := binary.BigEndian.Uint16(b[4:6])
	if ver != initialFlightVersion {
		return nil, fmt.Errorf("quic: unsupported Initial flight version %d", ver)
	}
	n := int(binary.BigEndian.Uint16(b[6:8]))
	o := 8
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		if o+4 > len(b) {
			return nil, fmt.Errorf("quic: truncated flight length at packet %d", i)
		}
		ln := int(binary.BigEndian.Uint32(b[o : o+4]))
		o += 4
		if ln < 0 || o+ln > len(b) {
			return nil, fmt.Errorf("quic: truncated flight packet %d", i)
		}
		out = append(out, append([]byte(nil), b[o:o+ln]...))
		o += ln
	}
	return out, nil
}

// DecryptInitialCapture decrypts a single UDP Initial or a CLQI flight file.
func DecryptInitialCapture(b []byte) (*DecryptedInitial, error) {
	if IsInitialFlight(b) {
		pkts, err := DecodeInitialFlight(b)
		if err != nil {
			return nil, err
		}
		return DecryptInitialFlight(pkts)
	}
	return DecryptInitial(b)
}

// DecryptInitialFlight decrypts one or more client Initials (same DCID) and
// merges CRYPTO frames so fragmented ClientHellos (Firefox) reassemble.
func DecryptInitialFlight(datagrams [][]byte) (*DecryptedInitial, error) {
	if len(datagrams) == 0 {
		return nil, fmt.Errorf("quic: empty Initial flight")
	}
	var base *DecryptedInitial
	var frames []QUICFrame
	var dcidKey string
	var decrypted int
	var lastErr error
	for _, dg := range datagrams {
		d, err := DecryptInitial(dg)
		if err != nil {
			lastErr = err
			continue
		}
		key := hex.EncodeToString(d.Header.DCID)
		if base == nil {
			base = d
			dcidKey = key
		} else if key != dcidKey {
			continue
		}
		frames = append(frames, d.Frames...)
		decrypted++
	}
	if base == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("quic: no decryptable Initial in flight")
	}
	base.Frames = frames
	base.CryptoData = gatherCRYPTO(frames)
	base.ClientHello = nil
	base.Transport = nil
	if len(base.CryptoData) > 0 {
		if ch, err := ParseClientHello(base.CryptoData); err == nil {
			base.ClientHello = ch
			if tp := extractQUICTransportParams(ch); tp != nil {
				base.Transport = tp
			}
		}
	}
	base.Findings = initialFindings(base)
	if decrypted > 1 {
		base.Findings = append(base.Findings,
			fmt.Sprintf("Merged CRYPTO from %d Initials (same DCID) — Firefox-style fragmented ClientHello", decrypted))
	}
	return base, nil
}
