package dissect

import (
	"fmt"
)

// QUIC long-header packet types (RFC 9000 §17.2) — high 2 bits of the
// type nibble after form/fixed bits are cleared via (firstByte & 0x30) >> 4.
const (
	QUICLongInitial   = 0x0
	QUICLong0RTT      = 0x1
	QUICLongHandshake = 0x2
	QUICLongRetry     = 0x3
)

// QUICVersion1 is the wire version for RFC 9000.
const QUICVersion1 uint32 = 0x00000001

// QUICLongHeader is the version-dependent long header before packet protection.
type QUICLongHeader struct {
	FirstByte    byte
	Version      uint32
	Type         int // 0=Initial … 3=Retry
	PNLength     int // 1..4 (from header; may be restored after HP removal)
	DCID         []byte
	SCID         []byte
	Token        []byte // Initial only
	Length       uint64 // length of PN + payload (Initial/0-RTT/Handshake)
	HeaderBytes  []byte // unprotected header up to (not including) PN
	PNOffset     int    // absolute offset of packet number in the UDP payload
	SampleOffset int    // absolute offset of 16-byte HP sample
	Raw          []byte // full UDP datagram (or packet bytes) provided
	Note         string
}

// ParseQUICLongHeader parses a QUIC long header from the start of b.
// Does not remove header protection — PNLength from the wire may be wrong
// until DecryptInitial is applied.
func ParseQUICLongHeader(b []byte) (*QUICLongHeader, error) {
	if len(b) < 6 {
		return nil, fmt.Errorf("quic: packet too short for long header")
	}
	if b[0]&0x80 == 0 {
		return nil, fmt.Errorf("quic: short header (1-RTT) — this lab starts at Initial long headers")
	}
	h := &QUICLongHeader{
		FirstByte: b[0],
		Version:   uint32(b[1])<<24 | uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4]),
		Type:      int((b[0] & 0x30) >> 4),
		PNLength:  int(b[0]&0x03) + 1,
		Raw:       append([]byte(nil), b...),
	}
	if b[0]&0x40 == 0 {
		h.Note = "Fixed Bit clear — not a valid QUIC packet (or grease_quic_bit peer)"
	}
	o := 5
	if o >= len(b) {
		return nil, fmt.Errorf("quic: truncated after version")
	}
	dcidLen := int(b[o])
	o++
	if o+dcidLen > len(b) {
		return nil, fmt.Errorf("quic: truncated DCID")
	}
	h.DCID = append([]byte(nil), b[o:o+dcidLen]...)
	o += dcidLen
	if o >= len(b) {
		return nil, fmt.Errorf("quic: truncated before SCID len")
	}
	scidLen := int(b[o])
	o++
	if o+scidLen > len(b) {
		return nil, fmt.Errorf("quic: truncated SCID")
	}
	h.SCID = append([]byte(nil), b[o:o+scidLen]...)
	o += scidLen

	switch h.Type {
	case QUICLongInitial:
		tokLen, n, err := ReadVarint(b[o:])
		if err != nil {
			return nil, fmt.Errorf("quic: token length: %w", err)
		}
		o += n
		if uint64(len(b)-o) < tokLen {
			return nil, fmt.Errorf("quic: truncated token")
		}
		h.Token = append([]byte(nil), b[o:o+int(tokLen)]...)
		o += int(tokLen)
		plen, n, err := ReadVarint(b[o:])
		if err != nil {
			return nil, fmt.Errorf("quic: length: %w", err)
		}
		o += n
		h.Length = plen
		h.HeaderBytes = append([]byte(nil), b[:o]...)
		h.PNOffset = o
		// Sample starts 4 bytes after PN start (RFC 9001 §5.4.2), regardless of PN length.
		h.SampleOffset = o + 4
	case QUICLong0RTT, QUICLongHandshake:
		plen, n, err := ReadVarint(b[o:])
		if err != nil {
			return nil, fmt.Errorf("quic: length: %w", err)
		}
		o += n
		h.Length = plen
		h.HeaderBytes = append([]byte(nil), b[:o]...)
		h.PNOffset = o
		h.SampleOffset = o + 4
	case QUICLongRetry:
		h.HeaderBytes = append([]byte(nil), b[:o]...)
		h.Note = "Retry packet — no PN/payload AEAD; remainder is Retry Token + integrity tag"
	default:
		return nil, fmt.Errorf("quic: unknown long type %d", h.Type)
	}
	if h.Version != QUICVersion1 && h.Version != 0 {
		h.Note = fmt.Sprintf("version=0x%08x — Initial decrypt in this lab only implements QUICv1 (0x00000001); grease/negotiation versions still parse headers", h.Version)
	}
	if IsQUICVersionGREASE(h.Version) {
		h.Note = "GREASE QUIC version (0x?a?a?a?a pattern) — real Chromium paints these in VN / negotiation"
	}
	return h, nil
}

// IsQUICVersionGREASE reports draft-ietf-quic-version-negotiation grease versions:
// of the form 0x?a?a?a?a — each nibble pair ends in 0xa (Chromium/quic-go test:
// (version & 0x0f0f0f0f) == 0x0a0a0a0a).
func IsQUICVersionGREASE(v uint32) bool {
	return v&0x0f0f0f0f == 0x0a0a0a0a
}

func quicLongTypeName(t int) string {
	switch t {
	case QUICLongInitial:
		return "Initial"
	case QUICLong0RTT:
		return "0-RTT"
	case QUICLongHandshake:
		return "Handshake"
	case QUICLongRetry:
		return "Retry"
	default:
		return fmt.Sprintf("type_%d", t)
	}
}
