package dissect

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

// QUICv1 Retry Integrity Tag key/nonce (RFC 9001 §5.8).
var (
	quicRetryKey   = mustDecodeHex("be0c690b9f66575a1d766b54e368c84e")
	quicRetryNonce = mustDecodeHex("461599d35d632bf2239825bb")
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// VersionNegotiation is a Version Negotiation packet (RFC 9000 §17.2.1).
type VersionNegotiation struct {
	FirstByte  byte
	DCID       []byte
	SCID       []byte
	Versions   []uint32
	Findings   []string
	Raw        []byte
}

// ParseVersionNegotiation parses a VN packet (Version field MUST be 0).
func ParseVersionNegotiation(b []byte) (*VersionNegotiation, error) {
	if len(b) < 7 {
		return nil, fmt.Errorf("quic vn: too short")
	}
	if b[0]&0x80 == 0 {
		return nil, fmt.Errorf("quic vn: not a long header")
	}
	ver := uint32(b[1])<<24 | uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4])
	if ver != 0 {
		return nil, fmt.Errorf("quic vn: version must be 0 (got 0x%08x) — not a Version Negotiation packet", ver)
	}
	vn := &VersionNegotiation{FirstByte: b[0], Raw: append([]byte(nil), b...)}
	o := 5
	dcidLen := int(b[o])
	o++
	if o+dcidLen > len(b) {
		return nil, fmt.Errorf("quic vn: truncated DCID")
	}
	vn.DCID = append([]byte(nil), b[o:o+dcidLen]...)
	o += dcidLen
	if o >= len(b) {
		return nil, fmt.Errorf("quic vn: truncated SCID len")
	}
	scidLen := int(b[o])
	o++
	if o+scidLen > len(b) {
		return nil, fmt.Errorf("quic vn: truncated SCID")
	}
	vn.SCID = append([]byte(nil), b[o:o+scidLen]...)
	o += scidLen
	if (len(b)-o)%4 != 0 {
		return nil, fmt.Errorf("quic vn: supported versions not multiple of 4 (%d remaining)", len(b)-o)
	}
	for o+4 <= len(b) {
		v := uint32(b[o])<<24 | uint32(b[o+1])<<16 | uint32(b[o+2])<<8 | uint32(b[o+3])
		vn.Versions = append(vn.Versions, v)
		o += 4
	}
	vn.Findings = vnFindings(vn)
	return vn, nil
}

func vnFindings(vn *VersionNegotiation) []string {
	var out []string
	out = append(out, "Version Negotiation (version=0) — server does not speak the client's offered version")
	if len(vn.Versions) == 0 {
		out = append(out, "No supported versions listed — malformed VN")
		return out
	}
	hasV1 := false
	grease := 0
	for _, v := range vn.Versions {
		if v == QUICVersion1 {
			hasV1 = true
		}
		if IsQUICVersionGREASE(v) {
			grease++
		}
	}
	if hasV1 {
		out = append(out, "Lists QUICv1 (0x00000001) — client can retry with version 1")
	} else {
		out = append(out, "No QUICv1 in supported list — exotic / future-only server")
	}
	if grease > 0 {
		out = append(out, fmt.Sprintf("%d GREASE version(s) (0x?a?a?a?a) — Chromium-style VN grease", grease))
	} else {
		out = append(out, "No GREASE versions — many naive servers only advertise 0x00000001")
	}
	out = append(out, "VN has no AEAD — anyone can forge it; clients must not treat it as authenticated")
	return out
}

// RetryPacket is a Retry long-header packet (RFC 9000 §17.2.5).
type RetryPacket struct {
	Header        *QUICLongHeader
	RetryToken    []byte
	IntegrityTag  []byte
	TagValid      *bool // nil if ODCID not provided for verification
	ODCID         []byte
	Findings      []string
}

// ParseRetry parses a Retry packet. If odcid is non-nil, verifies the
// Retry Integrity Tag (RFC 9001 §5.8) against that original DCID.
func ParseRetry(b []byte, odcid []byte) (*RetryPacket, error) {
	h, err := ParseQUICLongHeader(b)
	if err != nil {
		return nil, err
	}
	if h.Type != QUICLongRetry {
		return nil, fmt.Errorf("quic retry: want Retry type, got %s", quicLongTypeName(h.Type))
	}
	if h.Version == 0 {
		return nil, fmt.Errorf("quic retry: version 0 is Version Negotiation, not Retry")
	}
	rest := b[len(h.HeaderBytes):]
	if len(rest) < 16 {
		return nil, fmt.Errorf("quic retry: need ≥16-byte integrity tag, have %d", len(rest))
	}
	r := &RetryPacket{
		Header:       h,
		RetryToken:   append([]byte(nil), rest[:len(rest)-16]...),
		IntegrityTag: append([]byte(nil), rest[len(rest)-16:]...),
		ODCID:        append([]byte(nil), odcid...),
	}
	if len(odcid) > 0 || odcid != nil {
		// Allow empty ODCID (zero-length) — still verifiable.
		ok := VerifyRetryIntegrity(b, odcid)
		r.TagValid = &ok
	}
	r.Findings = retryFindings(r)
	return r, nil
}

// VerifyRetryIntegrity checks the Retry Integrity Tag (RFC 9001 §5.8).
func VerifyRetryIntegrity(retryPacket, odcid []byte) bool {
	if len(retryPacket) < 16 {
		return false
	}
	got := retryPacket[len(retryPacket)-16:]
	body := retryPacket[:len(retryPacket)-16]
	pseudo := make([]byte, 0, 1+len(odcid)+len(body))
	pseudo = append(pseudo, byte(len(odcid)))
	pseudo = append(pseudo, odcid...)
	pseudo = append(pseudo, body...)

	block, err := aes.NewCipher(quicRetryKey)
	if err != nil {
		return false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	// Empty plaintext; Seal returns ciphertext||tag with empty CT → tag only.
	tag := aead.Seal(nil, quicRetryNonce, nil, pseudo)
	return bytes.Equal(tag, got)
}

// ComputeRetryIntegrityTag builds the 16-byte tag for a Retry body (no tag yet).
func ComputeRetryIntegrityTag(retryBody, odcid []byte) ([]byte, error) {
	pseudo := make([]byte, 0, 1+len(odcid)+len(retryBody))
	pseudo = append(pseudo, byte(len(odcid)))
	pseudo = append(pseudo, odcid...)
	pseudo = append(pseudo, retryBody...)
	block, err := aes.NewCipher(quicRetryKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, quicRetryNonce, nil, pseudo), nil
}

func retryFindings(r *RetryPacket) []string {
	var out []string
	out = append(out, fmt.Sprintf("Retry packet version=0x%08x — address validation / anti-amplification", r.Header.Version))
	out = append(out, fmt.Sprintf("Retry Token: %d bytes — client must echo this in the next Initial token field", len(r.RetryToken)))
	out = append(out, fmt.Sprintf("SCID (%x) becomes the client's next DCID; ODCID is carried in transport params", r.Header.SCID))
	if r.TagValid == nil {
		out = append(out, "Integrity tag not verified — pass original DCID (client's first Initial DCID) to check")
	} else if *r.TagValid {
		out = append(out, "Retry Integrity Tag VALID — sender observed the client's Initial DCID")
	} else {
		out = append(out, "Retry Integrity Tag INVALID — forged / wrong ODCID / corruption")
	}
	if r.Header.Version != QUICVersion1 {
		out = append(out, "Non-v1 Retry — integrity constants in this lab are QUICv1-specific")
	}
	return out
}

// DetectQUICPacketClass classifies a UDP payload for the lab CLI.
func DetectQUICPacketClass(b []byte) string {
	if IsInitialFlight(b) {
		return "initial"
	}
	if len(b) < 5 {
		return "too_short"
	}
	if b[0]&0x80 == 0 {
		return "short_header"
	}
	ver := uint32(b[1])<<24 | uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4])
	if ver == 0 {
		return "version_negotiation"
	}
	typ := int((b[0] & 0x30) >> 4)
	switch typ {
	case QUICLongInitial:
		return "initial"
	case QUICLongRetry:
		return "retry"
	case QUICLong0RTT:
		return "0rtt"
	case QUICLongHandshake:
		return "handshake"
	default:
		return "long_unknown"
	}
}
