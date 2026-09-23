package dissect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// QUICv1 Initial salt (RFC 9001 §5.2).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// InitialSecrets holds client Initial AEAD + header-protection keys.
type InitialSecrets struct {
	Key []byte // 16
	IV  []byte // 12
	HP  []byte // 16
}

// DeriveClientInitialSecrets derives QUICv1 client Initial keys from DCID.
func DeriveClientInitialSecrets(dcid []byte) (*InitialSecrets, error) {
	initialSecret := hkdfExtract(sha256.New, quicV1InitialSalt, dcid)
	clientSecret, err := hkdfExpandLabel(sha256.New, initialSecret, "client in", nil, 32)
	if err != nil {
		return nil, err
	}
	key, err := hkdfExpandLabel(sha256.New, clientSecret, "quic key", nil, 16)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabel(sha256.New, clientSecret, "quic iv", nil, 12)
	if err != nil {
		return nil, err
	}
	hp, err := hkdfExpandLabel(sha256.New, clientSecret, "quic hp", nil, 16)
	if err != nil {
		return nil, err
	}
	return &InitialSecrets{Key: key, IV: iv, HP: hp}, nil
}

func hkdfExtract(hash func() hash.Hash, salt, ikm []byte) []byte {
	return hkdf.Extract(hash, ikm, salt)
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label with "tls13 " prefix
// (RFC 8446 §7.1) — required for QUIC Initial even when TLS 1.3 is not negotiated yet.
func hkdfExpandLabel(hash func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	const prefix = "tls13 "
	hkdfLabel := make([]byte, 2+1+len(prefix)+len(label)+1+len(context))
	binary.BigEndian.PutUint16(hkdfLabel[0:2], uint16(length))
	hkdfLabel[2] = byte(len(prefix) + len(label))
	copy(hkdfLabel[3:], prefix+label)
	o := 3 + len(prefix) + len(label)
	hkdfLabel[o] = byte(len(context))
	copy(hkdfLabel[o+1:], context)
	out := make([]byte, length)
	r := hkdf.Expand(hash, secret, hkdfLabel)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// DecryptedInitial is an Initial packet after header + packet protection removal.
type DecryptedInitial struct {
	Header      *QUICLongHeader
	PacketNumber uint64
	Payload     []byte
	Frames      []QUICFrame
	CryptoData  []byte // concatenated CRYPTO frame data (offset-ordered best-effort)
	ClientHello *ClientHello
	Transport   []TransportParam
	Findings    []string
}

// DecryptInitial parses and decrypts a QUICv1 client Initial UDP payload.
func DecryptInitial(b []byte) (*DecryptedInitial, error) {
	h, err := ParseQUICLongHeader(b)
	if err != nil {
		return nil, err
	}
	if h.Type != QUICLongInitial {
		return nil, fmt.Errorf("quic: want Initial packet, got %s", quicLongTypeName(h.Type))
	}
	if h.Version != QUICVersion1 {
		return nil, fmt.Errorf("quic: Initial decrypt only for version 1 (got 0x%08x)", h.Version)
	}
	sec, err := DeriveClientInitialSecrets(h.DCID)
	if err != nil {
		return nil, err
	}
	if h.SampleOffset+16 > len(b) {
		return nil, fmt.Errorf("quic: packet too short for HP sample")
	}
	sample := b[h.SampleOffset : h.SampleOffset+16]
	mask, err := aesECBMask(sec.HP, sample)
	if err != nil {
		return nil, err
	}

	// Unprotect first byte (only lower 4 bits for long headers).
	first := b[0] ^ (mask[0] & 0x0f)
	pnLen := int(first&0x03) + 1
	if h.PNOffset+pnLen > len(b) {
		return nil, fmt.Errorf("quic: truncated packet number")
	}
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = b[h.PNOffset+i] ^ mask[1+i]
	}
	var pn uint64
	for _, x := range pnBytes {
		pn = pn<<8 | uint64(x)
	}

	// Rebuild unprotected header for AEAD AAD.
	hdr := append([]byte(nil), b[:h.PNOffset]...)
	hdr[0] = first
	hdr = append(hdr, pnBytes...)

	payloadStart := h.PNOffset + pnLen
	ct := b[payloadStart:]
	if len(ct) < 16 {
		return nil, fmt.Errorf("quic: ciphertext too short")
	}
	aead, err := aesGCM(sec.Key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, len(sec.IV))
	copy(nonce, sec.IV)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plain, err := aead.Open(nil, nonce, ct, hdr)
	if err != nil {
		return nil, fmt.Errorf("quic: AEAD open failed (wrong version/DCID or truncated capture): %w", err)
	}

	out := &DecryptedInitial{
		Header:       h,
		PacketNumber: pn,
		Payload:      plain,
	}
	out.Header.FirstByte = first
	out.Header.PNLength = pnLen
	out.Frames = ParseQUICFrames(plain)
	out.CryptoData = gatherCRYPTO(out.Frames)
	if len(out.CryptoData) > 0 {
		if ch, err := ParseClientHello(out.CryptoData); err == nil {
			out.ClientHello = ch
			if tp := extractQUICTransportParams(ch); tp != nil {
				out.Transport = tp
			}
		}
	}
	out.Findings = initialFindings(out)
	return out, nil
}

func aesECBMask(hpKey, sample []byte) ([]byte, error) {
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)
	return mask, nil
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func initialFindings(d *DecryptedInitial) []string {
	var out []string
	out = append(out, fmt.Sprintf("QUICv1 Initial decrypted PN=%d DCID=%x SCID=%x", d.PacketNumber, d.Header.DCID, d.Header.SCID))
	if len(d.Header.Token) > 0 {
		out = append(out, fmt.Sprintf("Initial token present (%d bytes) — Retry / NEW_TOKEN path", len(d.Header.Token)))
	} else {
		out = append(out, "Empty Initial token — first flight (common)")
	}
	hasCrypto := false
	hasPadding := false
	hasPing := false
	for _, fr := range d.Frames {
		switch fr.Type {
		case QUICFrameCRYPTO:
			hasCrypto = true
		case QUICFramePadding:
			hasPadding = true
		case QUICFramePing:
			hasPing = true
		}
	}
	if hasCrypto {
		out = append(out, "CRYPTO frame(s) present — TLS handshake messages (ClientHello) live here, not in TCP")
	} else {
		out = append(out, "No CRYPTO frames — unusual for a client Initial")
	}
	if hasPadding {
		out = append(out, "PADDING present — Chromium pads Initials toward path MTU / anti-amplification")
	}
	if hasPing {
		out = append(out, "PING in Initial — uncommon for browsers")
	}
	if d.ClientHello != nil {
		out = append(out, fmt.Sprintf("Embedded ClientHello parsed (SNI=%q, %d extensions)", d.ClientHello.SNI, len(d.ClientHello.Extensions)))
	}
	if len(d.Transport) > 0 {
		grease := 0
		for _, tp := range d.Transport {
			if tp.GREASE {
				grease++
			}
		}
		out = append(out, fmt.Sprintf("quic_transport_parameters: %d entries (%d GREASE)", len(d.Transport), grease))
		if grease == 0 {
			out = append(out, "No GREASE transport parameters — many naive QUIC stacks forget 31·N+27")
		} else {
			out = append(out, "GREASE TPs observed — strong Chromium/quic-go family signal")
		}
	} else if d.ClientHello != nil {
		out = append(out, "ClientHello without quic_transport_parameters (0x39) — not a QUIC TLS hello, or TP in a later CRYPTO")
	}
	return out
}
