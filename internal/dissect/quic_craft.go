package dissect

import (
	"crypto/rand"
	"fmt"
)

// CraftChromeLikeInitial builds a QUICv1 client Initial containing a CRYPTO
// ClientHello with quic_transport_parameters (including GREASE). Protected
// with RFC 9001 Initial secrets — round-trips through DecryptInitial.
func CraftChromeLikeInitial() ([]byte, error) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x11}
	tps := chromeLikeTransportParams()
	cryptoMsg := minimalQUICClientHello("example.com", tps)
	payload := buildInitialPayload(cryptoMsg)

	sec, err := DeriveClientInitialSecrets(dcid)
	if err != nil {
		return nil, err
	}
	return sealInitial(dcid, scid, nil, 0, payload, sec)
}

// CraftMinimalTransportParams returns a raw TP blob without GREASE (naive stack).
func CraftMinimalTransportParams() []byte {
	var b []byte
	b = AppendTransportParam(b, TPMaxIdleTimeout, EncodeVarintTPValue(30000))
	b = AppendTransportParam(b, TPInitialMaxData, EncodeVarintTPValue(65536))
	b = AppendTransportParam(b, TPInitialMaxStreamsBidi, EncodeVarintTPValue(100))
	return b
}

func chromeLikeTransportParams() []byte {
	var b []byte
	b = AppendTransportParam(b, TPMaxIdleTimeout, EncodeVarintTPValue(30000))
	b = AppendTransportParam(b, TPMaxUDPPayloadSize, EncodeVarintTPValue(1472))
	b = AppendTransportParam(b, TPInitialMaxData, EncodeVarintTPValue(15728640))
	b = AppendTransportParam(b, TPInitialMaxStreamDataBidiLocal, EncodeVarintTPValue(6291456))
	b = AppendTransportParam(b, TPInitialMaxStreamDataBidiRemote, EncodeVarintTPValue(6291456))
	b = AppendTransportParam(b, TPInitialMaxStreamDataUni, EncodeVarintTPValue(6291456))
	b = AppendTransportParam(b, TPInitialMaxStreamsBidi, EncodeVarintTPValue(100))
	b = AppendTransportParam(b, TPInitialMaxStreamsUni, EncodeVarintTPValue(100))
	b = AppendTransportParam(b, TPAckDelayExponent, EncodeVarintTPValue(3))
	b = AppendTransportParam(b, TPMaxAckDelay, EncodeVarintTPValue(25))
	b = AppendTransportParam(b, TPActiveConnectionIDLimit, EncodeVarintTPValue(8))
	b = AppendTransportParam(b, TPInitialSourceConnectionID, []byte{0x11})
	b = AppendTransportParam(b, TPGreaseQUICBit, nil)
	// GREASE TP id = 31*N+27 → N=1 → 58 = 0x3a
	b = AppendTransportParam(b, 58, []byte{0xde, 0xad})
	return b
}

func minimalQUICClientHello(sni string, tps []byte) []byte {
	var body []byte
	body = append(body, 0x03, 0x03) // legacy_version TLS 1.2
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)
	body = append(body, rnd...)
	body = append(body, 0)          // session_id length
	body = append(body, 0x00, 0x02) // cipher suites len
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00) // compression

	var exts []byte
	// server_name
	host := []byte(sni)
	sniData := make([]byte, 0, 5+len(host))
	sniData = append(sniData, byte((len(host)+3)>>8), byte(len(host)+3))
	sniData = append(sniData, 0x00) // host_name
	sniData = append(sniData, byte(len(host)>>8), byte(len(host)))
	sniData = append(sniData, host...)
	exts = appendExtension(exts, 0x0000, sniData)
	// supported_versions — TLS 1.3 only
	exts = appendExtension(exts, 0x002b, []byte{0x02, 0x03, 0x04})
	// quic_transport_parameters
	exts = appendExtension(exts, ExtQUICTransportParameters, tps)
	// alpn h3
	exts = appendExtension(exts, 0x0010, []byte{0x00, 0x03, 0x02, 'h', '3'})

	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	msg := make([]byte, 4+len(body))
	msg[0] = 0x01 // ClientHello
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)
	return msg
}

func appendExtension(dst []byte, typ uint16, data []byte) []byte {
	dst = append(dst, byte(typ>>8), byte(typ))
	dst = append(dst, byte(len(data)>>8), byte(len(data)))
	return append(dst, data...)
}

func buildInitialPayload(cryptoMsg []byte) []byte {
	var b []byte
	b = AppendVarint(b, QUICFrameCRYPTO)
	b = AppendVarint(b, 0) // offset
	b = AppendVarint(b, uint64(len(cryptoMsg)))
	b = append(b, cryptoMsg...)
	// Pad toward >= 1200 UDP payload later in sealInitial
	return b
}

func sealInitial(dcid, scid, token []byte, pn uint64, payload []byte, sec *InitialSecrets) ([]byte, error) {
	pnLen := 1
	first := byte(0xc0 | 0x00<<4 | byte(pnLen-1)) // form=1 fixed=1 type=Initial pnLen=1

	var hdr []byte
	hdr = append(hdr, first)
	hdr = append(hdr, byte(QUICVersion1>>24), byte(QUICVersion1>>16), byte(QUICVersion1>>8), byte(QUICVersion1))
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = AppendVarint(hdr, uint64(len(token)))
	hdr = append(hdr, token...)

	// Pad payload so UDP datagram is at least 1200 bytes (anti-amplification).
	pnOffsetGuess := len(hdr) + 2 /* length varint budget */ + pnLen
	minPayload := 1200 - pnOffsetGuess
	if minPayload < len(payload)+16 {
		minPayload = len(payload) + 16
	}
	for len(payload) < minPayload-16 {
		payload = append(payload, 0x00) // PADDING frames (type 0)
	}

	length := uint64(pnLen + len(payload) + 16) // PN + ciphertext(incl tag)
	hdr = AppendVarint(hdr, length)
	pnOffset := len(hdr)
	pnBytes := []byte{byte(pn)}
	aad := append(append([]byte(nil), hdr...), pnBytes...)

	aead, err := aesGCM(sec.Key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, len(sec.IV))
	copy(nonce, sec.IV)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	ct := aead.Seal(nil, nonce, payload, aad)

	packet := append(aad, ct...)

	// Header protection
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(packet) {
		return nil, fmt.Errorf("craft: packet too short for sample")
	}
	mask, err := aesECBMask(sec.HP, packet[sampleOffset:sampleOffset+16])
	if err != nil {
		return nil, err
	}
	packet[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet, nil
}
