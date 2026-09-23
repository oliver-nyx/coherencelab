package dissect

import (
	"encoding/binary"
	"fmt"
)

// Extension type IDs (IANA TLS).
const (
	ExtServerName           uint16 = 0
	ExtStatusRequest        uint16 = 5
	ExtSupportedGroups      uint16 = 10
	ExtECPointFormats       uint16 = 11
	ExtSignatureAlgorithms  uint16 = 13
	ExtALPN                 uint16 = 16
	ExtSCT                  uint16 = 18
	ExtPadding              uint16 = 21
	ExtExtendedMasterSecret uint16 = 23
	ExtCompressCertificate  uint16 = 27
	ExtSessionTicket        uint16 = 35
	ExtPreSharedKey         uint16 = 41
	ExtEarlyData            uint16 = 42
	ExtSupportedVersions    uint16 = 43
	ExtCookie               uint16 = 44
	ExtPSKKeyExchangeModes  uint16 = 45
	ExtCertificateAuthorities uint16 = 47
	ExtPostHandshakeAuth    uint16 = 49
	ExtSignatureAlgorithmsCert uint16 = 50
	ExtKeyShare             uint16 = 51
	ExtRenegotiationInfo    uint16 = 0xff01
	ExtEncryptedClientHello uint16 = 0xfe0d
	// Chrome / BoringSSL application settings (ALPS), not final IANA.
	ExtApplicationSettings  uint16 = 17513 // 0x4469
	ExtApplicationSettingsNew uint16 = 17613
)

// Extension is one TLS extension in ClientHello order (order is the fingerprint).
type Extension struct {
	Type    uint16
	Data    []byte
	GREASE  bool
	Name    string
	Decoded string // human decode when known
	Note    string // RE teaching note
}

// ClientHello is a fully parsed ClientHello (handshake message body + record meta).
type ClientHello struct {
	// Record layer
	RecordContentType uint8
	RecordVersion     uint16
	RecordLength      uint16

	// Handshake
	HandshakeType   uint8
	HandshakeLength uint32

	// Body
	LegacyVersion      uint16
	Random             []byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []Extension

	// Convenience indexes
	SNI                string
	ALPN               []string
	SupportedVersions  []uint16
	SupportedGroups    []uint16
	ECPointFormats     []uint8
	SignatureAlgs      []uint16
	KeyShares          []KeyShare
	HasECH             bool
	HasALPS            bool
	ExtensionOrder     []uint16
	GREASECipherCount  int
	GREASEExtensionCount int

	Raw []byte // original bytes (record or raw handshake, as provided)
}

// KeyShare is a TLS 1.3 key_share entry.
type KeyShare struct {
	Group GREASEAware16
	Key   []byte
}

// GREASEAware16 tags GREASE groups/suites.
type GREASEAware16 struct {
	Value  uint16
	GREASE bool
}

// ParseClientHello parses a TLS record containing a ClientHello, or a bare
// handshake message starting with type=0x01.
func ParseClientHello(b []byte) (*ClientHello, error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("dissect: buffer too short for TLS record")
	}
	ch := &ClientHello{Raw: append([]byte(nil), b...)}
	off := 0

	// Detect record layer vs bare handshake.
	if b[0] == 0x16 { // handshake record
		ch.RecordContentType = b[0]
		ch.RecordVersion = binary.BigEndian.Uint16(b[1:3])
		ch.RecordLength = binary.BigEndian.Uint16(b[3:5])
		off = 5
		if int(ch.RecordLength)+5 > len(b) {
			// allow trailing data; require declared length present
			if len(b) < off+4 {
				return nil, fmt.Errorf("dissect: truncated record")
			}
		}
	}

	if len(b) < off+4 {
		return nil, fmt.Errorf("dissect: truncated handshake header")
	}
	ch.HandshakeType = b[off]
	if ch.HandshakeType != 0x01 {
		return nil, fmt.Errorf("dissect: not a ClientHello (type=0x%02x)", ch.HandshakeType)
	}
	ch.HandshakeLength = uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3])
	off += 4
	end := off + int(ch.HandshakeLength)
	if end > len(b) {
		end = len(b) // tolerate truncated captures with best-effort parse
	}
	body := b[off:end]
	if err := parseClientHelloBody(ch, body); err != nil {
		return nil, err
	}
	annotateClientHello(ch)
	return ch, nil
}

func parseClientHelloBody(ch *ClientHello, body []byte) error {
	if len(body) < 34 {
		return fmt.Errorf("dissect: ClientHello body too short")
	}
	o := 0
	ch.LegacyVersion = binary.BigEndian.Uint16(body[o : o+2])
	o += 2
	ch.Random = append([]byte(nil), body[o:o+32]...)
	o += 32

	if o >= len(body) {
		return fmt.Errorf("dissect: missing session_id length")
	}
	sidLen := int(body[o])
	o++
	if o+sidLen > len(body) {
		return fmt.Errorf("dissect: truncated session_id")
	}
	ch.SessionID = append([]byte(nil), body[o:o+sidLen]...)
	o += sidLen

	if o+2 > len(body) {
		return fmt.Errorf("dissect: missing cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[o : o+2]))
	o += 2
	if csLen%2 != 0 || o+csLen > len(body) {
		return fmt.Errorf("dissect: bad cipher suites length %d", csLen)
	}
	for i := 0; i < csLen; i += 2 {
		v := binary.BigEndian.Uint16(body[o+i : o+i+2])
		ch.CipherSuites = append(ch.CipherSuites, v)
		if IsGREASE16(v) {
			ch.GREASECipherCount++
		}
	}
	o += csLen

	if o >= len(body) {
		return fmt.Errorf("dissect: missing compression length")
	}
	compLen := int(body[o])
	o++
	if o+compLen > len(body) {
		return fmt.Errorf("dissect: truncated compression methods")
	}
	ch.CompressionMethods = append([]byte(nil), body[o:o+compLen]...)
	o += compLen

	if o == len(body) {
		return nil // no extensions (SSLv2-era oddity; modern browsers always send)
	}
	if o+2 > len(body) {
		return fmt.Errorf("dissect: truncated extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(body[o : o+2]))
	o += 2
	if o+extLen > len(body) {
		extLen = len(body) - o
	}
	extEnd := o + extLen
	for o+4 <= extEnd {
		typ := binary.BigEndian.Uint16(body[o : o+2])
		l := int(binary.BigEndian.Uint16(body[o+2 : o+4]))
		o += 4
		if o+l > extEnd {
			return fmt.Errorf("dissect: truncated extension 0x%04x", typ)
		}
		data := append([]byte(nil), body[o:o+l]...)
		o += l
		ext := Extension{
			Type:   typ,
			Data:   data,
			GREASE: IsGREASE16(typ),
			Name:   extensionName(typ),
		}
		if ext.GREASE {
			ch.GREASEExtensionCount++
		}
		decodeExtension(ch, &ext)
		ch.Extensions = append(ch.Extensions, ext)
		ch.ExtensionOrder = append(ch.ExtensionOrder, typ)
	}
	return nil
}

func decodeExtension(ch *ClientHello, ext *Extension) {
	switch ext.Type {
	case ExtServerName:
		ch.SNI = parseSNI(ext.Data)
		ext.Decoded = ch.SNI
	case ExtALPN:
		ch.ALPN = parseALPN(ext.Data)
		ext.Decoded = fmt.Sprintf("%v", ch.ALPN)
	case ExtSupportedVersions:
		ch.SupportedVersions = parseSupportedVersions(ext.Data)
		ext.Decoded = formatVersions(ch.SupportedVersions)
	case ExtSupportedGroups:
		ch.SupportedGroups = parseUint16List(ext.Data)
		ext.Decoded = formatGroups(ch.SupportedGroups)
	case ExtECPointFormats:
		if len(ext.Data) >= 1 {
			n := int(ext.Data[0])
			if 1+n <= len(ext.Data) {
				ch.ECPointFormats = append([]byte(nil), ext.Data[1:1+n]...)
				ext.Decoded = fmt.Sprintf("%v", ch.ECPointFormats)
			}
		}
	case ExtSignatureAlgorithms:
		ch.SignatureAlgs = parseUint16List(ext.Data)
		ext.Decoded = fmt.Sprintf("%d algs", len(ch.SignatureAlgs))
	case ExtKeyShare:
		ch.KeyShares = parseKeyShare(ext.Data)
		ext.Decoded = fmt.Sprintf("%d shares", len(ch.KeyShares))
	case ExtEncryptedClientHello:
		ch.HasECH = true
		ext.Decoded = fmt.Sprintf("ECH payload %d bytes", len(ext.Data))
	case ExtApplicationSettings, ExtApplicationSettingsNew:
		ch.HasALPS = true
		ext.Decoded = fmt.Sprintf("ALPS %d bytes", len(ext.Data))
	case ExtPadding:
		ext.Decoded = fmt.Sprintf("padding %d bytes", len(ext.Data))
	}
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// list_length(2) + name_type(1) + name_length(2) + host
	if data[2] != 0 { // host_name
		return ""
	}
	n := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+n > len(data) {
		return ""
	}
	return string(data[5 : 5+n])
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	o := 2 // skip list length
	var out []string
	for o < len(data) {
		l := int(data[o])
		o++
		if o+l > len(data) {
			break
		}
		out = append(out, string(data[o:o+l]))
		o += l
	}
	return out
}

func parseUint16List(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(data[0:2]))
	o := 2
	if o+n > len(data) {
		n = len(data) - o
	}
	var out []uint16
	for i := 0; i+1 < n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[o+i:o+i+2]))
	}
	return out
}

// parseSupportedVersions handles ClientHello's 1-byte vector length
// (RFC 8446: ProtocolVersion versions<2..254>).
func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	n := int(data[0])
	o := 1
	if o+n > len(data) {
		n = len(data) - o
	}
	var out []uint16
	for i := 0; i+1 < n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[o+i:o+i+2]))
	}
	return out
}

func parseKeyShare(data []byte) []KeyShare {
	if len(data) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(data[0:2]))
	o := 2
	end := o + n
	if end > len(data) {
		end = len(data)
	}
	var out []KeyShare
	for o+4 <= end {
		g := binary.BigEndian.Uint16(data[o : o+2])
		o += 2
		kl := int(binary.BigEndian.Uint16(data[o : o+2]))
		o += 2
		if o+kl > end {
			break
		}
		out = append(out, KeyShare{
			Group: GREASEAware16{Value: g, GREASE: IsGREASE16(g)},
			Key:   append([]byte(nil), data[o:o+kl]...),
		})
		o += kl
	}
	return out
}

func extensionName(t uint16) string {
	if IsGREASE16(t) {
		return "GREASE"
	}
	switch t {
	case ExtServerName:
		return "server_name"
	case ExtStatusRequest:
		return "status_request"
	case ExtSupportedGroups:
		return "supported_groups"
	case ExtECPointFormats:
		return "ec_point_formats"
	case ExtSignatureAlgorithms:
		return "signature_algorithms"
	case ExtALPN:
		return "application_layer_protocol_negotiation"
	case ExtSCT:
		return "signed_certificate_timestamp"
	case ExtPadding:
		return "padding"
	case ExtExtendedMasterSecret:
		return "extended_master_secret"
	case ExtCompressCertificate:
		return "compress_certificate"
	case ExtSessionTicket:
		return "session_ticket"
	case ExtPreSharedKey:
		return "pre_shared_key"
	case ExtEarlyData:
		return "early_data"
	case ExtSupportedVersions:
		return "supported_versions"
	case ExtCookie:
		return "cookie"
	case ExtPSKKeyExchangeModes:
		return "psk_key_exchange_modes"
	case ExtPostHandshakeAuth:
		return "post_handshake_auth"
	case ExtSignatureAlgorithmsCert:
		return "signature_algorithms_cert"
	case ExtKeyShare:
		return "key_share"
	case ExtRenegotiationInfo:
		return "renegotiation_info"
	case ExtEncryptedClientHello:
		return "encrypted_client_hello"
	case ExtApplicationSettings:
		return "application_settings (ALPS)"
	case ExtApplicationSettingsNew:
		return "application_settings_new (ALPS)"
	default:
		return fmt.Sprintf("unknown(0x%04x)", t)
	}
}

func formatVersions(vs []uint16) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		if IsGREASE16(v) {
			parts = append(parts, fmt.Sprintf("GREASE(0x%04x)", v))
			continue
		}
		parts = append(parts, tlsVersionName(v))
	}
	return joinComma(parts)
}

func formatGroups(gs []uint16) string {
	parts := make([]string, 0, len(gs))
	for _, g := range gs {
		if IsGREASE16(g) {
			parts = append(parts, fmt.Sprintf("GREASE(0x%04x)", g))
			continue
		}
		parts = append(parts, groupName(g))
	}
	return joinComma(parts)
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func groupName(g uint16) string {
	switch g {
	case 23:
		return "secp256r1"
	case 24:
		return "secp384r1"
	case 25:
		return "secp521r1"
	case 29:
		return "x25519"
	case 30:
		return "x448"
	case 4588: // 0x11ec — X25519Kyber768Draft00 / hybrid
		return "x25519Kyber768 / MLKEM hybrid"
	default:
		return fmt.Sprintf("0x%04x", g)
	}
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
