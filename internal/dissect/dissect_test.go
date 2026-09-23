package dissect

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestIsGREASE(t *testing.T) {
	if !IsGREASE16(0x0a0a) || !IsGREASE16(0xaaaa) || !IsGREASE16(0x1a1a) {
		t.Fatal("expected GREASE")
	}
	if IsGREASE16(0x0010) || IsGREASE16(0x002b) || IsGREASE16(0xfe0d) {
		t.Fatal("false positive GREASE")
	}
}

func TestParseMinimalClientHello(t *testing.T) {
	// Hand-crafted ClientHello record — readable for RE students.
	body := buildMinimalHelloBody(t)
	rec := make([]byte, 5+4+len(body))
	rec[0] = 0x16
	binary.BigEndian.PutUint16(rec[1:3], 0x0301) // record version TLS 1.0 (common)
	binary.BigEndian.PutUint16(rec[3:5], uint16(4+len(body)))
	rec[5] = 0x01 // ClientHello
	rec[6] = byte((len(body) >> 16) & 0xff)
	rec[7] = byte((len(body) >> 8) & 0xff)
	rec[8] = byte(len(body) & 0xff)
	copy(rec[9:], body)

	ch, err := ParseClientHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	if ch.LegacyVersion != 0x0303 {
		t.Fatalf("legacy version 0x%04x", ch.LegacyVersion)
	}
	if ch.SNI != "example.com" {
		t.Fatalf("SNI=%q", ch.SNI)
	}
	if len(ch.ALPN) != 2 || ch.ALPN[0] != "h2" {
		t.Fatalf("ALPN=%v", ch.ALPN)
	}
	if !hasVersion(ch.SupportedVersions, 0x0304) {
		t.Fatal("expected TLS 1.3 in supported_versions")
	}
	if ch.GREASECipherCount != 1 {
		t.Fatalf("GREASE ciphers=%d", ch.GREASECipherCount)
	}
	ja3 := ch.JA3Raw()
	if ja3 == "" || ch.JA3Hash() == "" {
		t.Fatal("empty JA3")
	}
	findings := ch.Findings()
	if len(findings) < 2 {
		t.Fatalf("expected findings, got %v", findings)
	}
}

func buildMinimalHelloBody(t *testing.T) []byte {
	t.Helper()
	var b []byte
	// legacy_version
	b = append(b, 0x03, 0x03)
	// random 32
	for i := 0; i < 32; i++ {
		b = append(b, byte(i))
	}
	// session_id empty
	b = append(b, 0x00)
	// cipher suites: GREASE + AES128-GCM
	cs := []byte{0x00, 0x04, 0x0a, 0x0a, 0x13, 0x01}
	b = append(b, cs...)
	// compression null
	b = append(b, 0x01, 0x00)

	var exts []byte
	// server_name example.com
	host := []byte("example.com")
	name := []byte{0x00} // host_name
	name = append(name, byte(len(host)>>8), byte(len(host)))
	name = append(name, host...)
	sniPayload := make([]byte, 2+len(name))
	sniPayload[0] = byte(len(name) >> 8)
	sniPayload[1] = byte(len(name))
	copy(sniPayload[2:], name)
	sni := []byte{0x00, 0x00, byte(len(sniPayload) >> 8), byte(len(sniPayload))}
	sni = append(sni, sniPayload...)
	exts = append(exts, sni...)

	// supported_versions: TLS 1.3 + TLS 1.2
	sv := []byte{0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03}
	exts = append(exts, sv...)

	// ALPN h2, http/1.1
	alpnProto := []byte{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	alpnListLen := len(alpnProto)
	alpn := []byte{0x00, 0x10, byte((2 + alpnListLen) >> 8), byte(2 + alpnListLen),
		byte(alpnListLen >> 8), byte(alpnListLen)}
	alpn = append(alpn, alpnProto...)
	exts = append(exts, alpn...)

	// supported_groups x25519
	sg := []byte{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d}
	exts = append(exts, sg...)

	// ec_point_formats uncompressed
	epf := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	exts = append(exts, epf...)

	b = append(b, byte(len(exts)>>8), byte(len(exts)))
	b = append(b, exts...)
	return b
}

func TestParseH2ChromiumLike(t *testing.T) {
	// preface + SETTINGS + WINDOW_UPDATE
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	settingsPayload := []byte{
		0x00, 0x01, 0x00, 0x00, 0xff, 0xff, // HEADER_TABLE_SIZE=65535 — wait use 65536
	}
	// HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=6291456
	settingsPayload = []byte{
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // 65536
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH=0
		0x00, 0x04, 0x00, 0x60, 0x00, 0x00, // 6291456 = 0x00600000
	}
	frame := make([]byte, 9+len(settingsPayload))
	frame[0] = byte(len(settingsPayload) >> 16)
	frame[1] = byte(len(settingsPayload) >> 8)
	frame[2] = byte(len(settingsPayload))
	frame[3] = FrameSettings
	copy(frame[9:], settingsPayload)

	wuPayload := []byte{0x00, 0xef, 0x00, 0x01} // 15663105 = 0x00EF0001
	wu := make([]byte, 9+4)
	wu[2] = 4
	wu[3] = FrameWindowUpdate
	copy(wu[9:], wuPayload)

	buf := append(append(preface, frame...), wu...)
	s, err := ParseH2(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasPreface {
		t.Fatal("preface")
	}
	if len(s.Settings) != 3 {
		t.Fatalf("settings=%d detail=%v", len(s.Settings), s.Settings)
	}
	found := false
	for _, f := range s.Findings {
		if hex.EncodeToString([]byte(f)) != "" && len(f) > 0 {
			if contains(f, "6291456") || contains(f, "ENABLE_PUSH=0") || contains(f, "15663105") {
				found = true
			}
		}
	}
	if !found {
		// still ok if findings mention Chromium
		ok := false
		for _, f := range s.Findings {
			if contains(f, "Chromium") || contains(f, "ENABLE_PUSH=0") {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("findings=%v", s.Findings)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}

func TestSynthChromeClientHello(t *testing.T) {
	raw, err := SynthClientHello("chrome_131", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ch.SNI != "example.com" {
		t.Fatalf("SNI=%q", ch.SNI)
	}
	if len(ch.CipherSuites) < 3 {
		t.Fatalf("too few ciphers: %d", len(ch.CipherSuites))
	}
	t.Logf("JA3=%s", ch.JA3Hash())
	t.Logf("JA4=%s", ch.JA4())
	for _, f := range ch.Findings() {
		t.Log("•", f)
	}
}
