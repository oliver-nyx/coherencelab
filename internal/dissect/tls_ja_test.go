package dissect

import "testing"

// Vectors are the worked example in FoxIO technical_details/JA4.md.
func TestJA4FoxIOExample(t *testing.T) {
	ch := &ClientHello{
		SupportedVersions: []uint16{0x0304},
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		ExtensionOrder: []uint16{
			0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
			0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
		},
		ALPN:          []string{"h2"},
		SignatureAlgs: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		SNI:           "example.com",
	}
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got := ch.JA4(); got != want {
		t.Fatalf("JA4\n got %s\nwant %s\n raw %s", got, want, ch.JA4Raw())
	}
}

func TestJA4ExtensionHashWithoutSignatures(t *testing.T) {
	ch := &ClientHello{
		SupportedVersions: []uint16{0x0304},
		CipherSuites:      []uint16{0x1301},
		ExtensionOrder: []uint16{
			0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b,
			0x0023, 0x002b, 0x002d, 0x0033, 0x4469, 0xff01,
		},
		ALPN: []string{"h2"},
		SNI:  "example.com",
	}
	// FoxIO: that extension list with no signature algorithms hashes to 6d807ffa2a79.
	// Prefix is not part of the published no-sig example; check the c section only.
	got := ch.JA4()
	const wantTail = "_6d807ffa2a79"
	if len(got) < len(wantTail) || got[len(got)-len(wantTail):] != wantTail {
		t.Fatalf("got %s, want suffix %s", got, wantTail)
	}
}

func TestJA4QUICPrefixAndALPNEdges(t *testing.T) {
	ch := &ClientHello{
		LegacyVersion:     0x0303,
		CipherSuites:      []uint16{0x1301},
		ExtensionOrder:    []uint16{0x002b},
		SupportedVersions: []uint16{0x0a0a, 0x0304}, // GREASE then 1.3
		QUIC:              true,
	}
	if got := ch.JA4(); got[:1] != "q" || got[1:3] != "13" {
		t.Fatalf("quic/version prefix: %s", got)
	}
	cases := []struct{ in, want string }{
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"h", "hh"},
		{"", "00"},
		{"\xab", "ab"},
		{"\x20", "20"},
		{"\xab\xcd", "ad"},
		{"\x20\x61", "21"},
		{"\x30\xab", "3b"},
		{"\x61\x20", "60"},
		{"\x30\x31\xab\xcd", "3d"},
		{"\x30\xab\xcd\x31", "01"},
	}
	for _, c := range cases {
		if got := ja4ALPN(c.in); got != c.want {
			t.Fatalf("alpn %q got %s want %s", c.in, got, c.want)
		}
	}
}

func TestJA4EmptyLists(t *testing.T) {
	ch := &ClientHello{LegacyVersion: 0x0303}
	got := ch.JA4()
	if got != "t12i000000_000000000000_000000000000" {
		t.Fatalf("empty hello JA4 = %s", got)
	}
}
