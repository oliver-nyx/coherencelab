package dissect

import (
	"testing"
)

func TestEncodeDecodeQPACKPseudoOrders(t *testing.T) {
	cases := []struct {
		order, family string
	}{
		{PseudoChrome, "chrome"},
		{PseudoFirefox, "firefox"},
		{PseudoSafari, "safari"},
	}
	for _, tc := range cases {
		raw, err := EncodeQPACKPseudoBlock(tc.order, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		sec, err := DecodeQPACKFieldSection(raw)
		if err != nil {
			t.Fatalf("%s: %v", tc.order, err)
		}
		if sec.RequiredInsertCount != 0 {
			t.Fatalf("RIC=%d", sec.RequiredInsertCount)
		}
		if sec.PseudoOrder != tc.order {
			t.Fatalf("order got %s want %s", sec.PseudoOrder, tc.order)
		}
		if sec.FamilyGuess != tc.family {
			t.Fatalf("family got %s want %s", sec.FamilyGuess, tc.family)
		}
		if len(sec.Fields) != 4 {
			t.Fatalf("fields=%d", len(sec.Fields))
		}
		foundAuth := false
		for _, f := range sec.Fields {
			if f.Name == ":authority" {
				foundAuth = true
				if f.Value != "example.com" || !f.Sensitive {
					t.Fatalf("authority=%+v", f)
				}
			}
		}
		if !foundAuth {
			t.Fatal("missing :authority")
		}
	}
}

func TestQPACKFixtures(t *testing.T) {
	for _, name := range []string{"qpack_chrome", "qpack_firefox", "qpack_safari"} {
		fx, raw, err := LoadFixtureBytes(name)
		if err != nil {
			t.Fatal(err)
		}
		if fx.Kind != "qpack" {
			t.Fatalf("kind=%s", fx.Kind)
		}
		sec, err := DecodeQPACKFieldSection(raw)
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case "qpack_chrome":
			if sec.PseudoOrder != PseudoChrome {
				t.Fatalf("got %s", sec.PseudoOrder)
			}
		case "qpack_firefox":
			if sec.PseudoOrder != PseudoFirefox {
				t.Fatalf("got %s", sec.PseudoOrder)
			}
		case "qpack_safari":
			if sec.PseudoOrder != PseudoSafari {
				t.Fatalf("got %s", sec.PseudoOrder)
			}
		}
	}
}

func TestQPACKRejectsDynamicRIC(t *testing.T) {
	// RIC=1, DeltaBase=0 → dynamic path rejected
	_, err := DecodeQPACKFieldSection([]byte{0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for RIC>0")
	}
}

func TestQPACKStaticIndicesDifferFromHPACK(t *testing.T) {
	// Teaching assertion: QPACK :method GET is index 17; HPACK uses index 2.
	if qpackStatic[17][0] != ":method" || qpackStatic[17][1] != "GET" {
		t.Fatalf("qpack static 17 = %v", qpackStatic[17])
	}
	if hpackStatic[2][0] != ":method" || hpackStatic[2][1] != "GET" {
		t.Fatalf("hpack static 2 = %v", hpackStatic[2])
	}
}
