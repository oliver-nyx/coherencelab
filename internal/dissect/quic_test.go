package dissect

import (
	"testing"
)

func TestCraftAndDecryptInitial(t *testing.T) {
	pkt, err := CraftChromeLikeInitial()
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) < 1200 {
		t.Fatalf("Initial should be padded to >=1200, got %d", len(pkt))
	}
	d, err := DecryptInitial(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if d.ClientHello == nil {
		t.Fatal("expected embedded ClientHello")
	}
	if d.ClientHello.SNI != "example.com" {
		t.Fatalf("SNI=%q", d.ClientHello.SNI)
	}
	if len(d.Transport) < 5 {
		t.Fatalf("tps=%d", len(d.Transport))
	}
	grease := 0
	hasGreaseBit := false
	for _, tp := range d.Transport {
		if tp.GREASE {
			grease++
		}
		if tp.ID == TPGreaseQUICBit {
			hasGreaseBit = true
		}
	}
	if grease == 0 {
		t.Fatal("expected GREASE transport parameter")
	}
	if !hasGreaseBit {
		t.Fatal("expected grease_quic_bit")
	}
	t.Logf("pn=%d hello_exts=%d tps=%d grease=%d", d.PacketNumber, len(d.ClientHello.Extensions), len(d.Transport), grease)
}

func TestParseTransportParametersGREASE(t *testing.T) {
	raw := CraftMinimalTransportParams()
	tps, err := ParseTransportParameters(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tp := range tps {
		if tp.GREASE {
			t.Fatal("minimal should have no GREASE")
		}
	}
	if !IsTransportParamGREASE(27) || !IsTransportParamGREASE(58) {
		t.Fatal("31*N+27 grease check")
	}
	if IsTransportParamGREASE(TPInitialMaxData) {
		t.Fatal("0x04 is not grease")
	}
}

func TestParseQUICLongHeaderInitial(t *testing.T) {
	pkt, err := CraftChromeLikeInitial()
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseQUICLongHeader(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != QUICLongInitial || h.Version != QUICVersion1 {
		t.Fatalf("%+v", h)
	}
	if len(h.DCID) == 0 {
		t.Fatal("dcid")
	}
}

func TestQUICInitialFixture(t *testing.T) {
	_, raw, err := LoadFixtureBytes("quic_initial_chrome")
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecryptInitial(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Transport) == 0 {
		t.Fatal("expected transport parameters")
	}
}

func TestQUICTPFixture(t *testing.T) {
	_, raw, err := LoadFixtureBytes("quic_tp_minimal")
	if err != nil {
		t.Fatal(err)
	}
	tps, err := ParseTransportParameters(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(tps) == 0 {
		t.Fatal("empty")
	}
}
