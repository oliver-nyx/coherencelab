package dissect

import (
	"encoding/binary"
	"testing"
)

func TestHPACKPseudoChromeOrder(t *testing.T) {
	block, err := EncodeIndexedPseudoBlock(PseudoChrome, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	hb, err := DecodeHeaderBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if hb.PseudoOrder != PseudoChrome {
		t.Fatalf("got %s", hb.PseudoOrder)
	}
	if hb.FamilyGuess != "chrome" {
		t.Fatalf("family %s", hb.FamilyGuess)
	}
}

func TestHPACKPseudoFirefoxOrder(t *testing.T) {
	block, err := EncodeIndexedPseudoBlock(PseudoFirefox, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	hb, err := DecodeHeaderBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if hb.PseudoOrder != PseudoFirefox || hb.FamilyGuess != "firefox" {
		t.Fatalf("%s / %s", hb.PseudoOrder, hb.FamilyGuess)
	}
}

func TestHPACKWeirdOrderFlagged(t *testing.T) {
	block, err := EncodeIndexedPseudoBlock("a,m,p,s", "x.test")
	if err != nil {
		t.Fatal(err)
	}
	hb, err := DecodeHeaderBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if hb.FamilyGuess != "unknown" {
		t.Fatalf("expected unknown, got %s", hb.FamilyGuess)
	}
}

func TestH2SessionDecodesHEADERS(t *testing.T) {
	block, err := EncodeIndexedPseudoBlock(PseudoChrome, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	settingsPayload := []byte{
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x00, 0x60, 0x00, 0x00,
	}
	sf := make([]byte, 9+len(settingsPayload))
	sf[2] = byte(len(settingsPayload))
	sf[3] = FrameSettings
	copy(sf[9:], settingsPayload)

	hf := make([]byte, 9+len(block))
	binary.BigEndian.PutUint32(hf[5:9], 1) // stream 1 — fix length bytes
	hf[0] = byte(len(block) >> 16)
	hf[1] = byte(len(block) >> 8)
	hf[2] = byte(len(block))
	hf[3] = FrameHeaders
	hf[4] = 0x04 // END_HEADERS
	hf[8] = 0x01 // stream id 1
	copy(hf[9:], block)

	buf := append(append(preface, sf...), hf...)
	s, err := ParseH2(buf)
	if err != nil {
		t.Fatal(err)
	}
	if s.HeaderBlock == nil || s.HeaderBlock.PseudoOrder != PseudoChrome {
		t.Fatalf("header block=%v", s.HeaderBlock)
	}
	fp := s.AkamaiH2Fingerprint()
	if fp == "" || s.HeaderBlock.PseudoOrder == "" {
		t.Fatalf("fingerprint %q", fp)
	}
	t.Log(fp)
}

func TestExtensionPermutationChrome(t *testing.T) {
	rep, err := AnalyzeExtensionPermutation("chrome_131", "example.com", 3)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Samples != 3 {
		t.Fatalf("samples %d", rep.Samples)
	}
	if rep.UniqueJA3 < 1 {
		t.Fatal("expected JA3")
	}
	t.Logf("orders=%d ja3=%d stableSkeleton=%v", rep.UniqueOrders, rep.UniqueJA3, rep.SkeletonStable)
	for _, f := range rep.Findings {
		t.Log("•", f)
	}
}
