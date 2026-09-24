package dissect

import (
	"encoding/binary"
	"testing"
)

func TestContinuationMergeDecodesPseudo(t *testing.T) {
	block, err := EncodeIndexedPseudoBlock(PseudoChrome, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(block) < 4 {
		t.Fatal("block too small")
	}
	// Split HPACK across HEADERS (no END_HEADERS) + CONTINUATION (END_HEADERS).
	part1 := block[:2]
	part2 := block[2:]

	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h1 := makeFrame(FrameHeaders, 0x00, 1, part1)      // no END_HEADERS
	c1 := makeFrame(FrameContinuation, 0x04, 1, part2) // END_HEADERS
	buf := append(append(preface, h1...), c1...)

	s, err := ParseH2(buf)
	if err != nil {
		t.Fatal(err)
	}
	if s.HeaderBlock == nil {
		t.Fatal("expected merged header block")
	}
	if s.HeaderBlock.PseudoOrder != PseudoChrome {
		t.Fatalf("pseudo=%s", s.HeaderBlock.PseudoOrder)
	}
	found := false
	for _, f := range s.Findings {
		if contains(f, "CONTINUATION") || contains(f, "Merged HEADERS") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected continuation finding, got %v", s.Findings)
	}
}

func makeFrame(typ, flags uint8, stream uint32, payload []byte) []byte {
	f := make([]byte, 9+len(payload))
	f[0] = byte(len(payload) >> 16)
	f[1] = byte(len(payload) >> 8)
	f[2] = byte(len(payload))
	f[3] = typ
	f[4] = flags
	binary.BigEndian.PutUint32(f[5:9], stream&0x7fffffff)
	copy(f[9:], payload)
	return f
}

func TestCorpusSelfDiffHighScore(t *testing.T) {
	raw, err := SynthClientHello("chrome_131", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Diff against itself
	d := DiffClientHellos(ref, ref)
	if d.Score < 99 {
		t.Fatalf("self-diff score %.1f diffs=%+v", d.Score, d.Diffs)
	}
}

func TestCorpusOrderPermutationIsNotCritical(t *testing.T) {
	raw, err := SynthClientHello("chrome_131", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	parrot := *ref
	order := append([]uint16(nil), ref.ExtensionOrder...)
	if len(order) < 4 {
		t.Fatal("hello too short to permute")
	}
	order[1], order[3] = order[3], order[1]
	parrot.ExtensionOrder = order
	d := DiffClientHellos(ref, &parrot)
	for _, x := range d.Diffs {
		if x.Severity == "critical" {
			t.Fatalf("order-only delta must not be critical: %+v", x)
		}
		if x.Field == "extension_set" {
			t.Fatalf("set should match after a shuffle: %+v", x)
		}
	}
	if d.Score < 75 {
		t.Fatalf("order-only shuffle score %.1f, want >= 75 (diffs=%+v)", d.Score, d.Diffs)
	}
}

func TestCorpusChromeVsFirefoxLowScore(t *testing.T) {
	raw, err := SynthClientHello("chrome_131", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	diff, _, _, err := DiffCapturedVsUTLS(raw, "firefox_133", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if diff.Score > 70 {
		t.Fatalf("chrome capture vs firefox parrot should disagree, score=%.1f matches=%v", diff.Score, diff.Matches)
	}
	crit := 0
	for _, x := range diff.Diffs {
		if x.Severity == "critical" {
			crit++
		}
	}
	if crit == 0 {
		t.Fatalf("expected critical diffs, got %+v", diff.Diffs)
	}
	t.Logf("score=%.1f critical=%d", diff.Score, crit)
}
