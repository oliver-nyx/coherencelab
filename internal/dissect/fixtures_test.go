package dissect

import (
	"testing"
)

func TestLoadFixtureChromeHello(t *testing.T) {
	fx, raw, err := LoadFixtureBytes("chrome_131")
	if err != nil {
		t.Fatal(err)
	}
	if fx.Kind != "clienthello" || len(raw) < 100 {
		t.Fatalf("%+v len=%d", fx, len(raw))
	}
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ch.SNI != "example.com" {
		t.Fatalf("SNI=%q", ch.SNI)
	}
}

func TestLoadFixtureH2ChromeContinuation(t *testing.T) {
	_, raw, err := LoadFixtureBytes("h2_chrome")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseH2(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.HeaderBlock == nil || s.HeaderBlock.PseudoOrder != PseudoChrome {
		t.Fatalf("block=%v", s.HeaderBlock)
	}
	hasCont := false
	for _, fr := range s.Frames {
		if fr.Type == FrameContinuation {
			hasCont = true
		}
	}
	if !hasCont {
		t.Fatal("expected CONTINUATION in h2_chrome fixture")
	}
}

func TestCorpusFixtureVsMatchingParrot(t *testing.T) {
	_, raw, err := LoadFixtureBytes("chrome_131")
	if err != nil {
		t.Fatal(err)
	}
	diff, _, _, err := DiffCapturedVsUTLS(raw, "chrome_131", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Same uTLS id that generated the fixture — should be very high.
	// GREASE permutation may still move skeleton across runs.
	if diff.Score < 50 {
		t.Fatalf("expected decent agreement with matching parrot, score=%.1f diffs=%+v", diff.Score, diff.Diffs)
	}
	t.Logf("score=%.1f matches=%v", diff.Score, diff.Matches)
}

func TestCorpusFixtureVsWrongParrot(t *testing.T) {
	_, raw, err := LoadFixtureBytes("chrome_131")
	if err != nil {
		t.Fatal(err)
	}
	diff, _, _, err := DiffCapturedVsUTLS(raw, "firefox_133", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if diff.Score > 75 {
		t.Fatalf("chrome fixture vs firefox should disagree, score=%.1f", diff.Score)
	}
}
