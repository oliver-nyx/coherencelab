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
	if fx.Source == "live-browser" {
		if ch.SNI == "" {
			t.Fatal("live fixture missing SNI")
		}
		t.Logf("live chrome SNI=%q source=%s", ch.SNI, fx.Source)
	} else if ch.SNI != "example.com" {
		t.Fatalf("SNI=%q", ch.SNI)
	}
}

func TestLoadFixtureEdgeLive(t *testing.T) {
	fx, raw, err := LoadFixtureBytes("edge_live")
	if err != nil {
		t.Fatal(err)
	}
	if fx.Source != "live-browser" {
		t.Fatalf("source=%s", fx.Source)
	}
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ch.SNI != "example.com" {
		t.Fatalf("SNI=%q", ch.SNI)
	}
}

func TestLoadFixtureFirefoxLive(t *testing.T) {
	fx, raw, err := LoadFixtureBytes("firefox_live")
	if err != nil {
		t.Fatal(err)
	}
	if fx.Source != "live-browser" {
		t.Fatalf("source=%s", fx.Source)
	}
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ch.SNI != "example.com" {
		t.Fatalf("SNI=%q", ch.SNI)
	}
}

func TestLiveFirefoxVsParrot(t *testing.T) {
	fx, raw, err := LoadFixtureBytes("firefox_live")
	if err != nil {
		t.Fatal(err)
	}
	if fx.Source != "live-browser" {
		t.Skip("firefox_live not yet a live capture")
	}
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	sni := ch.SNI
	if sni == "" {
		sni = "example.com"
	}
	diffFF, _, _, err := DiffCapturedVsUTLS(raw, "firefox_133", sni)
	if err != nil {
		t.Fatal(err)
	}
	diffChrome, _, _, err := DiffCapturedVsUTLS(raw, "chrome_131", sni)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("live-ff-vs-firefox_133 score=%.1f; vs-chrome_131 score=%.1f", diffFF.Score, diffChrome.Score)
	if diffChrome.Score >= diffFF.Score {
		t.Fatalf("chrome parrot scored %.1f >= firefox parrot %.1f — unexpected", diffChrome.Score, diffFF.Score)
	}
}


func TestLoadFixtureH2Continuation(t *testing.T) {
	_, raw, err := LoadFixtureBytes("h2_continuation")
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
		t.Fatal("expected CONTINUATION in h2_continuation fixture")
	}
}

func TestLoadFixtureH2ChromeLive(t *testing.T) {
	fx, raw, err := LoadFixtureBytes("h2_chrome")
	if err != nil {
		t.Fatal(err)
	}
	if fx.Source != "live-browser" {
		t.Fatalf("source=%s", fx.Source)
	}
	s, err := ParseH2(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasPreface {
		t.Fatal("expected client preface")
	}
	if len(s.Frames) < 2 {
		t.Fatalf("expected SETTINGS+WINDOW_UPDATE, frames=%d", len(s.Frames))
	}
}

func TestCorpusFixtureVsMatchingParrot(t *testing.T) {
	// Parrot-vs-parrot: synth fixture must agree with the same uTLS id.
	_, raw, err := LoadFixtureBytes("chrome_131_utls")
	if err != nil {
		t.Fatal(err)
	}
	diff, _, _, err := DiffCapturedVsUTLS(raw, "chrome_131", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if diff.Score < 50 {
		t.Fatalf("expected decent agreement with matching parrot, score=%.1f diffs=%+v", diff.Score, diff.Diffs)
	}
	t.Logf("utls-vs-utls score=%.1f matches=%v", diff.Score, diff.Matches)
}

func TestLiveChromeVsParrot(t *testing.T) {
	fx, raw, err := LoadFixtureBytes("chrome_131")
	if err != nil {
		t.Fatal(err)
	}
	if fx.Source != "live-browser" {
		t.Skip("chrome_131 not yet a live capture")
	}
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	sni := ch.SNI
	if sni == "" {
		sni = "example.com"
	}
	diff, _, _, err := DiffCapturedVsUTLS(raw, "chrome_131", sni)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("live-vs-utls score=%.1f diffs=%d matches=%v", diff.Score, len(diff.Diffs), diff.Matches)
	diffFF, _, _, err := DiffCapturedVsUTLS(raw, "firefox_133", sni)
	if err != nil {
		t.Fatal(err)
	}
	if diffFF.Score >= diff.Score {
		t.Fatalf("firefox parrot scored %.1f >= chrome parrot %.1f — unexpected", diffFF.Score, diff.Score)
	}
}

func TestCorpusFixtureVsWrongParrot(t *testing.T) {
	_, raw, err := LoadFixtureBytes("chrome_131")
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := ParseClientHello(raw)
	sni := "example.com"
	if ch != nil && ch.SNI != "" {
		sni = ch.SNI
	}
	diff, _, _, err := DiffCapturedVsUTLS(raw, "firefox_133", sni)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Score > 75 {
		t.Fatalf("chrome fixture vs firefox should disagree, score=%.1f", diff.Score)
	}
}
