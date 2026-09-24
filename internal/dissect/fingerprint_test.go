package dissect

import "testing"

func TestFingerprintChromeRanksChrome(t *testing.T) {
	b := loadFamilyBundle(t, "chrome_131", "h2_chrome", "h3_chrome", "quic_initial_chrome")
	rep, err := FingerprintCapture(b)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Best != "chrome" {
		t.Fatalf("best=%s ranking=%+v", rep.Best, rep.Families)
	}
	if rep.Families[0].Score < rep.familyScore("firefox")+15 {
		t.Fatalf("chrome should lead firefox by >=15, got %+v", rep.Families)
	}
}

func TestFingerprintFirefoxRanksFirefox(t *testing.T) {
	b := loadFamilyBundle(t, "firefox_live", "h2_firefox", "h3_firefox", "quic_initial_firefox")
	rep, err := FingerprintCapture(b)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Best != "firefox" {
		t.Fatalf("best=%s ranking=%+v", rep.Best, rep.Families)
	}
}

func TestFingerprintCrossLayerConflict(t *testing.T) {
	chrome := loadFamilyBundle(t, "chrome_131", "h2_chrome", "", "")
	firefox := loadFamilyBundle(t, "firefox_live", "h2_firefox", "", "")
	mixed := CaptureBundle{Hello: chrome.Hello, H2: firefox.H2}
	rep, err := FingerprintCapture(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Conflicts) == 0 {
		t.Fatalf("expected cross-layer conflict, best=%s notes=%v", rep.Best, rep.Families)
	}
}

func (r *FingerprintReport) familyScore(name string) float64 {
	for _, f := range r.Families {
		if f.Family == name {
			return f.Score
		}
	}
	return 0
}

func loadFamilyBundle(t *testing.T, hello, h2, h3, quic string) CaptureBundle {
	t.Helper()
	var b CaptureBundle
	load := func(name string) []byte {
		if name == "" {
			return nil
		}
		_, raw, err := LoadFixtureBytes(name)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	b.Hello = load(hello)
	b.H2 = load(h2)
	b.H3 = load(h3)
	b.QUIC = load(quic)
	return b
}
