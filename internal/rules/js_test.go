package rules

import (
	"testing"

	"github.com/coherencelab/coherencelab/internal/profile"
	"github.com/coherencelab/coherencelab/internal/signal"
)

func TestJSWebdriverFail(t *testing.T) {
	wdFalse := false
	wdTrue := true
	p := &profile.Profile{
		ID: "t", Browser: "chrome", Platform: "windows",
		JSRuntime: &profile.JSRuntimeSpec{
			Navigator: &profile.NavigatorSpec{Platform: "Win32", Webdriver: &wdFalse},
		},
	}
	s := &signal.Snapshot{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
		JS: &signal.JSObservation{
			Navigator: &signal.NavigatorObservation{Platform: "Win32", Webdriver: &wdTrue},
		},
	}
	f := jsNavigatorWebdriverRule().Check(p, s)
	if f.Passed {
		t.Fatal("expected webdriver mismatch to fail")
	}
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestJSPlatformCrossLayer(t *testing.T) {
	s := &signal.Snapshot{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
		SecCHUAPlatform: `"Windows"`,
		JS: &signal.JSObservation{
			Navigator: &signal.NavigatorObservation{Platform: "Linux x86_64"},
		},
	}
	p := &profile.Profile{Platform: "windows"}
	f := crossJSPlatformRule().Check(p, s)
	if f.Passed {
		t.Fatal("expected Linux navigator.platform vs Windows UA to fail")
	}
}

func TestJSRulesSkipWithoutProfile(t *testing.T) {
	p := &profile.Profile{ID: "t", Browser: "chrome"}
	s := &signal.Snapshot{}
	for _, r := range []Rule{
		jsNavigatorPlatformRule(),
		jsNavigatorVendorRule(),
		jsNavigatorWebdriverRule(),
		jsWebGLRule(),
		crossJSPlatformRule(),
	} {
		f := r.Check(p, s)
		if !f.Passed || f.Weight != 0 {
			t.Fatalf("%s should skip, got passed=%v weight=%d", r.ID, f.Passed, f.Weight)
		}
	}
}

func TestNavigatorPlatformConsistent(t *testing.T) {
	cases := []struct {
		nav, ua, hint, prof string
		want                bool
	}{
		{"Win32", "Windows NT 10.0", `"Windows"`, "windows", true},
		{"MacIntel", "Macintosh; Intel Mac OS X", `"macOS"`, "macos", true},
		{"Linux x86_64", "X11; Linux x86_64", `"Linux"`, "linux", true},
		{"iPhone", "iPhone; CPU iPhone OS", "", "ios", true},
		{"Win32", "X11; Linux x86_64", `"Linux"`, "linux", false},
	}
	for _, c := range cases {
		if got := navigatorPlatformConsistent(c.nav, c.ua, c.hint, c.prof); got != c.want {
			t.Errorf("nav=%s ua=%s => %v want %v", c.nav, c.ua, got, c.want)
		}
	}
}
