package rules

import (
	"testing"

	"github.com/oliver-nyx/coherencelab/internal/profile"
	"github.com/oliver-nyx/coherencelab/internal/signal"
)

func TestPlatformConsistent(t *testing.T) {
	cases := []struct {
		ua, platform string
		want         bool
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131", "windows", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131", "Linux", false},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)", "ios", true},
	}
	for _, c := range cases {
		if got := platformConsistent(c.ua, c.platform); got != c.want {
			t.Errorf("platformConsistent(%q, %q) = %v want %v", c.ua, c.platform, got, c.want)
		}
	}
}

func TestBrowserConsistentChrome(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
	ch := `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`
	if !browserConsistent(ua, ch, "chrome") {
		t.Fatal("expected chrome consistency")
	}
}

func TestBrowserConsistentFirefoxNoHints(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
	if !browserConsistent(ua, "", "firefox") {
		t.Fatal("expected firefox consistency without client hints")
	}
}

func TestEvaluateCoherentChrome(t *testing.T) {
	p := &profile.Profile{
		ID: "test", Name: "Test", Browser: "chrome",
		UserAgent: profile.UserAgentSpec{
			Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			Pattern: "Chrome/131.0.0.0", MatchMode: "contains",
			Major: 131,
		},
		ClientHints: profile.ClientHintsSpec{
			SecCHUA: `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
			SecCHUAMobile: "?0", SecCHUAPlatform: `"Windows"`,
		},
		Headers: profile.HeaderSpec{
			Required: map[string]string{
				"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate",
			},
			Accept: "text/html", AcceptEncoding: "gzip, deflate, br, zstd",
		},
		TLS:   profile.TLSSpec{ALPN: []string{"h2", "http/1.1"}, UTLSClientID: "chrome_131"},
		HTTP2: profile.HTTP2Spec{HeaderTableSize: 65536, MaxConcurrent: 1000},
		AcceptLanguage: profile.AcceptLanguageSpec{Primary: "en-US"},
	}
	s := &signal.Snapshot{
		UserAgent: p.UserAgent.Value,
		SecCHUA: p.ClientHints.SecCHUA, SecCHUAMobile: "?0", SecCHUAPlatform: `"Windows"`,
		AcceptLanguage: "en-US,en;q=0.9", Accept: "text/html", AcceptEncoding: "gzip, deflate, br, zstd",
		Headers: map[string]string{
			"sec-fetch-site": "none", "sec-fetch-mode": "navigate",
			"sec-fetch-user": "?1", "sec-fetch-dest": "document",
		},
		TLS: &signal.TLSObservation{UTLSClientID: "chrome_131", Version: "TLS 1.3", ALPN: "h2"},
		H2:  &signal.H2Observation{HeaderTableSize: 65536, MaxConcurrent: 1000},
	}
	findings := Evaluate(p, s, DefaultRules())
	criticalFails := 0
	for _, f := range findings {
		if !f.Passed && f.Severity == SeverityCritical {
			criticalFails++
		}
	}
	if criticalFails > 0 {
		t.Fatalf("expected no critical failures for coherent profile, got %d", criticalFails)
	}
}

func TestOrderSimilarity(t *testing.T) {
	expected := []string{"host", "user-agent", "accept", "accept-language"}
	actual := []string{"host", "accept", "user-agent", "accept-language"}
	score := orderSimilarity(expected, actual)
	if score < 0.5 {
		t.Fatalf("expected reasonable similarity, got %f", score)
	}
}

func TestBrowserConsistentCriOS(t *testing.T) {
	ua := "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.154 Mobile/15E148 Safari/604.1"
	if !browserConsistent(ua, "", "chrome") {
		t.Fatal("expected CriOS without Client Hints to be consistent")
	}
}

func TestBrowserConsistentOpera(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0"
	ch := `"Opera";v="116", "Chromium";v="131", "Not A(Brand";v="24"`
	if !browserConsistent(ua, ch, "opera") {
		t.Fatal("expected Opera consistency")
	}
}

func TestChromeIOSUsesWebKitTLS(t *testing.T) {
	p := &profile.Profile{
		ID: "chrome-131-ios", Name: "Chrome iOS", Browser: "chrome", Platform: "ios",
		UserAgent: profile.UserAgentSpec{
			Value: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.154 Mobile/15E148 Safari/604.1",
			Pattern: "CriOS/131", MatchMode: "contains", Major: 131,
		},
		TLS:   profile.TLSSpec{ALPN: []string{"h2"}, UTLSClientID: "safari_ios_18"},
		HTTP2: profile.HTTP2Spec{HeaderTableSize: 4096, MaxConcurrent: 100},
		AcceptLanguage: profile.AcceptLanguageSpec{Primary: "en-US"},
	}
	s := &signal.Snapshot{
		UserAgent: p.UserAgent.Value,
		AcceptLanguage: "en-US,en;q=0.9",
		TLS: &signal.TLSObservation{UTLSClientID: "safari_ios_18", Version: "TLS 1.3", ALPN: "h2"},
		H2:  &signal.H2Observation{HeaderTableSize: 4096, MaxConcurrent: 100},
	}
	findings := Evaluate(p, s, DefaultRules())
	for _, f := range findings {
		if f.ID == "cross.chrome_tls_ua" && !f.Passed {
			t.Fatalf("CriOS+WebKit TLS should pass: %+v", f)
		}
		if !f.Passed && f.Severity == SeverityCritical {
			t.Fatalf("unexpected critical failure %s: %+v", f.ID, f)
		}
	}
}

func TestSkippedFindingsKeepZeroWeight(t *testing.T) {
	p := &profile.Profile{
		ID: "ff", Name: "Firefox", Browser: "firefox",
		UserAgent: profile.UserAgentSpec{
			Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
			Pattern: "Firefox/133", MatchMode: "contains", Major: 133,
		},
		TLS:   profile.TLSSpec{ALPN: []string{"h2"}, UTLSClientID: "firefox_133"},
		HTTP2: profile.HTTP2Spec{HeaderTableSize: 65536, EnablePush: 0, MaxConcurrent: 100},
		AcceptLanguage: profile.AcceptLanguageSpec{Primary: "en-US"},
	}
	s := &signal.Snapshot{
		UserAgent:      p.UserAgent.Value,
		AcceptLanguage: "en-US,en;q=0.5",
		Headers:        map[string]string{},
	}
	findings := Evaluate(p, s, DefaultRules())
	var skippedCount int
	for _, f := range findings {
		if f.Skipped {
			skippedCount++
			if f.Weight != 0 {
				t.Fatalf("skipped finding %s has weight %d (score inflation)", f.ID, f.Weight)
			}
		}
	}
	if skippedCount < 5 {
		t.Fatalf("expected several skipped findings, got %d", skippedCount)
	}
}

func TestChromeTLSRequiresPresetNotJustJA3(t *testing.T) {
	p := &profile.Profile{
		ID: "chrome", Name: "Chrome", Browser: "chrome",
		UserAgent: profile.UserAgentSpec{
			Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			Pattern: "Chrome/131", MatchMode: "contains", Major: 131,
		},
		ClientHints: profile.ClientHintsSpec{
			SecCHUA: `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
			SecCHUAMobile: "?0", SecCHUAPlatform: `"Windows"`,
		},
		TLS: profile.TLSSpec{ALPN: []string{"h2"}, UTLSClientID: "chrome_131", MinVersion: "TLS 1.2", MaxVersion: "TLS 1.3"},
		HTTP2: profile.HTTP2Spec{HeaderTableSize: 65536, EnablePush: 0, MaxConcurrent: 1000, InitialWindowSize: 6291456, MaxFrameSize: 16384, MaxHeaderListSize: 262144},
		AcceptLanguage: profile.AcceptLanguageSpec{Primary: "en-US"},
	}
	s := &signal.Snapshot{
		UserAgent: p.UserAgent.Value,
		SecCHUA: p.ClientHints.SecCHUA, SecCHUAMobile: "?0", SecCHUAPlatform: `"Windows"`,
		AcceptLanguage: "en-US,en;q=0.9",
		Headers: map[string]string{},
		TLS: &signal.TLSObservation{UTLSClientID: "firefox_133", JA3: "deadbeef", Version: "TLS 1.3", ALPN: "h2"},
		H2:  &signal.H2Observation{HeaderTableSize: 65536, EnablePush: 0, MaxConcurrent: 1000, InitialWindowSize: 6291456, MaxFrameSize: 16384, MaxHeaderListSize: 262144},
	}
	findings := Evaluate(p, s, DefaultRules())
	for _, f := range findings {
		if f.ID == "cross.chrome_tls_ua" {
			if f.Passed {
				t.Fatal("JA3 alone must not satisfy chrome TLS cross-layer rule")
			}
			return
		}
	}
	t.Fatal("cross.chrome_tls_ua finding missing")
}

func TestHTTP2EnablePushZeroIsChecked(t *testing.T) {
	p := &profile.Profile{
		ID: "chrome", Name: "Chrome", Browser: "chrome",
		UserAgent: profile.UserAgentSpec{
			Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
			Pattern: "Chrome/131", MatchMode: "contains", Major: 131,
		},
		ClientHints: profile.ClientHintsSpec{
			SecCHUA: `"Google Chrome";v="131"`, SecCHUAMobile: "?0", SecCHUAPlatform: `"Windows"`,
		},
		TLS: profile.TLSSpec{ALPN: []string{"h2"}, UTLSClientID: "chrome_131"},
		HTTP2: profile.HTTP2Spec{
			HeaderTableSize: 65536, EnablePush: 0, MaxConcurrent: 1000,
			InitialWindowSize: 6291456, MaxFrameSize: 16384, MaxHeaderListSize: 262144,
		},
		AcceptLanguage: profile.AcceptLanguageSpec{Primary: "en-US"},
	}
	s := &signal.Snapshot{
		UserAgent: p.UserAgent.Value,
		SecCHUA: p.ClientHints.SecCHUA, SecCHUAMobile: "?0", SecCHUAPlatform: `"Windows"`,
		AcceptLanguage: "en-US",
		Headers: map[string]string{},
		TLS: &signal.TLSObservation{UTLSClientID: "chrome_131", Version: "TLS 1.3", ALPN: "h2"},
		H2: &signal.H2Observation{
			HeaderTableSize: 65536, EnablePush: 1, MaxConcurrent: 1000,
			InitialWindowSize: 6291456, MaxFrameSize: 16384, MaxHeaderListSize: 262144,
		},
	}
	findings := Evaluate(p, s, DefaultRules())
	for _, f := range findings {
		if f.ID == "http2.settings" {
			if f.Passed {
				t.Fatalf("ENABLE_PUSH=1 should fail when profile expects 0: %+v", f)
			}
			return
		}
	}
	t.Fatal("http2.settings finding missing")
}
