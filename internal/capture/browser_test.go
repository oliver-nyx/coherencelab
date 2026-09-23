package capture

import (
	"testing"

	"github.com/oliver-nyx/coherencelab/internal/signal"
)

func TestInferFromUA(t *testing.T) {
	cases := []struct {
		ua                 string
		browser, platform  string
		version            string
	}{
		{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"chrome", "windows", "131",
		},
		{
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
			"firefox", "macos", "133",
		},
		{
			"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.154 Mobile/15E148 Safari/604.1",
			"chrome", "ios", "131",
		},
		{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
			"opera", "windows", "116",
		},
	}
	for _, c := range cases {
		m := InferFromUA(c.ua)
		if m.Browser != c.browser || m.Platform != c.platform || m.Version != c.version {
			t.Fatalf("ua=%q => %+v want %s/%s/%s", c.ua, m, c.browser, c.platform, c.version)
		}
	}
}

func TestFromHTTPBuildsProfile(t *testing.T) {
	wd := false
	in := FromHTTP(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		map[string]string{
			"sec-ch-ua":          `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
			"sec-ch-ua-platform": `"Windows"`,
			"sec-ch-ua-mobile":   "?0",
			"accept-language":    "en-US,en;q=0.9",
			"accept":             "text/html",
			"accept-encoding":    "gzip, deflate, br",
			"sec-fetch-mode":     "navigate",
		},
		[]string{"sec-ch-ua", "user-agent", "accept"},
		&signal.TLSObservation{ALPN: "h2", Version: "TLS 1.3"},
		&signal.H2Observation{HeaderTableSize: 65536, MaxConcurrent: 1000, InitialWindowSize: 6291456, MaxFrameSize: 16384},
		&BrowserPayload{
			ID: "my-chrome-win",
			JSRuntime: &signal.JSObservation{
				Navigator: &signal.NavigatorObservation{Platform: "Win32", Vendor: "Google Inc.", Webdriver: &wd},
				WebGL:     &signal.WebGLObservation{Vendor: "Google Inc.", Renderer: "ANGLE"},
			},
		},
	)
	p, err := ToProfile(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "my-chrome-win" {
		t.Fatalf("id=%s", p.ID)
	}
	if p.JSRuntime == nil || p.JSRuntime.Navigator == nil || p.JSRuntime.Navigator.Platform != "Win32" {
		t.Fatalf("js: %+v", p.JSRuntime)
	}
	if p.HTTP2.MaxConcurrent != 1000 {
		t.Fatalf("h2 concurrent=%d", p.HTTP2.MaxConcurrent)
	}
}

func TestCriOSUsesSafariTLS(t *testing.T) {
	in := FromHTTP(
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.154 Mobile/15E148 Safari/604.1",
		map[string]string{"accept-language": "en-US"},
		nil, nil, nil, nil,
	)
	p, err := ToProfile(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.TLS.UTLSClientID != "safari_ios_18" {
		t.Fatalf("utls=%s", p.TLS.UTLSClientID)
	}
	if p.Engine != "webkit" {
		t.Fatalf("engine=%s", p.Engine)
	}
}
