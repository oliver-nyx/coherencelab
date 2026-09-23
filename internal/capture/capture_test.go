package capture

import (
	"testing"

	"github.com/oliver-nyx/coherencelab/internal/signal"
)

func TestToProfile(t *testing.T) {
	in := &Input{
		ID: "test-cap", Browser: "chrome", Platform: "windows",
		Snapshot: signal.Snapshot{
			UserAgent: "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36",
			SecCHUA:   `"Google Chrome";v="131"`,
			SecCHUAPlatform: `"Windows"`,
			AcceptLanguage: "en-US,en;q=0.9",
			Headers: map[string]string{"sec-fetch-mode": "navigate"},
		},
	}
	p, err := ToProfile(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.TLS.UTLSClientID != "chrome_131" {
		t.Fatalf("tls preset: %s", p.TLS.UTLSClientID)
	}
}
