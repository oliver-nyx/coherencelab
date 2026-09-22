package curlimpersonate

import "testing"

func TestResolveChrome131(t *testing.T) {
	id, err := ResolveProfileID(&Export{Impersonate: "chrome131_windows"})
	if err != nil || id != "chrome-131-win" {
		t.Fatalf("got %q err=%v", id, err)
	}
}

func TestToSnapshot(t *testing.T) {
	s := ToSnapshot(&Export{
		Impersonate: "chrome131",
		UserAgent:   "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36",
		Headers:     map[string]string{"sec-ch-ua-platform": `"Windows"`},
		JA3:         "abc123",
	})
	if s.TLS == nil || s.TLS.JA3 != "abc123" {
		t.Fatal("expected ja3 on snapshot")
	}
}
