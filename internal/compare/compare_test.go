package compare

import (
	"strings"
	"testing"

	"github.com/oliver-nyx/coherencelab/internal/signal"
)

func TestSnapshotsDetectUAMismatch(t *testing.T) {
	a := &signal.Snapshot{UserAgent: "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36", SecCHUAPlatform: `"Windows"`, SecCHUA: `"Google Chrome";v="131"`}
	b := &signal.Snapshot{UserAgent: "Mozilla/5.0 Firefox/133.0", SecCHUAPlatform: `"Windows"`, SecCHUA: `"Google Chrome";v="131"`}
	r := Snapshots("chrome", a, "broken", b)
	if r.Coherent || r.Critical == 0 {
		t.Fatalf("expected critical diffs, got %+v", r)
	}
}

func TestSnapshotsCoherent(t *testing.T) {
	s := &signal.Snapshot{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
		SecCHUA: `"Google Chrome";v="131"`, SecCHUAPlatform: `"Windows"`,
		TLS: &signal.TLSObservation{UTLSClientID: "chrome_131", ALPN: "h2"},
	}
	r := Snapshots("a", s, "b", s)
	if !r.Coherent {
		t.Fatalf("expected coherent, got %+v", r.Diffs)
	}
}

func TestCrossLayerFirefoxHints(t *testing.T) {
	s := &signal.Snapshot{
		UserAgent: "Mozilla/5.0 Firefox/133.0",
		SecCHUA:   `"Google Chrome";v="131"`,
	}
	note := crossLayerNote(s)
	if !strings.Contains(note, "Firefox") {
		t.Fatalf("expected firefox note, got %q", note)
	}
}
