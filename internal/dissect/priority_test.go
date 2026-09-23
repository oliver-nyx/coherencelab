package dissect

import (
	"testing"
)

func TestParsePriorityUpdateChromeLike(t *testing.T) {
	payload := append([]byte{0x00, 0x00, 0x00, 0x01}, []byte("u=0, i")...)
	pu, err := ParsePriorityUpdatePayload(0, payload)
	if err != nil {
		t.Fatal(err)
	}
	if pu.PrioritizedStream != 1 {
		t.Fatalf("stream=%d", pu.PrioritizedStream)
	}
	if pu.Urgency == nil || *pu.Urgency != 0 {
		t.Fatalf("urgency=%v", pu.Urgency)
	}
	if pu.Incremental == nil || !*pu.Incremental {
		t.Fatalf("incremental=%v", pu.Incremental)
	}
}

func TestPriorityUpdateNonZeroHeaderStreamNoted(t *testing.T) {
	payload := append([]byte{0x00, 0x00, 0x00, 0x03}, []byte("u=3")...)
	pu, err := ParsePriorityUpdatePayload(5, payload)
	if err != nil {
		t.Fatal(err)
	}
	if pu.Note == "" || !contains(pu.Note, "MUST be 0") {
		t.Fatalf("note=%q", pu.Note)
	}
}

func TestH2ChromeFixtureHasPriorityUpdate(t *testing.T) {
	// Ensure generator was run — load fixture after regen in CI/local.
	_, raw, err := LoadFixtureBytes("h2_chrome")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseH2(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasNoRFC7540Priorities() {
		t.Fatal("expected SETTINGS_NO_RFC7540_PRIORITIES=1 in chrome fixture")
	}
	if len(s.PriorityUpdates) == 0 {
		t.Fatal("expected PRIORITY_UPDATE in chrome fixture — regenerate with go run ./tools/gen_corpus.go")
	}
	fp := s.PriorityFingerprint()
	if fp != "u=0,i" {
		t.Fatalf("priority fingerprint %q", fp)
	}
	ak := s.AkamaiH2Fingerprint()
	if !contains(ak, "u=0,i") || !contains(ak, "m,a,s,p") || !contains(ak, "9:1") {
		t.Fatalf("akamai fp=%s", ak)
	}
	t.Log(ak)
}

func TestFirefoxFixturePriorityIsZero(t *testing.T) {
	_, raw, err := LoadFixtureBytes("h2_firefox")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseH2(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.PriorityFingerprint() != "0" {
		t.Fatalf("got %s", s.PriorityFingerprint())
	}
}
