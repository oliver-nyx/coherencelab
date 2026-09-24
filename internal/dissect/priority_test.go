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

func TestH2LiveChromeRequestFlightPriorityHeader(t *testing.T) {
	_, raw, err := LoadFixtureBytes("h2_chrome")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseH2(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.PriorityFingerprint() != "hdr:u=0,i" {
		t.Fatalf("live Chrome should use Priority HTTP header, got %s", s.PriorityFingerprint())
	}
	if s.HeaderBlock == nil || s.HeaderBlock.PseudoOrder != "m,a,s,p" {
		t.Fatalf("pseudo=%v", s.HeaderBlock)
	}
	ak := s.AkamaiH2Fingerprint()
	want := "1:65536;2:0;4:6291456;6:262144|15663105|hdr:u=0,i|m,a,s,p"
	if ak != want {
		t.Fatalf("live h2 akamai=%s", ak)
	}
	t.Log(ak)
}

func TestH2LiveEdgeRequestFlightMatchesChromeFamily(t *testing.T) {
	_, raw, err := LoadFixtureBytes("h2_edge")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseH2(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := "1:65536;2:0;4:6291456;6:262144|15663105|hdr:u=0,i|m,a,s,p"
	if got := s.AkamaiH2Fingerprint(); got != want {
		t.Fatalf("edge akamai=%s", got)
	}
}

func TestH2ContinuationFixtureHasPriorityUpdate(t *testing.T) {
	// Teaching fixture — regenerate with go run ./tools/gen_corpus.go
	_, raw, err := LoadFixtureBytes("h2_continuation")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseH2(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasNoRFC7540Priorities() {
		t.Fatal("expected SETTINGS_NO_RFC7540_PRIORITIES=1 in continuation fixture")
	}
	if len(s.PriorityUpdates) == 0 {
		t.Fatal("expected PRIORITY_UPDATE in h2_continuation — regenerate with go run ./tools/gen_corpus.go")
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
	fx, raw, err := LoadFixtureBytes("h2_firefox")
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
	if fx.Source == "live-browser" {
		want := "1:65536;2:0;4:131072;5:16384|12517377|0|"
		if got := s.AkamaiH2Fingerprint(); got != want {
			t.Fatalf("live firefox H2 akamai changed\n got  %s\n want %s", got, want)
		}
	}
}

func TestLoadFixtureH2FirefoxLive(t *testing.T) {
	fx, raw, err := LoadFixtureBytes("h2_firefox")
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
	if !s.HasPreface || len(s.Frames) < 2 {
		t.Fatalf("preface=%v frames=%d", s.HasPreface, len(s.Frames))
	}
}
