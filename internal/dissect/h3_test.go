package dissect

import (
	"testing"
)

func TestVarintRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 63, 64, 16383, 16384, 0xF0700, 0xF0701} {
		b := EncodeVarint(v)
		got, n, err := ReadVarint(b)
		if err != nil {
			t.Fatalf("v=%d: %v", v, err)
		}
		if got != v || n != len(b) {
			t.Fatalf("v=%d got=%d n=%d enc=%x", v, got, n, b)
		}
	}
}

func TestIsH3GREASE(t *testing.T) {
	if !IsH3GREASEFrame(0x21) || !IsH3GREASEFrame(0x40) {
		t.Fatal("expected grease frames")
	}
	if IsH3GREASEFrame(H3FrameSettings) || IsH3GREASEFrame(H3FramePriorityUpdateRequest) {
		t.Fatal("settings/priority must not be grease")
	}
}

func TestParseH3ChromeLike(t *testing.T) {
	raw := craftH3ChromeLike()
	s, err := ParseH3(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.PriorityUpdates) != 1 {
		t.Fatalf("priority updates=%d", len(s.PriorityUpdates))
	}
	pu := s.PriorityUpdates[0]
	if pu.FrameType != H3FramePriorityUpdateRequest || pu.TargetID != 0 {
		t.Fatalf("pu=%+v", pu)
	}
	if pu.Urgency == nil || *pu.Urgency != 0 || pu.Incremental == nil || !*pu.Incremental {
		t.Fatalf("structured=%+v", pu)
	}
	fp := s.PriorityFingerprint()
	if fp != "request_stream:0:u=0,i" {
		t.Fatalf("fp=%s", fp)
	}
	hasGrease := false
	for _, fr := range s.Frames {
		if fr.GREASE {
			hasGrease = true
		}
	}
	if !hasGrease {
		t.Fatal("expected GREASE frame in chrome-like fixture")
	}
}

func TestParseH3MinimalNoPriority(t *testing.T) {
	raw := craftH3Minimal()
	s, err := ParseH3(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.PriorityFingerprint() != "0" {
		t.Fatalf("got %s", s.PriorityFingerprint())
	}
}

func TestH3FixtureCatalog(t *testing.T) {
	_, raw, err := LoadFixtureBytes("h3_chrome")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseH3(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.PriorityUpdates) == 0 {
		t.Fatal("expected PRIORITY_UPDATE — regenerate with go run ./tools/gen_corpus.go")
	}
	if !contains(s.PriorityFingerprint(), "u=0,i") {
		t.Fatalf("fp=%s", s.PriorityFingerprint())
	}
	if s.HeaderBlock == nil || s.HeaderBlock.PseudoOrder != PseudoChrome {
		t.Fatalf("expected QPACK chrome pseudo, got %+v", s.HeaderBlock)
	}

	_, raw2, err := LoadFixtureBytes("h3_minimal")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := ParseH3(raw2)
	if err != nil {
		t.Fatal(err)
	}
	if s2.PriorityFingerprint() != "0" {
		t.Fatalf("minimal fp=%s", s2.PriorityFingerprint())
	}
}

func TestBadRequestStreamIDNoted(t *testing.T) {
	// stream id 1 is server-bidi, not client-bidi
	payload := append(EncodeVarint(1), []byte("u=3")...)
	pu, err := ParseH3PriorityUpdate(H3FramePriorityUpdateRequest, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(pu.Note, "H3_ID_ERROR") {
		t.Fatalf("note=%q", pu.Note)
	}
}

func craftH3ChromeLike() []byte {
	// SETTINGS: QPACK_MAX_TABLE_CAPACITY=0, MAX_FIELD_SECTION_SIZE=262144, GREASE
	var settings []byte
	settings = AppendVarint(settings, H3SettingQPACKMaxTableCapacity)
	settings = AppendVarint(settings, 0)
	settings = AppendVarint(settings, H3SettingMaxFieldSectionSize)
	settings = AppendVarint(settings, 262144)
	settings = AppendVarint(settings, H3SettingQPACKBlockedStreams)
	settings = AppendVarint(settings, 100)
	settings = AppendVarint(settings, 0x21) // GREASE setting
	settings = AppendVarint(settings, 1)

	var buf []byte
	buf = AppendH3Frame(buf, H3FrameSettings, settings)
	buf = AppendH3Frame(buf, 0x21, nil) // GREASE frame
	puPayload := append(EncodeVarint(0), []byte("u=0, i")...)
	buf = AppendH3Frame(buf, H3FramePriorityUpdateRequest, puPayload)
	qpack, err := EncodeQPACKPseudoBlock(PseudoChrome, "example.com")
	if err != nil {
		panic(err)
	}
	buf = AppendH3Frame(buf, H3FrameHeaders, qpack)
	return buf
}

func craftH3Minimal() []byte {
	var settings []byte
	settings = AppendVarint(settings, H3SettingQPACKMaxTableCapacity)
	settings = AppendVarint(settings, 0)
	settings = AppendVarint(settings, H3SettingMaxFieldSectionSize)
	settings = AppendVarint(settings, 16384)
	return AppendH3Frame(nil, H3FrameSettings, settings)
}
