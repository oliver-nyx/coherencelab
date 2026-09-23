package dissect

import (
	"testing"
)

func TestVersionNegotiationParse(t *testing.T) {
	raw := CraftVNChromeLike()
	vn, err := ParseVersionNegotiation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(vn.Versions) < 2 {
		t.Fatalf("versions=%v", vn.Versions)
	}
	grease := 0
	for _, v := range vn.Versions {
		if IsQUICVersionGREASE(v) {
			grease++
		}
	}
	if grease == 0 {
		t.Fatal("expected GREASE versions in crafted VN")
	}
	if DetectQUICPacketClass(raw) != "version_negotiation" {
		t.Fatal(DetectQUICPacketClass(raw))
	}
}

func TestRetryIntegrityRoundTrip(t *testing.T) {
	raw, err := CraftRetryChromeLike()
	if err != nil {
		t.Fatal(err)
	}
	if DetectQUICPacketClass(raw) != "retry" {
		t.Fatal(DetectQUICPacketClass(raw))
	}
	odcid := ODCIDFromChromeLikeInitial()
	r, err := ParseRetry(raw, odcid)
	if err != nil {
		t.Fatal(err)
	}
	if r.TagValid == nil || !*r.TagValid {
		t.Fatal("expected valid integrity tag")
	}
	if len(r.RetryToken) == 0 {
		t.Fatal("empty token")
	}
	// Wrong ODCID must fail
	r2, err := ParseRetry(raw, []byte{0xff})
	if err != nil {
		t.Fatal(err)
	}
	if r2.TagValid == nil || *r2.TagValid {
		t.Fatal("wrong ODCID should invalidate tag")
	}
}

func TestRetryAndVNFixtures(t *testing.T) {
	_, raw, err := LoadFixtureBytes("quic_vn")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseVersionNegotiation(raw); err != nil {
		t.Fatal(err)
	}
	_, raw2, err := LoadFixtureBytes("quic_retry")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRetry(raw2, ODCIDFromChromeLikeInitial())
	if err != nil {
		t.Fatal(err)
	}
	if r.TagValid == nil || !*r.TagValid {
		t.Fatal("fixture retry tag invalid")
	}
}
