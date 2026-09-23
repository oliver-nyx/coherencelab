package dissect

import (
	"strings"
	"testing"
)

func TestTransportFingerprintChromeVsMinimal(t *testing.T) {
	chromeTPs, _, err := LoadTransportParamsForGolden("quic_initial_chrome")
	if err != nil {
		t.Fatal(err)
	}
	minTPs, _, err := LoadTransportParamsForGolden("quic_tp_minimal")
	if err != nil {
		t.Fatal(err)
	}
	cfp := TransportFingerprint(chromeTPs)
	mfp := TransportFingerprint(minTPs)
	if !strings.Contains(cfp, "gq1") || !strings.Contains(cfp, "|g1|") {
		t.Fatalf("chrome TP fp missing grease signals: %s", cfp)
	}
	if strings.Contains(mfp, "gq1") || strings.Contains(mfp, "|g1|") {
		t.Fatalf("minimal TP fp should lack grease: %s", mfp)
	}
	diff := DiffTransportParameters(chromeTPs, minTPs)
	if diff.Score > 40 {
		t.Fatalf("chrome vs minimal should disagree hard, score=%.1f fp=%s vs %s", diff.Score, cfp, mfp)
	}
	t.Logf("chrome TP fp=%s score-vs-min=%.1f", cfp, diff.Score)
}

func TestH3FingerprintChromeVsMinimal(t *testing.T) {
	_, rawC, err := LoadFixtureBytes("h3_chrome")
	if err != nil {
		t.Fatal(err)
	}
	_, rawM, err := LoadFixtureBytes("h3_minimal")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseH3(rawC)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseH3(rawM)
	if err != nil {
		t.Fatal(err)
	}
	cfp := H3Fingerprint(c)
	mfp := H3Fingerprint(m)
	if !strings.Contains(cfp, "|gf1|") || !strings.Contains(cfp, "u=0,i") {
		t.Fatalf("chrome H3 fp incomplete: %s", cfp)
	}
	if mfp != "1,6|gf0|0" {
		t.Fatalf("minimal H3 fp unexpected: %s", mfp)
	}
	diff := DiffH3Sessions(c, m)
	if diff.Score > 45 {
		t.Fatalf("h3 chrome vs minimal should disagree, score=%.1f", diff.Score)
	}
	same := DiffH3Sessions(c, c)
	if same.Score < 99 {
		t.Fatalf("self-diff score=%.1f", same.Score)
	}
	t.Logf("h3 chrome fp=%s vs minimal=%s score=%.1f", cfp, mfp, diff.Score)
}

func TestCrossLayerChromeFamilyCoherent(t *testing.T) {
	r, err := AnalyzeChromeFamilyCrossLayer()
	if err != nil {
		t.Fatal(err)
	}
	if !r.Coherent {
		t.Fatalf("expected coherent chrome fixtures, conflicts=%v", r.Conflicts)
	}
	if r.H3FP == "" || r.QUICTPFP == "" || r.H2Akamai == "" {
		t.Fatalf("missing fps: %+v", r)
	}
	t.Logf("H2=%s\nH3=%s\nTP=%s", r.H2Akamai, r.H3FP, r.QUICTPFP)
}

func TestGoldenFingerprintsLocked(t *testing.T) {
	// Lock the crafted goldens so gen_corpus regressions fail loudly.
	chromeTPs, _, err := LoadTransportParamsForGolden("quic_initial_chrome")
	if err != nil {
		t.Fatal(err)
	}
	wantTP := "1,3,4,5,6,7,8,9,a,b,e,f,2ab2|g1|gq1"
	if got := TransportFingerprint(chromeTPs); got != wantTP {
		t.Fatalf("quic_initial_chrome TP golden changed\n got  %s\n want %s", got, wantTP)
	}

	_, h3raw, err := LoadFixtureBytes("h3_chrome")
	if err != nil {
		t.Fatal(err)
	}
	h3, err := ParseH3(h3raw)
	if err != nil {
		t.Fatal(err)
	}
	wantH3 := "1,6,7,g|gf1|request_stream:0:u=0,i"
	if got := H3Fingerprint(h3); got != wantH3 {
		t.Fatalf("h3_chrome golden changed\n got  %s\n want %s", got, wantH3)
	}
}
