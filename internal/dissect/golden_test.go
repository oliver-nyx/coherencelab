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
	// Live Chrome paints GREASE TPs but often omits grease_quic_bit (gq0).
	if !strings.Contains(cfp, "|g1|") {
		t.Fatalf("live chrome TP fp missing GREASE: %s", cfp)
	}
	if strings.Contains(mfp, "gq1") || strings.Contains(mfp, "|g1|") {
		t.Fatalf("minimal TP fp should lack grease: %s", mfp)
	}
	diff := DiffTransportParameters(chromeTPs, minTPs)
	if diff.Score > 40 {
		t.Fatalf("chrome vs minimal should disagree hard, score=%.1f fp=%s vs %s", diff.Score, cfp, mfp)
	}
	t.Logf("live chrome TP fp=%s score-vs-min=%.1f", cfp, diff.Score)

	craftedTPs, _, err := LoadTransportParamsForGolden("quic_initial_crafted")
	if err != nil {
		t.Fatal(err)
	}
	craf := TransportFingerprint(craftedTPs)
	if !strings.Contains(craf, "gq1") || !strings.Contains(craf, "|g1|") {
		t.Fatalf("crafted TP fp missing grease_quic_bit: %s", craf)
	}
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

func TestCrossLayerLiveChromeFamilyCoherent(t *testing.T) {
	r, err := AnalyzeChromeFamilyCrossLayer()
	if err != nil {
		t.Fatal(err)
	}
	if !r.Coherent {
		t.Fatalf("expected live-mode coherent (documented gaps as signals), conflicts=%v", r.Conflicts)
	}
	if r.Family != "chrome" {
		t.Fatalf("family=%s", r.Family)
	}
	if r.H3FP == "" || r.QUICTPFP == "" || r.H2Akamai == "" {
		t.Fatalf("missing fps: %+v", r)
	}
	if r.H2Akamai != "1:65536;2:0;4:6291456;6:262144|15663105|hdr:u=0,i|m,a,s,p" {
		t.Logf("live H2 Akamai (may drift across Chrome builds): %s", r.H2Akamai)
	}
	t.Logf("H2=%s\nH3=%s\nTP=%s", r.H2Akamai, r.H3FP, r.QUICTPFP)
}

func TestCrossLayerLiveFirefoxFamilyCoherent(t *testing.T) {
	r, err := AnalyzeFirefoxFamilyCrossLayer()
	if err != nil {
		t.Fatal(err)
	}
	if !r.Coherent {
		t.Fatalf("expected firefox live coherent, conflicts=%v signals=%v", r.Conflicts, r.Signals)
	}
	if r.Family != "firefox" {
		t.Fatalf("family=%s", r.Family)
	}
	wantH3 := "1,7,2b603742,ffd277,33,8|gf1|0"
	if r.H3FP != wantH3 {
		t.Fatalf("firefox H3 fp\n got  %s\n want %s", r.H3FP, wantH3)
	}
	if !strings.Contains(r.H2Akamai, "|m,p,a,s") {
		t.Fatalf("firefox H2 should be mpas: %s", r.H2Akamai)
	}
	if strings.Contains(r.QUICTPFP, "3128") {
		t.Fatalf("firefox TP must not include Google 0x3128: %s", r.QUICTPFP)
	}
	t.Logf("H2=%s\nH3=%s\nTP=%s", r.H2Akamai, r.H3FP, r.QUICTPFP)
}

func TestChromiumVsFirefoxFamilyContrast(t *testing.T) {
	r, err := AnalyzeChromiumVsFirefox()
	if err != nil {
		t.Fatal(err)
	}
	if r.H3Diff == nil || r.H3Diff.Score > 55 {
		t.Fatalf("chrome vs firefox H3 should disagree hard, score=%v", r.H3Diff)
	}
	if len(r.Splits) < 3 {
		t.Fatalf("expected several family splits, got %v", r.Splits)
	}
	joined := strings.Join(r.Splits, "\n")
	for _, need := range []string{"m,a,s,p", "0x3128", "0x2b603742"} {
		if !strings.Contains(joined, need) {
			t.Fatalf("missing split mentioning %s in %v", need, r.Splits)
		}
	}
	t.Logf("agreements=%v\nsplits=%v\nscore=%.1f", r.Agreements, r.Splits, r.H3Diff.Score)
}

func TestCrossLayerTeachingChromeFamilyCoherent(t *testing.T) {
	r, err := AnalyzeTeachingChromeFamilyCrossLayer()
	if err != nil {
		t.Fatal(err)
	}
	if !r.Coherent {
		t.Fatalf("expected teaching fixtures coherent, conflicts=%v", r.Conflicts)
	}
	if !strings.Contains(r.QUICTPFP, "gq1") {
		t.Fatalf("teaching QUIC should lock gq1: %s", r.QUICTPFP)
	}
	t.Logf("H2=%s\nH3=%s\nTP=%s", r.H2Akamai, r.H3FP, r.QUICTPFP)
}

func TestGoldenFingerprintsLocked(t *testing.T) {
	liveTPs, _, err := LoadTransportParamsForGolden("quic_initial_chrome")
	if err != nil {
		t.Fatal(err)
	}
	wantLiveTP := "3128,8,5,4,3,6,9,7,1,20,11,f|g1|gq0"
	if got := TransportFingerprint(liveTPs); got != wantLiveTP {
		t.Fatalf("quic_initial_chrome (live) TP golden changed\n got  %s\n want %s", got, wantLiveTP)
	}

	edgeTPs, _, err := LoadTransportParamsForGolden("quic_initial_edge")
	if err != nil {
		t.Fatal(err)
	}
	wantEdgeTP := "3,20,4,11,5,3128,1,7,8,6,f,9|g1|gq0"
	if got := TransportFingerprint(edgeTPs); got != wantEdgeTP {
		t.Fatalf("quic_initial_edge (live) TP golden changed\n got  %s\n want %s", got, wantEdgeTP)
	}
	if got := TransportFingerprint(edgeTPs); got == wantLiveTP {
		t.Fatalf("edge TP order unexpectedly identical to chrome — capture may be a Chrome copy")
	}

	ffTPs, _, err := LoadTransportParamsForGolden("quic_initial_firefox")
	if err != nil {
		t.Fatal(err)
	}
	wantFFTP := "1,4,5,6,7,8,9,b,e,f,11,1d,20|g1|gq0"
	if got := TransportFingerprint(ffTPs); got != wantFFTP {
		t.Fatalf("quic_initial_firefox (live) TP golden changed\n got  %s\n want %s", got, wantFFTP)
	}
	if strings.Contains(TransportFingerprint(ffTPs), "3128") {
		t.Fatalf("firefox TP must not include Google QUIC TP 0x3128: %s", TransportFingerprint(ffTPs))
	}

	craftedTPs, _, err := LoadTransportParamsForGolden("quic_initial_crafted")
	if err != nil {
		t.Fatal(err)
	}
	wantCraftedTP := "1,3,4,5,6,7,8,9,a,b,e,f,2ab2|g1|gq1"
	if got := TransportFingerprint(craftedTPs); got != wantCraftedTP {
		t.Fatalf("quic_initial_crafted TP golden changed\n got  %s\n want %s", got, wantCraftedTP)
	}

	_, h3raw, err := LoadFixtureBytes("h3_chrome")
	if err != nil {
		t.Fatal(err)
	}
	h3, err := ParseH3(h3raw)
	if err != nil {
		t.Fatal(err)
	}
	wantH3 := "1,6,7,33,g|gf1|request_stream:0:u=0,i"
	if got := H3Fingerprint(h3); got != wantH3 {
		t.Fatalf("h3_chrome (live) golden changed\n got  %s\n want %s", got, wantH3)
	}

	_, h3cRaw, err := LoadFixtureBytes("h3_chrome_crafted")
	if err != nil {
		t.Fatal(err)
	}
	h3c, err := ParseH3(h3cRaw)
	if err != nil {
		t.Fatal(err)
	}
	wantH3c := "1,6,7,g|gf1|request_stream:0:u=0,i"
	if got := H3Fingerprint(h3c); got != wantH3c {
		t.Fatalf("h3_chrome_crafted golden changed\n got  %s\n want %s", got, wantH3c)
	}

	_, h3ffRaw, err := LoadFixtureBytes("h3_firefox")
	if err != nil {
		t.Fatal(err)
	}
	h3ff, err := ParseH3(h3ffRaw)
	if err != nil {
		t.Fatal(err)
	}
	// Firefox: QPACK 1+7, WebTransport draft ids (0x2b603742 / 0xffd277),
	// H3_DATAGRAM 0x33, ENABLE_CONNECT 0x8; GREASE frame; no PRIORITY_UPDATE on
	// the first control-stream capture from a simple /probe navigation.
	wantH3ff := "1,7,2b603742,ffd277,33,8|gf1|0"
	if got := H3Fingerprint(h3ff); got != wantH3ff {
		t.Fatalf("h3_firefox (live) golden changed\n got  %s\n want %s", got, wantH3ff)
	}

	_, h2raw, err := LoadFixtureBytes("h2_chrome")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ParseH2(h2raw)
	if err != nil {
		t.Fatal(err)
	}
	wantH2 := "1:65536;2:0;4:6291456;6:262144|15663105|hdr:u=0,i|m,a,s,p"
	if got := h2.AkamaiH2Fingerprint(); got != wantH2 {
		t.Fatalf("h2_chrome (live) Akamai golden changed\n got  %s\n want %s", got, wantH2)
	}
}
