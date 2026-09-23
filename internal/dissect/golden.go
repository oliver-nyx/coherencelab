package dissect

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// GoldenDelta is one field-level difference in a QUIC/H3 golden comparison.
type GoldenDelta struct {
	Field    string
	Ref      string
	Other    string
	Severity string
	Note     string
}

// GoldenDiff compares two golden fingerprints (chrome-like vs naive, or two claims).
type GoldenDiff struct {
	Layer    string // quic_tp | h3 | cross
	RefFP    string
	OtherFP  string
	Matches  []string
	Diffs    []GoldenDelta
	Score    float64
	Findings []string
}

// TransportFingerprint builds a stable QUIC TP identity string:
//
//	nonGREASE_ids(wire)|gN|gq0|gq1|values_hash_hint
//
// Example chrome-like: "1,3,4,5,6,7,8,9,a,b,e,f,2ab2|g1|gq1"
// Naive stacks omit GREASE and grease_quic_bit → low agreement with chrome ref.
func TransportFingerprint(tps []TransportParam) string {
	var ids []string
	greaseN := 0
	gq := "gq0"
	for _, tp := range tps {
		if tp.GREASE {
			greaseN++
			continue
		}
		ids = append(ids, fmt.Sprintf("%x", tp.ID))
		if tp.ID == TPGreaseQUICBit {
			gq = "gq1"
		}
	}
	return fmt.Sprintf("%s|g%d|%s", strings.Join(ids, ","), greaseN, gq)
}

// H3Fingerprint builds a stable HTTP/3 control-stream identity string:
//
//	settings_ids(wire, GREASE as g)|gfN|priority_field
//
// Example chrome-like: "1,6,7,g|gf1|request_stream:0:u=0,i"
func H3Fingerprint(s *H3Session) string {
	if s == nil {
		return ""
	}
	var settings []string
	for _, st := range s.Settings {
		if st.GREASE {
			settings = append(settings, "g")
			continue
		}
		settings = append(settings, fmt.Sprintf("%x", st.ID))
	}
	gf := 0
	for _, fr := range s.Frames {
		if fr.GREASE {
			gf++
		}
	}
	return fmt.Sprintf("%s|gf%d|%s", strings.Join(settings, ","), gf, s.PriorityFingerprint())
}

// DiffTransportParameters scores chrome-vs-naive (or any two) TP surfaces.
func DiffTransportParameters(ref, other []TransportParam) *GoldenDiff {
	d := &GoldenDiff{
		Layer:   "quic_tp",
		RefFP:   TransportFingerprint(ref),
		OtherFP: TransportFingerprint(other),
	}
	var earned, weight float64
	check := func(field, sev, note, a, b string, w float64, eq bool) {
		weight += w
		if eq {
			earned += w
			d.Matches = append(d.Matches, field)
			return
		}
		d.Diffs = append(d.Diffs, GoldenDelta{Field: field, Ref: a, Other: b, Severity: sev, Note: note})
	}

	refIDs := nonGREASETPIDList(ref)
	othIDs := nonGREASETPIDList(other)
	check("tp_id_order", "critical",
		"Non-GREASE transport_parameter id order — Chromium emits a rich set; naive stacks look sparse",
		refIDs, othIDs, 30, refIDs == othIDs)

	refG, othG := countTPGREASE(ref), countTPGREASE(other)
	check("tp_grease", "critical",
		"GREASE TPs (31·N+27) — modern Chromium/quic-go paint these; sterile blobs are a tell",
		fmt.Sprintf("%d", refG), fmt.Sprintf("%d", othG), 25, refG == othG)

	refGQ, othGQ := hasGreaseQUICBit(ref), hasGreaseQUICBit(other)
	check("grease_quic_bit", "high",
		"grease_quic_bit (0x2ab2) presence — Chromium family signal on Initial CRYPTO",
		strconv.FormatBool(refGQ), strconv.FormatBool(othGQ), 20, refGQ == othGQ)

	refMax, othMax := tpDecoded(ref, TPInitialMaxData), tpDecoded(other, TPInitialMaxData)
	check("initial_max_data", "medium",
		"Flow-control budget magnitude — browsers use multi-MB; toy stacks often keep 64KiB",
		refMax, othMax, 15, refMax == othMax)

	refN, othN := fmt.Sprintf("%d", len(ref)), fmt.Sprintf("%d", len(other))
	check("tp_count", "low", "Total TP entries including GREASE",
		refN, othN, 10, refN == othN)

	if weight > 0 {
		d.Score = earned / weight * 100
	}
	d.Findings = goldenFindings(d, "QUIC transport parameters")
	return d
}

// DiffH3Sessions scores chrome-vs-naive HTTP/3 control-stream surfaces.
func DiffH3Sessions(ref, other *H3Session) *GoldenDiff {
	d := &GoldenDiff{
		Layer:   "h3",
		RefFP:   H3Fingerprint(ref),
		OtherFP: H3Fingerprint(other),
	}
	var earned, weight float64
	check := func(field, sev, note, a, b string, w float64, eq bool) {
		weight += w
		if eq {
			earned += w
			d.Matches = append(d.Matches, field)
			return
		}
		d.Diffs = append(d.Diffs, GoldenDelta{Field: field, Ref: a, Other: b, Severity: sev, Note: note})
	}

	check("h3_fingerprint", "critical",
		"Compact H3 identity (settings|grease_frames|priority) — lock this in CI as a golden",
		d.RefFP, d.OtherFP, 20, d.RefFP == d.OtherFP)

	refSet, othSet := h3SettingsSig(ref), h3SettingsSig(other)
	check("settings_ids", "critical",
		"SETTINGS id list (GREASE collapsed to g) — sterile 1/6/7-only stacks stand out",
		refSet, othSet, 25, refSet == othSet)

	refGF, othGF := countH3GREASEFrames(ref), countH3GREASEFrames(other)
	check("grease_frames", "critical",
		"HTTP/3 GREASE frame types (0x1f·N+0x21) — Chromium paints; many parrots omit",
		fmt.Sprintf("%d", refGF), fmt.Sprintf("%d", othGF), 25, refGF == othGF)

	refP, othP := ref.PriorityFingerprint(), other.PriorityFingerprint()
	check("priority_update", "high",
		"RFC 9218 PRIORITY_UPDATE field — Chrome navigations usually send u=/i early",
		refP, othP, 20, refP == othP)

	refGS, othGS := countH3GREASESettings(ref), countH3GREASESettings(other)
	check("grease_settings", "medium",
		"GREASE SETTINGS identifiers",
		fmt.Sprintf("%d", refGS), fmt.Sprintf("%d", othGS), 10, refGS == othGS)

	if weight > 0 {
		d.Score = earned / weight * 100
	}
	d.Findings = goldenFindings(d, "HTTP/3 control stream")
	return d
}

// CrossLayerReport checks whether chrome-like fixtures tell one family story
// across H2 / H3 / QUIC Initial layers (the RE coherence question after Labs 07–10).
type CrossLayerReport struct {
	H2Akamai   string
	H3FP       string
	QUICTPFP   string
	Signals    []string
	Conflicts  []string
	Findings   []string
	Coherent   bool
}

// AnalyzeChromeFamilyCrossLayer loads live Chrome H2/H3/QUIC fixtures and
// reports first-flight honesty (live H2 often lacks PRIORITY_UPDATE; live QUIC
// often lacks grease_quic_bit). For the teaching “EPS everywhere” story use
// AnalyzeTeachingChromeFamilyCrossLayer (h2_continuation + quic_initial_crafted).
func AnalyzeChromeFamilyCrossLayer() (*CrossLayerReport, error) {
	_, h2raw, err := LoadFixtureBytes("h2_chrome")
	if err != nil {
		return nil, err
	}
	h2, err := ParseH2(h2raw)
	if err != nil {
		return nil, err
	}
	_, h3raw, err := LoadFixtureBytes("h3_chrome")
	if err != nil {
		return nil, err
	}
	h3, err := ParseH3(h3raw)
	if err != nil {
		return nil, err
	}
	_, qraw, err := LoadFixtureBytes("quic_initial_chrome")
	if err != nil {
		return nil, err
	}
	qi, err := DecryptInitial(qraw)
	if err != nil {
		return nil, err
	}
	return CrossLayerFromParsed(h2, h3, qi.Transport, CrossLayerLive), nil
}

// AnalyzeTeachingChromeFamilyCrossLayer uses crafted chrome-like fixtures that
// paint PRIORITY_UPDATE + grease_quic_bit together (Labs 07–11 pedagogy).
func AnalyzeTeachingChromeFamilyCrossLayer() (*CrossLayerReport, error) {
	_, h2raw, err := LoadFixtureBytes("h2_continuation")
	if err != nil {
		return nil, err
	}
	h2, err := ParseH2(h2raw)
	if err != nil {
		return nil, err
	}
	_, h3raw, err := LoadFixtureBytes("h3_chrome_crafted")
	if err != nil {
		return nil, err
	}
	h3, err := ParseH3(h3raw)
	if err != nil {
		return nil, err
	}
	_, qraw, err := LoadFixtureBytes("quic_initial_crafted")
	if err != nil {
		return nil, err
	}
	qi, err := DecryptInitial(qraw)
	if err != nil {
		return nil, err
	}
	return CrossLayerFromParsed(h2, h3, qi.Transport, CrossLayerTeaching), nil
}

// CrossLayerMode selects how missing EPS / grease_quic_bit are scored.
type CrossLayerMode int

const (
	CrossLayerTeaching CrossLayerMode = iota // crafted bins — EPS + gq1 required
	CrossLayerLive                           // live first-flight — document gaps as signals
)

// CrossLayerFromParsed builds a coherence report from already-parsed layers.
func CrossLayerFromParsed(h2 *H2Session, h3 *H3Session, tps []TransportParam, mode CrossLayerMode) *CrossLayerReport {
	r := &CrossLayerReport{
		H2Akamai: h2.AkamaiH2Fingerprint(),
		H3FP:     H3Fingerprint(h3),
		QUICTPFP: TransportFingerprint(tps),
	}

	h2PU := h2.PriorityFingerprint() != "0"
	h3PU := h3.PriorityFingerprint() != "0"
	h3GF := countH3GREASEFrames(h3) > 0
	tpG := countTPGREASE(tps) > 0
	gq := hasGreaseQUICBit(tps)

	add := func(ok bool, good, bad string) {
		if ok {
			r.Signals = append(r.Signals, good)
		} else {
			r.Conflicts = append(r.Conflicts, bad)
		}
	}

	switch mode {
	case CrossLayerLive:
		if h2PU {
			r.Signals = append(r.Signals, "H2 PRIORITY_UPDATE present (Akamai field 3 ≠ 0)")
		} else {
			r.Signals = append(r.Signals,
				"Live H2 first flight: Akamai field 3=0 — Chrome often defers PRIORITY_UPDATE until a real request (probe SETTINGS+WINDOW_UPDATE only)")
		}
		add(h3PU, "H3 PRIORITY_UPDATE present (live Chrome control stream)",
			"H3 missing PRIORITY_UPDATE — Chrome navigations usually send u=/i")
		add(h3GF, "H3 GREASE frames present",
			"H3 lacks GREASE frames — sterile parrot smell")
		add(tpG, "QUIC GREASE transport parameters present",
			"QUIC TPs lack GREASE — naive Initial")
		if gq {
			r.Signals = append(r.Signals, "grease_quic_bit present on Initial")
		} else {
			r.Signals = append(r.Signals,
				"Live Chrome Initial: grease_quic_bit absent (gq0) — observed on Windows capture; do not lock gq1 as universal")
		}
		if h3GF && tpG {
			r.Signals = append(r.Signals, "GREASE painted on both H3 frames and QUIC TPs")
		} else if h3GF != tpG {
			r.Conflicts = append(r.Conflicts,
				"GREASE on only one of H3/QUIC — mixed stack / half-upgraded impersonator")
		}
		if h2PU != h3PU {
			r.Signals = append(r.Signals,
				fmt.Sprintf("Live timing: H2 first-flight EPS=%v vs H3 control EPS=%v — not a family break when H2 is preface-only", h2PU, h3PU))
		}
	default: // teaching
		add(h2PU, "H2 PRIORITY_UPDATE present (Akamai field 3 ≠ 0)",
			"H2 missing PRIORITY_UPDATE while claiming Chromium EPS")
		add(h3PU, "H3 PRIORITY_UPDATE present",
			"H3 missing PRIORITY_UPDATE — Chrome navigations usually send u=/i")
		add(h3GF, "H3 GREASE frames present",
			"H3 lacks GREASE frames — sterile parrot smell")
		add(tpG, "QUIC GREASE transport parameters present",
			"QUIC TPs lack GREASE — naive Initial")
		add(gq, "grease_quic_bit present on Initial",
			"grease_quic_bit absent — uncommon for Chromium QUIC teaching fixture")
		if h2PU != h3PU {
			r.Conflicts = append(r.Conflicts,
				fmt.Sprintf("PRIORITY_UPDATE mismatch across H2/H3 (h2=%v h3=%v) — broken family story", h2PU, h3PU))
		} else {
			r.Signals = append(r.Signals, "PRIORITY_UPDATE story consistent across H2 and H3")
		}
		if h3GF && tpG {
			r.Signals = append(r.Signals, "GREASE painted on both H3 frames and QUIC TPs")
		} else if h3GF != tpG {
			r.Conflicts = append(r.Conflicts,
				"GREASE on only one of H3/QUIC — mixed stack / half-upgraded impersonator")
		}
	}

	r.Coherent = len(r.Conflicts) == 0
	r.Findings = append(r.Findings,
		fmt.Sprintf("H2 Akamai: %s", r.H2Akamai),
		fmt.Sprintf("H3 golden:  %s", r.H3FP),
		fmt.Sprintf("QUIC TP:    %s", r.QUICTPFP),
	)
	if r.Coherent {
		if mode == CrossLayerLive {
			r.Findings = append(r.Findings, "Live Chrome H2/H3/QUIC are coherent with documented first-flight EPS/gq timing gaps")
		} else {
			r.Findings = append(r.Findings, "Chrome-family fixtures are cross-layer coherent on GREASE + PRIORITY_UPDATE")
		}
	} else {
		r.Findings = append(r.Findings, fmt.Sprintf("%d cross-layer conflict(s) — investigate before trusting a 'Chrome' claim", len(r.Conflicts)))
	}
	return r
}

// LoadTransportParamsForGolden loads TPs from a quic Initial fixture or raw quic_tp blob.
func LoadTransportParamsForGolden(name string) ([]TransportParam, string, error) {
	fx, raw, err := LoadFixtureBytes(name)
	if err != nil {
		return nil, "", err
	}
	switch fx.Kind {
	case "quic_tp":
		tps, err := ParseTransportParameters(raw)
		return tps, fx.Notes, err
	case "quic":
		d, err := DecryptInitial(raw)
		if err != nil {
			return nil, fx.Notes, err
		}
		return d.Transport, fx.Notes, nil
	default:
		return nil, "", fmt.Errorf("fixture %s kind %s (want quic or quic_tp)", name, fx.Kind)
	}
}

// FormatGoldenDiff writes a chrome-vs-naive (or claim-vs-claim) report.
func FormatGoldenDiff(w io.Writer, d *GoldenDiff) {
	title := "QUIC/H3 golden diff"
	switch d.Layer {
	case "quic_tp":
		title = "QUIC transport-parameter golden diff"
	case "h3":
		title = "HTTP/3 golden diff"
	}
	fmt.Fprintf(w, "═══ %s ═══\n", title)
	fmt.Fprintf(w, "Score: %.1f%%\n", d.Score)
	fmt.Fprintf(w, "FP ref:   %s\n", d.RefFP)
	fmt.Fprintf(w, "FP other: %s\n", d.OtherFP)
	fmt.Fprintln(w, "\n── Matches ──")
	if len(d.Matches) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, m := range d.Matches {
		fmt.Fprintf(w, "  ✓ %s\n", m)
	}
	fmt.Fprintln(w, "\n── Diffs ──")
	if len(d.Diffs) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, x := range d.Diffs {
		fmt.Fprintf(w, "  ✗ [%s] %s\n", x.Severity, x.Field)
		fmt.Fprintf(w, "      ref:   %s\n", x.Ref)
		fmt.Fprintf(w, "      other: %s\n", x.Other)
		if x.Note != "" {
			fmt.Fprintf(w, "      ※ %s\n", x.Note)
		}
	}
	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range d.Findings {
		fmt.Fprintf(w, "• %s\n", f)
	}
}

// FormatCrossLayer writes the H2/H3/QUIC coherence report.
func FormatCrossLayer(w io.Writer, r *CrossLayerReport) {
	fmt.Fprintln(w, "═══ Cross-layer Chrome-family coherence ═══")
	fmt.Fprintf(w, "Coherent: %v\n", r.Coherent)
	fmt.Fprintln(w, "\n── Fingerprints ──")
	fmt.Fprintf(w, "H2 Akamai: %s\n", r.H2Akamai)
	fmt.Fprintf(w, "H3 golden: %s\n", r.H3FP)
	fmt.Fprintf(w, "QUIC TP:   %s\n", r.QUICTPFP)
	fmt.Fprintln(w, "\n── Aligned signals ──")
	if len(r.Signals) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, s := range r.Signals {
		fmt.Fprintf(w, "  ✓ %s\n", s)
	}
	fmt.Fprintln(w, "\n── Conflicts ──")
	if len(r.Conflicts) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, c := range r.Conflicts {
		fmt.Fprintf(w, "  ✗ %s\n", c)
	}
	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "• %s\n", f)
	}
}

func goldenFindings(d *GoldenDiff, layer string) []string {
	var out []string
	out = append(out, fmt.Sprintf("%s agreement: %.1f%% (%d matches, %d diffs)", layer, d.Score, len(d.Matches), len(d.Diffs)))
	crit := 0
	for _, x := range d.Diffs {
		if x.Severity == "critical" {
			crit++
		}
	}
	if crit > 0 {
		out = append(out, fmt.Sprintf("%d critical delta(s) — other side is not a chrome-like golden", crit))
	}
	if d.Score < 40 {
		out = append(out, "Large gap is expected for chrome-vs-naive — use as CI gate when shipping a Chrome QUIC/H3 claim")
	}
	if d.Score >= 95 {
		out = append(out, "Fingerprints agree — golden lock holds")
	}
	return out
}

func nonGREASETPIDList(tps []TransportParam) string {
	var ids []string
	for _, tp := range tps {
		if tp.GREASE {
			continue
		}
		ids = append(ids, fmt.Sprintf("%x", tp.ID))
	}
	return strings.Join(ids, ",")
}

func countTPGREASE(tps []TransportParam) int {
	n := 0
	for _, tp := range tps {
		if tp.GREASE {
			n++
		}
	}
	return n
}

func hasGreaseQUICBit(tps []TransportParam) bool {
	for _, tp := range tps {
		if tp.ID == TPGreaseQUICBit {
			return true
		}
	}
	return false
}

func tpDecoded(tps []TransportParam, id uint64) string {
	for _, tp := range tps {
		if tp.ID == id {
			if tp.Decoded != "" {
				return tp.Decoded
			}
			return fmt.Sprintf("%x", tp.Value)
		}
	}
	return "(absent)"
}

func h3SettingsSig(s *H3Session) string {
	if s == nil {
		return ""
	}
	var parts []string
	for _, st := range s.Settings {
		if st.GREASE {
			parts = append(parts, "g")
			continue
		}
		parts = append(parts, fmt.Sprintf("%x", st.ID))
	}
	return strings.Join(parts, ",")
}

func countH3GREASEFrames(s *H3Session) int {
	if s == nil {
		return 0
	}
	n := 0
	for _, fr := range s.Frames {
		if fr.GREASE {
			n++
		}
	}
	return n
}

func countH3GREASESettings(s *H3Session) int {
	if s == nil {
		return 0
	}
	n := 0
	for _, st := range s.Settings {
		if st.GREASE {
			n++
		}
	}
	return n
}
