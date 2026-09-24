package dissect

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CaptureBundle is one client's wire surfaces, any of which may be absent.
type CaptureBundle struct {
	Hello []byte
	H2    []byte
	H3    []byte
	QUIC  []byte
}

// FamilyMatch is one live-corpus family scored against a capture.
type FamilyMatch struct {
	Family     string
	Score      float64
	HelloScore float64
	H2Score    float64
	H3Score    float64
	QUICScore  float64
	Notes      []string
}

// FingerprintReport ranks a capture against live Chrome, Edge, and Firefox.
type FingerprintReport struct {
	Families  []FamilyMatch
	Best      string
	JA3       string
	JA4       string
	H2        string
	H3        string
	QUIC      string
	Signals   []string
	Conflicts []string
}

type fpFamily struct {
	name                string
	hello, h2, h3, quic string
}

var fingerprintFamilies = []fpFamily{
	{"chrome", "chrome_131", "h2_chrome", "h3_chrome", "quic_initial_chrome"},
	{"edge", "edge_live", "h2_edge", "h3_edge", "quic_initial_edge"},
	{"firefox", "firefox_live", "h2_firefox", "h3_firefox", "quic_initial_firefox"},
}

// FingerprintCapture scores bundle against the live-browser corpus.
// Layers that failed to parse are skipped, not treated as a family miss.
func FingerprintCapture(bundle CaptureBundle) (*FingerprintReport, error) {
	rep := &FingerprintReport{}
	var hello *ClientHello
	if len(bundle.Hello) > 0 {
		ch, err := ParseClientHello(bundle.Hello)
		if err != nil {
			return nil, fmt.Errorf("parse clienthello: %w", err)
		}
		hello = ch
		rep.JA3 = ch.JA3Hash()
		rep.JA4 = ch.JA4()
	}
	var h2s *H2Session
	if len(bundle.H2) > 0 {
		s, err := ParseH2(bundle.H2)
		if err != nil {
			rep.Signals = append(rep.Signals, "H2 bytes present but did not parse: "+err.Error())
		} else {
			h2s = s
			rep.H2 = s.AkamaiH2Fingerprint()
		}
	}
	var h3s *H3Session
	if len(bundle.H3) > 0 {
		s, err := ParseH3(bundle.H3)
		if err != nil {
			rep.Signals = append(rep.Signals, "H3 bytes present but did not parse: "+err.Error())
		} else {
			h3s = s
			rep.H3 = H3Fingerprint(s)
		}
	}
	var tps []TransportParam
	if len(bundle.QUIC) > 0 {
		d, err := DecryptInitialCapture(bundle.QUIC)
		if err != nil {
			rep.Signals = append(rep.Signals, "QUIC Initial present but did not decrypt: "+err.Error())
		} else if len(d.Transport) == 0 {
			rep.Signals = append(rep.Signals, "QUIC Initial decrypted without transport parameters")
		} else {
			tps = d.Transport
			rep.QUIC = TransportFingerprint(tps)
		}
	}
	if hello == nil && h2s == nil && h3s == nil && tps == nil {
		return nil, fmt.Errorf("no parseable ClientHello, H2, H3, or QUIC capture")
	}

	for _, fam := range fingerprintFamilies {
		m := scoreFamily(fam, hello, h2s, h3s, tps)
		rep.Families = append(rep.Families, m)
	}
	sort.SliceStable(rep.Families, func(i, j int) bool {
		return rep.Families[i].Score > rep.Families[j].Score
	})
	if len(rep.Families) > 0 {
		rep.Best = rep.Families[0].Family
	}
	rep.Conflicts = fingerprintConflicts(rep)
	if rep.Best != "" {
		rep.Signals = append(rep.Signals, fmt.Sprintf("Closest live corpus family: %s (%.0f%%)", rep.Best, rep.Families[0].Score))
	}
	return rep, nil
}

func scoreFamily(fam fpFamily, hello *ClientHello, h2s *H2Session, h3s *H3Session, tps []TransportParam) FamilyMatch {
	m := FamilyMatch{Family: fam.name}
	var earned, weight float64
	add := func(w, score float64) {
		weight += w
		earned += w * score / 100
	}
	if hello != nil {
		if _, raw, err := LoadFixtureBytes(fam.hello); err == nil {
			if ref, err := ParseClientHello(raw); err == nil {
				d := DiffClientHellos(ref, hello)
				m.HelloScore = d.Score
				add(50, d.Score)
				m.Notes = append(m.Notes, fmt.Sprintf("hello %.0f%% vs %s", d.Score, fam.hello))
			}
		}
	}
	if h2s != nil {
		if _, raw, err := LoadFixtureBytes(fam.h2); err == nil {
			if ref, err := ParseH2(raw); err == nil {
				m.H2Score = h2PseudoScore(ref, h2s)
				add(25, m.H2Score)
				m.Notes = append(m.Notes, fmt.Sprintf("h2 pseudo %.0f%% vs %s", m.H2Score, fam.h2))
			}
		}
	}
	if h3s != nil {
		if _, raw, err := LoadFixtureBytes(fam.h3); err == nil {
			if ref, err := ParseH3(raw); err == nil {
				m.H3Score = h3FamilyScore(ref, h3s)
				add(15, m.H3Score)
				m.Notes = append(m.Notes, fmt.Sprintf("h3 %.0f%% vs %s", m.H3Score, fam.h3))
			}
		}
	}
	if len(tps) > 0 {
		if _, raw, err := LoadFixtureBytes(fam.quic); err == nil {
			if d, err := DecryptInitialCapture(raw); err == nil && len(d.Transport) > 0 {
				m.QUICScore = quicFamilyScore(d.Transport, tps)
				add(15, m.QUICScore)
				m.Notes = append(m.Notes, fmt.Sprintf("quic tp %.0f%% vs %s", m.QUICScore, fam.quic))
			}
		}
	}
	if weight > 0 {
		m.Score = earned / weight * 100
	}
	return m
}

func h2PseudoScore(ref, got *H2Session) float64 {
	rp, gp := "", ""
	if ref.HeaderBlock != nil {
		rp = ref.HeaderBlock.PseudoOrder
	}
	if got.HeaderBlock != nil {
		gp = got.HeaderBlock.PseudoOrder
	}
	switch {
	case rp != "" && rp == gp:
		return 100
	case rp == "" || gp == "":
		return 40 // preface-only: inconclusive, not a contradiction
	default:
		return 0
	}
}

func h3FamilyScore(ref, got *H3Session) float64 {
	j := jaccardU64(h3SettingIDs(ref), h3SettingIDs(got))
	prio := 0.0
	if (len(ref.PriorityUpdates) > 0) == (len(got.PriorityUpdates) > 0) {
		prio = 30
	}
	return j*70 + prio
}

func quicFamilyScore(ref, got []TransportParam) float64 {
	return jaccardU64(tpIDs(ref), tpIDs(got)) * 100
}

func h3SettingIDs(s *H3Session) []uint64 {
	var ids []uint64
	for _, st := range s.Settings {
		if st.GREASE {
			continue
		}
		ids = append(ids, st.ID)
	}
	return ids
}

func tpIDs(tps []TransportParam) []uint64 {
	var ids []uint64
	for _, tp := range tps {
		if tp.GREASE {
			continue
		}
		ids = append(ids, tp.ID)
	}
	return ids
}

func jaccardU64(a, b []uint64) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	sa, sb := map[uint64]struct{}{}, map[uint64]struct{}{}
	for _, v := range a {
		sa[v] = struct{}{}
	}
	inter := 0
	for _, v := range b {
		if _, ok := sa[v]; ok {
			inter++
		}
		sb[v] = struct{}{}
	}
	union := len(sa)
	for v := range sb {
		if _, ok := sa[v]; !ok {
			union++
		}
	}
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}

func fingerprintConflicts(rep *FingerprintReport) []string {
	if rep.H2 == "" || len(rep.Families) < 2 {
		return nil
	}
	var helloBest, h2Best string
	var helloScore, h2Score float64
	for _, f := range rep.Families {
		if f.HelloScore > helloScore {
			helloScore = f.HelloScore
			helloBest = f.Family
		}
		if f.H2Score > h2Score {
			h2Score = f.H2Score
			h2Best = f.Family
		}
	}
	if helloBest != "" && h2Best != "" && helloBest != h2Best && h2Score >= 100 && helloScore >= 50 {
		return []string{fmt.Sprintf("ClientHello closest to %s but H2 pseudo-header order closest to %s", helloBest, h2Best)}
	}
	return nil
}

// LoadCaptureDir picks the newest ClientHello, H2, H3, and QUIC file in dir.
// A *.quic-flight.bin wins over a single *.quic.bin when both exist.
func LoadCaptureDir(dir string) (CaptureBundle, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return CaptureBundle{}, err
	}
	type hit struct {
		path string
		mod  time.Time
	}
	var hello, h2, h3, flight, quic *hit
	consider := func(dst **hit, path string, mod time.Time) {
		if *dst == nil || mod.After((*dst).mod) {
			*dst = &hit{path: path, mod: mod}
		}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		info, err := e.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(dir, name)
		switch {
		case strings.HasSuffix(name, ".clienthello.bin"):
			consider(&hello, path, info.ModTime())
		case strings.HasSuffix(name, ".h2.bin"):
			consider(&h2, path, info.ModTime())
		case strings.HasSuffix(name, ".h3.bin"):
			consider(&h3, path, info.ModTime())
		case strings.HasSuffix(name, ".quic-flight.bin"):
			consider(&flight, path, info.ModTime())
		case strings.HasSuffix(name, ".quic.bin"):
			consider(&quic, path, info.ModTime())
		}
	}
	var b CaptureBundle
	read := func(h *hit) ([]byte, error) {
		if h == nil {
			return nil, nil
		}
		return os.ReadFile(h.path)
	}
	var err2 error
	if b.Hello, err2 = read(hello); err2 != nil {
		return b, err2
	}
	if b.H2, err2 = read(h2); err2 != nil {
		return b, err2
	}
	if b.H3, err2 = read(h3); err2 != nil {
		return b, err2
	}
	if flight != nil {
		b.QUIC, err2 = read(flight)
	} else {
		b.QUIC, err2 = read(quic)
	}
	return b, err2
}

// FormatFingerprint writes the family ranking.
func FormatFingerprint(w io.Writer, rep *FingerprintReport) {
	fmt.Fprintln(w, "═══ Wire fingerprint vs live corpus ═══")
	if rep.JA3 != "" {
		fmt.Fprintf(w, "JA3  %s\nJA4  %s\n", rep.JA3, rep.JA4)
	}
	if rep.H2 != "" {
		fmt.Fprintf(w, "H2   %s\n", rep.H2)
	}
	if rep.H3 != "" {
		fmt.Fprintf(w, "H3   %s\n", rep.H3)
	}
	if rep.QUIC != "" {
		fmt.Fprintf(w, "QUIC %s\n", rep.QUIC)
	}
	fmt.Fprintf(w, "\nClosest family: %s\n", rep.Best)
	fmt.Fprintln(w, "\n── Ranking ──")
	for i, f := range rep.Families {
		fmt.Fprintf(w, "  %d. %-8s %5.1f%%   hello %.0f  h2 %.0f  h3 %.0f  quic %.0f\n",
			i+1, f.Family, f.Score, f.HelloScore, f.H2Score, f.H3Score, f.QUICScore)
	}
	if len(rep.Conflicts) > 0 {
		fmt.Fprintln(w, "\n── Cross-layer conflicts ──")
		for _, c := range rep.Conflicts {
			fmt.Fprintf(w, "  ✗ %s\n", c)
		}
	}
	fmt.Fprintln(w, "\n── Notes ──")
	for _, s := range rep.Signals {
		fmt.Fprintf(w, "• %s\n", s)
	}
	if len(rep.Families) > 0 {
		fmt.Fprintf(w, "• %s\n", strings.Join(rep.Families[0].Notes, "; "))
	}
}
