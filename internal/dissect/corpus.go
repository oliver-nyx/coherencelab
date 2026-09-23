package dissect

import (
	"fmt"
	"io"
	"strings"
)

// HelloDelta is one field-level difference between two ClientHellos.
type HelloDelta struct {
	Field    string
	Ref      string
	Parrot   string
	Severity string // critical | high | medium | low | info
	Note     string
}

// HelloDiff compares a reference (often a real-browser capture) to a parrot
// (often a uTLS synthesis). This is the RE workflow: ground truth vs claim.
type HelloDiff struct {
	RefJA3, ParrotJA3         string
	RefJA4, ParrotJA4         string
	RefSkeleton, ParrotSkeleton string
	Matches                   []string
	Diffs                     []HelloDelta
	Score                     float64 // 0..100 agreement on weighted checks
	Findings                  []string
}

// DiffClientHellos compares two parsed ClientHellos.
func DiffClientHellos(ref, parrot *ClientHello) *HelloDiff {
	d := &HelloDiff{
		RefJA3:          ref.JA3Hash(),
		ParrotJA3:       parrot.JA3Hash(),
		RefJA4:          ref.JA4(),
		ParrotJA4:       parrot.JA4(),
		RefSkeleton:     extensionOrderSignature(ref.ExtensionOrder, true),
		ParrotSkeleton:  extensionOrderSignature(parrot.ExtensionOrder, true),
	}
	var earned, weight float64

	check := func(field, severity, note, a, b string, w float64, equal bool) {
		weight += w
		if equal {
			earned += w
			d.Matches = append(d.Matches, field)
			return
		}
		d.Diffs = append(d.Diffs, HelloDelta{
			Field: field, Ref: a, Parrot: b, Severity: severity, Note: note,
		})
	}

	check("ja3", "high",
		"JA3 strips GREASE; mismatch means cipher/extension/group set differs after normalization",
		d.RefJA3, d.ParrotJA3, 20, d.RefJA3 == d.ParrotJA3)

	check("extension_skeleton", "critical",
		"GREASE-stripped extension type order — stable Chrome identity anchor; frozen wrong skeleton = parrot",
		humanSkeleton(d.RefSkeleton), humanSkeleton(d.ParrotSkeleton), 25,
		d.RefSkeleton == d.ParrotSkeleton)

	refALP := strings.Join(ref.ALPN, ",")
	parALP := strings.Join(parrot.ALPN, ",")
	check("alpn", "high", "ALPN list/order; browsers put h2 first",
		refALP, parALP, 10, refALP == parALP)

	check("alps", "critical",
		"ALPS is Chromium-only; missing on a Chrome claim or present on Firefox claim is decisive",
		fmt.Sprintf("%v", ref.HasALPS), fmt.Sprintf("%v", parrot.HasALPS), 15,
		ref.HasALPS == parrot.HasALPS)

	check("ech", "medium",
		"ECH presence is a generation signal; absence on modern Chrome builds is suspicious",
		fmt.Sprintf("%v", ref.HasECH), fmt.Sprintf("%v", parrot.HasECH), 10,
		ref.HasECH == parrot.HasECH)

	refCS := joinNonGREASE(ref.CipherSuites)
	parCS := joinNonGREASE(parrot.CipherSuites)
	check("ciphers", "high", "Non-GREASE cipher suite list/order",
		refCS, parCS, 10, refCS == parCS)

	refG := joinNonGREASE(ref.SupportedGroups)
	parG := joinNonGREASE(parrot.SupportedGroups)
	check("groups", "high", "Non-GREASE supported_groups (X25519/MLKEM ordering matters)",
		refG, parG, 10, refG == parG)

	check("session_id_len", "medium",
		"Chrome TLS 1.3 compatibility mode uses a 32-byte session_id",
		fmt.Sprintf("%d", len(ref.SessionID)), fmt.Sprintf("%d", len(parrot.SessionID)), 5,
		len(ref.SessionID) == len(parrot.SessionID))

	if weight > 0 {
		d.Score = earned / weight * 100
	}
	d.Findings = helloDiffFindings(d)
	return d
}

// DiffCapturedVsUTLS parses a captured ClientHello and diffs it against a
// freshly synthesized uTLS hello for the claimed browser id.
func DiffCapturedVsUTLS(captured []byte, utlsClientID, sni string) (*HelloDiff, *ClientHello, *ClientHello, error) {
	ref, err := ParseClientHello(captured)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse capture: %w", err)
	}
	raw, err := SynthClientHello(utlsClientID, sni)
	if err != nil {
		return nil, ref, nil, fmt.Errorf("synth parrot: %w", err)
	}
	parrot, err := ParseClientHello(raw)
	if err != nil {
		return nil, ref, nil, fmt.Errorf("parse parrot: %w", err)
	}
	return DiffClientHellos(ref, parrot), ref, parrot, nil
}

func helloDiffFindings(d *HelloDiff) []string {
	var out []string
	out = append(out, fmt.Sprintf("Agreement score: %.1f%% (%d matches, %d diffs)", d.Score, len(d.Matches), len(d.Diffs)))
	crit := 0
	for _, x := range d.Diffs {
		if x.Severity == "critical" {
			crit++
		}
	}
	if crit > 0 {
		out = append(out, fmt.Sprintf("%d critical delta(s) — parrot is not coherent with the captured hello", crit))
	}
	if d.Score >= 95 && len(d.Diffs) == 0 {
		out = append(out, "Capture and parrot agree on weighted surfaces — good uTLS fidelity for this id")
	}
	if d.RefJA3 == d.ParrotJA3 && d.RefSkeleton != d.ParrotSkeleton {
		out = append(out, "JA3 matches but extension skeleton differs — classic case where JA3-only tooling lies")
	}
	return out
}

// FormatHelloDiff writes an expert-oriented corpus diff report.
func FormatHelloDiff(w io.Writer, d *HelloDiff) {
	fmt.Fprintln(w, "═══ ClientHello corpus diff (capture vs parrot) ═══")
	fmt.Fprintf(w, "Score: %.1f%%\n", d.Score)
	fmt.Fprintf(w, "JA3  ref=%s\n     par=%s\n", d.RefJA3, d.ParrotJA3)
	fmt.Fprintf(w, "JA4* ref=%s\n     par=%s\n", d.RefJA4, d.ParrotJA4)
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
		fmt.Fprintf(w, "      ref:    %s\n", x.Ref)
		fmt.Fprintf(w, "      parrot: %s\n", x.Parrot)
		if x.Note != "" {
			fmt.Fprintf(w, "      ※ %s\n", x.Note)
		}
	}
	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range d.Findings {
		fmt.Fprintf(w, "• %s\n", f)
	}
}
