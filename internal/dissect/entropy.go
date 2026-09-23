package dissect

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// PermutationReport measures ClientHello extension-order entropy across
// repeated synthesises of the same uTLS browser id.
//
// Chrome randomizes GREASE + some extension order. A stable single order
// across N handshakes is an impersonation smell; many distinct orders with
// a stable non-GREASE skeleton is Chrome-like.
type PermutationReport struct {
	UTLSClientID   string
	Samples        int
	UniqueOrders   int
	UniqueJA3      int
	Orders         map[string]int // order signature → count
	JA3            map[string]int
	SkeletonStable bool
	Skeleton       string // GREASE-stripped extension type sequence
	Findings       []string
}

// AnalyzeExtensionPermutation synthesises n ClientHellos and clusters orders.
func AnalyzeExtensionPermutation(utlsClientID, sni string, n int) (*PermutationReport, error) {
	if n < 2 {
		n = 2
	}
	if n > 64 {
		n = 64
	}
	rep := &PermutationReport{
		UTLSClientID: utlsClientID,
		Samples:      n,
		Orders:       map[string]int{},
		JA3:          map[string]int{},
	}
	var skeletons []string
	for i := 0; i < n; i++ {
		raw, err := SynthClientHello(utlsClientID, sni)
		if err != nil {
			return nil, fmt.Errorf("sample %d: %w", i, err)
		}
		ch, err := ParseClientHello(raw)
		if err != nil {
			return nil, fmt.Errorf("sample %d parse: %w", i, err)
		}
		sig := extensionOrderSignature(ch.ExtensionOrder, false)
		skel := extensionOrderSignature(ch.ExtensionOrder, true)
		rep.Orders[sig]++
		rep.JA3[ch.JA3Hash()]++
		skeletons = append(skeletons, skel)
	}
	rep.UniqueOrders = len(rep.Orders)
	rep.UniqueJA3 = len(rep.JA3)
	rep.Skeleton, rep.SkeletonStable = majorityStable(skeletons)
	rep.Findings = permutationFindings(rep)
	return rep, nil
}

func extensionOrderSignature(order []uint16, stripGREASE bool) string {
	parts := make([]string, 0, len(order))
	for _, t := range order {
		if stripGREASE && IsGREASE16(t) {
			continue
		}
		if IsGREASE16(t) {
			parts = append(parts, "G")
			continue
		}
		parts = append(parts, fmt.Sprintf("%d", t))
	}
	return strings.Join(parts, "-")
}

func majorityStable(vals []string) (string, bool) {
	if len(vals) == 0 {
		return "", false
	}
	counts := map[string]int{}
	for _, v := range vals {
		counts[v]++
	}
	best, bestN := "", 0
	for k, n := range counts {
		if n > bestN {
			best, bestN = k, n
		}
	}
	return best, bestN == len(vals)
}

func permutationFindings(rep *PermutationReport) []string {
	var out []string
	chromeLike := strings.Contains(strings.ToLower(rep.UTLSClientID), "chrome") ||
		strings.Contains(strings.ToLower(rep.UTLSClientID), "edge")
	switch {
	case chromeLike && rep.UniqueOrders == 1:
		out = append(out, "Chrome-class id produced ONE extension order across samples — unusual for real Chrome GREASE/permutation; possible frozen parrot")
	case chromeLike && rep.UniqueOrders > 1:
		out = append(out, fmt.Sprintf("Chrome-class id produced %d distinct extension orders across %d samples — permutation entropy present", rep.UniqueOrders, rep.Samples))
	case !chromeLike && rep.UniqueOrders == 1:
		out = append(out, "Single stable extension order — expected for many Firefox/Safari parrots")
	default:
		out = append(out, fmt.Sprintf("%d unique orders / %d samples", rep.UniqueOrders, rep.Samples))
	}
	if rep.UniqueJA3 == 1 {
		out = append(out, "JA3 collapsed to one hash (GREASE stripped) — expected; JA3 cannot see permutation")
	} else {
		out = append(out, fmt.Sprintf("JA3 variants=%d — investigate GREASE stripping in JA3Raw", rep.UniqueJA3))
	}
	if rep.SkeletonStable {
		out = append(out, "GREASE-stripped extension skeleton is stable — good secondary identity anchor")
	} else {
		out = append(out, "GREASE-stripped skeleton varies — stronger randomization or handshake failure noise")
	}
	return out
}

// FormatPermutation writes the entropy report.
func FormatPermutation(w io.Writer, rep *PermutationReport) {
	fmt.Fprintln(w, "═══ ClientHello extension permutation lab ═══")
	fmt.Fprintf(w, "uTLS id: %s\nSamples: %d\nUnique orders: %d\nUnique JA3: %d\n",
		rep.UTLSClientID, rep.Samples, rep.UniqueOrders, rep.UniqueJA3)
	if rep.SkeletonStable {
		fmt.Fprintf(w, "Stable skeleton (GREASE stripped):\n  %s\n", humanSkeleton(rep.Skeleton))
	}
	fmt.Fprintln(w, "\n── Order histogram ──")
	type kv struct {
		k string
		n int
	}
	var list []kv
	for k, n := range rep.Orders {
		list = append(list, kv{k, n})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
	for i, e := range list {
		if i >= 8 {
			fmt.Fprintf(w, "  … %d more\n", len(list)-8)
			break
		}
		fmt.Fprintf(w, "  %2dx  %s\n", e.n, humanSkeleton(e.k))
	}
	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range rep.Findings {
		fmt.Fprintf(w, "• %s\n", f)
	}
}

func humanSkeleton(sig string) string {
	if sig == "" {
		return "(empty)"
	}
	parts := strings.Split(sig, "-")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "G" {
			out = append(out, "GREASE")
			continue
		}
		var id uint16
		if _, err := fmt.Sscanf(p, "%d", &id); err == nil {
			out = append(out, extensionName(id))
			continue
		}
		out = append(out, p)
	}
	if len(out) > 14 {
		return strings.Join(out[:14], " → ") + " → …"
	}
	return strings.Join(out, " → ")
}
