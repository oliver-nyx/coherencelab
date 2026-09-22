package compare

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

// WriteText renders a comparison result.
func WriteText(w io.Writer, r *Result) error {
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)

	cyan.Fprintf(w, "\n  CoherenceLab Compare\n")
	cyan.Fprintf(w, "  ─────────────────────────────────────────\n\n")
	fmt.Fprintf(w, "  A: %s\n  B: %s\n\n", r.LabelA, r.LabelB)

	if r.Coherent {
		green.Fprintf(w, "  ✓ No mismatches detected between exports\n\n")
		return nil
	}

	red.Fprintf(w, "  %d difference(s) — %d critical, %d high\n\n", r.Total, r.Critical, r.High)
	yellow.Fprintf(w, "  Differences\n")
	fmt.Fprintf(w, "  ─────────────────\n")
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	for _, d := range r.Diffs {
		fmt.Fprintf(tw, "  [%s]\t%s\n", strings.ToUpper(string(d.Severity)), d.Field)
		if d.Note != "" {
			fmt.Fprintf(tw, "  \tNote:   %s\n", d.Note)
		}
		fmt.Fprintf(tw, "  \tA:      %s\n", truncate(d.Left, 72))
		fmt.Fprintf(tw, "  \tB:      %s\n", truncate(d.Right, 72))
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
	return nil
}

// WriteJSON renders JSON output.
func WriteJSON(w io.Writer, r *Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
