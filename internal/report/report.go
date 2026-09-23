package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/oliver-nyx/coherencelab/internal/rules"
	"github.com/oliver-nyx/coherencelab/internal/scan"
)

// Format output format.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Write renders a scan report.
func Write(w io.Writer, rep *scan.Report, format Format) error {
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	default:
		return writeText(w, rep)
	}
}

// WriteToFile saves report to path.
func WriteToFile(path string, rep *scan.Report, format Format) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return Write(f, rep, format)
}

func writeText(w io.Writer, rep *scan.Report) error {
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	cyan.Fprintf(w, "\n  CoherenceLab Scan Report\n")
	cyan.Fprintf(w, "  ─────────────────────────────────────────\n\n")
	fmt.Fprintf(w, "  Profile:  %s (%s)\n", rep.ProfileName, rep.ProfileID)
	fmt.Fprintf(w, "  Mode:     %s\n", rep.Mode)
	if rep.ProbeURL != "" {
		fmt.Fprintf(w, "  Probe:    %s\n", rep.ProbeURL)
	}
	fmt.Fprintf(w, "  Time:     %s\n\n", rep.Timestamp.Format("2006-01-02 15:04:05 UTC"))

	scoreColor := green
	switch rep.Result.Grade {
	case "D", "F":
		scoreColor = red
	case "C":
		scoreColor = yellow
	}

	scoreColor.Fprintf(w, "  Score:    %d / %d (%.1f%%)  Grade: %s\n",
		rep.Result.Score, rep.Result.MaxScore, rep.Result.Percentage, rep.Result.Grade)
	fmt.Fprintf(w, "  Checks:   %d passed, %d failed, %d skipped\n",
		rep.Result.Passed, rep.Result.Failed, rep.Result.Skipped)
	if rep.Result.CriticalFails > 0 {
		red.Fprintf(w, "  Critical: %d failure(s) — automatic grade F\n", rep.Result.CriticalFails)
	}
	fmt.Fprintln(w)

	if rep.Signals != nil {
		yellow.Fprintf(w, "  Observed Signals\n")
		fmt.Fprintf(w, "  ─────────────────\n")
		fmt.Fprintf(w, "  User-Agent:         %s\n", truncate(rep.Signals.UserAgent, 72))
		if rep.Signals.SecCHUA != "" {
			fmt.Fprintf(w, "  Sec-Ch-Ua:          %s\n", truncate(rep.Signals.SecCHUA, 72))
			fmt.Fprintf(w, "  Sec-Ch-Ua-Platform: %s\n", rep.Signals.SecCHUAPlatform)
		}
		if rep.Signals.TLS != nil {
			fmt.Fprintf(w, "  TLS:                %s / %s / ALPN=%s\n",
				rep.Signals.TLS.Version, rep.Signals.TLS.CipherSuite, rep.Signals.TLS.ALPN)
			if rep.Signals.TLS.JA3 != "" {
				fmt.Fprintf(w, "  JA3:                %s\n", rep.Signals.TLS.JA3)
			}
		}
		if rep.Signals.H2 != nil {
			src := rep.Signals.H2.Source
			if src == "" {
				src = "unknown"
			}
			fmt.Fprintf(w, "  HTTP/2:             table=%d window=%d concurrent=%d (source=%s)\n",
				rep.Signals.H2.HeaderTableSize,
				rep.Signals.H2.InitialWindowSize,
				rep.Signals.H2.MaxConcurrent,
				src)
		}
		fmt.Fprintln(w)
	}

	if len(rep.Result.FailedFindings) > 0 {
		red.Fprintf(w, "  Failed Checks (%d)\n", len(rep.Result.FailedFindings))
		fmt.Fprintf(w, "  ─────────────────\n")
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		for _, f := range rep.Result.FailedFindings {
			fmt.Fprintf(tw, "  [%s]\t%s\n", strings.ToUpper(string(f.Severity)), f.Title)
			if f.Expected != "" {
				fmt.Fprintf(tw, "  \tExpected: %s\n", truncate(f.Expected, 80))
			}
			if f.Actual != "" {
				fmt.Fprintf(tw, "  \tActual:   %s\n", truncate(f.Actual, 80))
			}
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}

	green.Fprintf(w, "  Category Breakdown\n")
	fmt.Fprintf(w, "  ─────────────────\n")
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	for cat, max := range rep.Result.CategoryMax {
		got := rep.Result.CategoryScores[cat]
		pct := 100.0
		if max > 0 {
			pct = float64(got) / float64(max) * 100
		}
		fmt.Fprintf(tw, "  %-18s\t%d / %d (%.0f%%)\n", cat, got, max, pct)
	}
	_ = tw.Flush()
	fmt.Fprintln(w)

	if rep.Result.Percentage >= 95 && rep.Result.CriticalFails == 0 {
		green.Fprintf(w, "  ✓ Identity signals are coherent for profile %s\n\n", rep.ProfileID)
	} else {
		yellow.Fprintf(w, "  ⚠ Identity mismatch detected — review failed checks above\n\n")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// SummaryLine returns a one-line summary for CI.
func SummaryLine(rep *scan.Report) string {
	return fmt.Sprintf("coherencelab: profile=%s score=%d/%d grade=%s critical=%d",
		rep.ProfileID, rep.Result.Score, rep.Result.MaxScore, rep.Result.Grade, rep.Result.CriticalFails)
}

// CIExitCode returns 0 if pass threshold met.
func CIExitCode(rep *scan.Report, minScore float64) int {
	if rep.Result.CriticalFails > 0 {
		return 1
	}
	if rep.Result.Percentage < minScore {
		return 1
	}
	return 0
}

// FormatFinding returns a human-readable finding line.
func FormatFinding(f rules.Finding) string {
	status := "PASS"
	if !f.Passed {
		status = "FAIL"
	}
	return fmt.Sprintf("[%s] %s — %s", status, f.ID, f.Title)
}
