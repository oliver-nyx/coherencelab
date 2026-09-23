package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/coherencelab/coherencelab/internal/adapters"
	"github.com/coherencelab/coherencelab/internal/capture"
	"github.com/coherencelab/coherencelab/internal/compare"
	"github.com/coherencelab/coherencelab/internal/profile"
	"github.com/coherencelab/coherencelab/internal/probe"
	"github.com/coherencelab/coherencelab/internal/report"
	"github.com/coherencelab/coherencelab/internal/scan"
	"github.com/coherencelab/coherencelab/internal/ui"
)

var (
	profilesDir string
	outputPath  string
	format      string
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "coherencelab",
		Short: "Browser identity consistency validator",
		Long: `CoherenceLab validates that TLS, HTTP/2, headers, and Client Hints
all tell the same story. Mismatched identity layers are the #1 cause of
bot detection failures in production HTTP clients and automation stacks.`,
	}
	cmd.PersistentFlags().StringVar(&profilesDir, "profiles", defaultProfilesDir(), "path to browser profiles directory")

	cmd.AddCommand(scanCmd())
	cmd.AddCommand(compareCmd())
	cmd.AddCommand(captureCmd())
	cmd.AddCommand(profilesCmd())
	cmd.AddCommand(serveCmd())
	cmd.AddCommand(uiCmd())
	cmd.AddCommand(demoCmd())
	cmd.AddCommand(versionCmd())
	return cmd
}

func scanCmd() *cobra.Command {
	var (
		profileID string
		mode      string
		probeURL  string
		mutate    string
		importPath string
		adapter   string
		insecure  bool
		minScore  float64
		ci        bool
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a coherence scan against a browser profile",
		Example: `  coherencelab scan --profile chrome-131-win
  coherencelab scan --profile chrome-131-win --mode live --probe https://tls.peet.ws/api/all
  coherencelab scan --profile chrome-131-win --mode mutate --mutate wrong-platform
  coherencelab scan --profile chrome-131-win --ci --min-score 90`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			opts := scan.Options{
				Mode:     scan.Mode(mode),
				ProbeURL: probeURL,
				Mutate:   mutate,
				Insecure: insecure,
			}

			if importPath != "" {
				snap, p, err := adapters.ScanExport(adapter, importPath, profilesDir, profileID)
				if err != nil {
					return err
				}
				opts.Profile = p
				opts.Mode = scan.ModeImport
				opts.Snapshot = snap
			} else {
				if profileID == "" {
					return fmt.Errorf("--profile is required")
				}
				p, err := profile.FindByID(profilesDir, profileID)
				if err != nil {
					return err
				}
				opts.Profile = p
			}

			rep, err := scan.Run(ctx, opts)
			if err != nil {
				return err
			}

			if outputPath != "" {
				if err := report.WriteToFile(outputPath, rep, report.Format(format)); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "Report written to %s\n", outputPath)
			} else {
				if err := report.Write(os.Stdout, rep, report.Format(format)); err != nil {
					return err
				}
			}

			if ci {
				code := report.CIExitCode(rep, minScore)
				fmt.Fprintln(os.Stderr, report.SummaryLine(rep))
				if code != 0 {
					os.Exit(code)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&profileID, "profile", "p", "", "browser profile ID (required)")
	cmd.Flags().StringVar(&mode, "mode", "local", "scan mode: local, live, mutate")
	cmd.Flags().StringVar(&probeURL, "probe", "", "probe URL for live mode")
	cmd.Flags().StringVar(&mutate, "mutate", "", "mutation for mutate mode: wrong-platform, wrong-browser, automation-leak, tls-mismatch, js-webdriver, js-wrong-platform")
	cmd.Flags().StringVar(&importPath, "import", "", "JSON session export to scan (httpcloak adapter)")
	cmd.Flags().StringVar(&adapter, "adapter", "httpcloak", "adapter for --import: httpcloak, playwright, curl")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verify for live probe (local testing)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "write report to file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json")
	cmd.Flags().Float64Var(&minScore, "min-score", 90, "minimum score percentage for --ci")
	cmd.Flags().BoolVar(&ci, "ci", false, "exit non-zero if score below threshold or critical failures")
	return cmd
}

func profilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "List and inspect browser profiles",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List available profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := profile.LoadDir(profilesDir)
			if err != nil {
				return err
			}
			fmt.Printf("%-22s %-10s %-12s %s\n", "ID", "BROWSER", "PLATFORM", "NAME")
			fmt.Println(stringsRepeat("-", 72))
			for _, p := range profiles {
				fmt.Printf("%-22s %-10s %-12s %s\n", p.ID, p.Browser, p.Platform, p.Name)
			}
			return nil
		},
	})
	var showID string
	show := &cobra.Command{
		Use:   "show",
		Short: "Show profile details",
		RunE: func(cmd *cobra.Command, args []string) error {
			if showID == "" && len(args) > 0 {
				showID = args[0]
			}
			if showID == "" {
				return fmt.Errorf("profile ID required")
			}
			p, err := profile.FindByID(profilesDir, showID)
			if err != nil {
				return err
			}
			fmt.Printf("ID:          %s\n", p.ID)
			fmt.Printf("Name:        %s\n", p.Name)
			fmt.Printf("Browser:     %s %s\n", p.Browser, p.Version)
			fmt.Printf("Platform:    %s\n", p.Platform)
			fmt.Printf("Description: %s\n\n", p.Description)
			fmt.Printf("User-Agent:  %s\n", p.UserAgent.Pattern)
			if p.ClientHints.SecCHUA != "" {
				fmt.Printf("Sec-Ch-Ua:   %s\n", p.ClientHints.SecCHUA)
			}
			fmt.Printf("TLS Client:  %s\n", p.TLS.UTLSClientID)
			fmt.Printf("ALPN:        %v\n", p.TLS.ALPN)
			return nil
		},
	}
	show.Flags().StringVarP(&showID, "profile", "p", "", "profile ID")
	cmd.AddCommand(show)
	cmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate all profiles pass local coherence checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := profile.LoadDir(profilesDir)
			if err != nil {
				return err
			}
			ctx := context.Background()
			var failed int
			for _, p := range profiles {
				rep, err := scan.Run(ctx, scan.Options{Profile: p, Mode: scan.ModeLocal})
				if err != nil {
					return fmt.Errorf("%s: %w", p.ID, err)
				}
				if rep.Result.CriticalFails > 0 || rep.Result.Grade == "F" {
					fmt.Printf("FAIL  %s  grade=%s  score=%.0f%%\n", p.ID, rep.Result.Grade, rep.Result.Percentage)
					failed++
					continue
				}
				fmt.Printf("OK    %s  grade=%s  score=%.0f%%\n", p.ID, rep.Result.Grade, rep.Result.Percentage)
			}
			fmt.Printf("\n%d/%d profiles passed\n", len(profiles)-failed, len(profiles))
			if failed > 0 {
				return fmt.Errorf("%d profile(s) failed validation", failed)
			}
			return nil
		},
	})
	return cmd
}

func compareCmd() *cobra.Command {
	var (
		pathA, pathB       string
		adapterA, adapterB string
		defaultAdapter     string
		labelA, labelB     string
		outFormat          string
	)
	cmd := &cobra.Command{
		Use:   "compare",
		Short: "Compare two session exports for identity mismatches",
		Example: `  coherencelab compare --a chrome.json --b broken.json --adapter httpcloak
  coherencelab compare --a pw.json --adapter-a playwright --b curl.json --adapter-b curl`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if pathA == "" || pathB == "" {
				return fmt.Errorf("--a and --b are required")
			}
			aAdapt := adapterA
			if aAdapt == "" {
				aAdapt = defaultAdapter
			}
			bAdapt := adapterB
			if bAdapt == "" {
				bAdapt = aAdapt
			}
			snapA, idA, err := adapters.LoadSnapshot(aAdapt, pathA)
			if err != nil {
				return fmt.Errorf("load A: %w", err)
			}
			snapB, idB, err := adapters.LoadSnapshot(bAdapt, pathB)
			if err != nil {
				return fmt.Errorf("load B: %w", err)
			}
			if labelA == "" {
				labelA = defaultLabel(pathA, idA)
			}
			if labelB == "" {
				labelB = defaultLabel(pathB, idB)
			}
			result := compare.Snapshots(labelA, snapA, labelB, snapB)
			switch outFormat {
			case "json":
				return compare.WriteJSON(os.Stdout, result)
			default:
				return compare.WriteText(os.Stdout, result)
			}
		},
	}
	cmd.Flags().StringVar(&pathA, "a", "", "first export JSON path")
	cmd.Flags().StringVar(&pathB, "b", "", "second export JSON path")
	cmd.Flags().StringVar(&defaultAdapter, "adapter", "httpcloak", "default adapter for both exports")
	cmd.Flags().StringVar(&adapterA, "adapter-a", "", "adapter for --a (overrides --adapter)")
	cmd.Flags().StringVar(&adapterB, "adapter-b", "", "adapter for --b (overrides --adapter)")
	cmd.Flags().StringVar(&labelA, "label-a", "", "display label for A")
	cmd.Flags().StringVar(&labelB, "label-b", "", "display label for B")
	cmd.Flags().StringVar(&outFormat, "format", "text", "output format: text, json")
	return cmd
}

func defaultLabel(path, profileID string) string {
	if profileID != "" {
		return profileID
	}
	return filepath.Base(path)
}

func captureCmd() *cobra.Command {
	var input, output string
	cmd := &cobra.Command{
		Use:   "capture",
		Short: "Generate a profile YAML from a captured session JSON",
		Example: `  coherencelab capture --input session-capture.json --output profiles/my-client.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if input == "" || output == "" {
				return fmt.Errorf("--input and --output are required")
			}
			in, err := capture.FromJSONFile(input)
			if err != nil {
				return err
			}
			p, err := capture.ToProfile(in)
			if err != nil {
				return err
			}
			if err := capture.WriteYAML(output, p); err != nil {
				return err
			}
			fmt.Printf("Profile written to %s\n", output)
			return nil
		},
	}
	cmd.Flags().StringVar(&input, "input", "", "captured session JSON")
	cmd.Flags().StringVar(&output, "output", "", "output profile YAML path")
	return cmd
}

func serveCmd() *cobra.Command {
	var addr, captureDir string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a local TLS probe + browser capture server",
		Long: `Starts a local HTTPS server for live probes and real-browser profile capture.

  GET  /capture       — open in Chrome/Firefox/Safari to auto-capture a profile
  POST /api/capture   — receive JS runtime + write YAML (when --capture-dir is set)
  GET  /probe         — live scan target
  GET  /observations  — recorded probe observations
  GET  /health        — health check`,
		Example: `  coherencelab serve --addr 127.0.0.1:8443 --capture-dir ./captured
  # then open https://127.0.0.1:8443/capture in your browser`,
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := probe.New(addr)
			srv.CaptureDir = captureDir
			if err := srv.Start(); err != nil {
				return err
			}
			fmt.Printf("CoherenceLab probe server listening on https://%s\n", addr)
			fmt.Printf("  GET  /capture        — browser profile capture UI\n")
			fmt.Printf("  POST /api/capture    — save capture (+ YAML if --capture-dir set)\n")
			fmt.Printf("  GET  /probe          — receive live probe requests\n")
			fmt.Printf("  GET  /observations   — view captured observations\n")
			fmt.Printf("  GET  /health         — health check\n")
			if captureDir != "" {
				fmt.Printf("\nCapture directory: %s\n", captureDir)
			} else {
				fmt.Println("\nTip: pass --capture-dir ./captured to write profile YAML automatically.")
			}
			fmt.Printf("\nOpen https://%s/capture in a real browser (accept the self-signed cert).\n", addr)
			fmt.Println("Press Ctrl+C to stop.")
			select {}
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8443", "listen address")
	cmd.Flags().StringVar(&captureDir, "capture-dir", "", "directory to write captured JSON + profile YAML")
	return cmd
}

func uiCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Open the local Web UI report viewer",
		Long:  `Starts an HTTP UI to run coherence scans and view reports in the browser.`,
		Example: `  coherencelab ui --profiles profiles --addr 127.0.0.1:8080
  # then open http://127.0.0.1:8080`,
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := ui.New(addr, profilesDir)
			if err := srv.Start(); err != nil {
				return err
			}
			fmt.Printf("CoherenceLab UI listening on http://%s\n", addr)
			fmt.Printf("  Profiles: %s\n", profilesDir)
			fmt.Printf("Open http://%s in your browser.\n", addr)
			fmt.Println("Press Ctrl+C to stop.")
			select {}
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "listen address (HTTP)")
	return cmd
}

func demoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Run demonstration scans showing coherence vs mismatch",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.FindByID(profilesDir, "chrome-131-win")
			if err != nil {
				return err
			}
			ctx := context.Background()

			fmt.Println("=== Demo 1: Coherent Chrome 131 profile (local) ===")
			rep1, _ := scan.Run(ctx, scan.Options{Profile: p, Mode: scan.ModeLocal})
			_ = report.Write(os.Stdout, rep1, report.FormatText)

			fmt.Println("=== Demo 2: Platform mismatch (mutate) ===")
			rep2, _ := scan.Run(ctx, scan.Options{Profile: p, Mode: scan.ModeMutate, Mutate: "wrong-platform"})
			_ = report.Write(os.Stdout, rep2, report.FormatText)

			fmt.Println("=== Demo 3: Browser mismatch (mutate) ===")
			rep3, _ := scan.Run(ctx, scan.Options{Profile: p, Mode: scan.ModeMutate, Mutate: "wrong-browser"})
			_ = report.Write(os.Stdout, rep3, report.FormatText)
			return nil
		},
	}
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("coherencelab v1.7.0")
		},
	}
}

func defaultProfilesDir() string {
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Join(filepath.Dir(exe), "profiles")
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	candidates := []string{
		"profiles",
		filepath.Join("..", "profiles"),
		filepath.Join("..", "..", "profiles"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return "profiles"
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}
