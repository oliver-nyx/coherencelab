package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/coherencelab/coherencelab/internal/profile"
	"github.com/coherencelab/coherencelab/internal/probe"
	"github.com/coherencelab/coherencelab/internal/report"
	"github.com/coherencelab/coherencelab/internal/scan"
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
	cmd.AddCommand(profilesCmd())
	cmd.AddCommand(serveCmd())
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
			if profileID == "" {
				return fmt.Errorf("--profile is required")
			}
			p, err := profile.FindByID(profilesDir, profileID)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			rep, err := scan.Run(ctx, scan.Options{
				Profile:  p,
				Mode:     scan.Mode(mode),
				ProbeURL: probeURL,
				Mutate:   mutate,
			})
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
	cmd.Flags().StringVar(&mutate, "mutate", "", "mutation for mutate mode: wrong-platform, wrong-browser, automation-leak, tls-mismatch")
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

func serveCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a local TLS probe server",
		Long:  `Starts a local HTTPS probe server that records client identity signals. Use with --mode live --probe https://127.0.0.1:8443/probe (with --insecure if needed).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := probe.New(addr)
			if err := srv.Start(); err != nil {
				return err
			}
			fmt.Printf("CoherenceLab probe server listening on https://%s\n", addr)
			fmt.Printf("  GET /probe         — receive probe requests\n")
			fmt.Printf("  GET /observations  — view captured observations\n")
			fmt.Printf("  GET /health        — health check\n")
			fmt.Println("\nPress Ctrl+C to stop.")
			select {}
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8443", "listen address")
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
			fmt.Println("coherencelab v1.0.0")
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
