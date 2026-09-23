package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/oliver-nyx/coherencelab/internal/adapters"
	"github.com/oliver-nyx/coherencelab/internal/capture"
	"github.com/oliver-nyx/coherencelab/internal/compare"
	"github.com/oliver-nyx/coherencelab/internal/dissect"
	"github.com/oliver-nyx/coherencelab/internal/profile"
	"github.com/oliver-nyx/coherencelab/internal/probe"
	"github.com/oliver-nyx/coherencelab/internal/report"
	"github.com/oliver-nyx/coherencelab/internal/scan"
	"github.com/oliver-nyx/coherencelab/internal/ui"
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
	cmd.AddCommand(labCmd())
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
			return waitForInterrupt(func(ctx context.Context) error {
				return srv.Stop(ctx)
			})
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
			return waitForInterrupt(func(ctx context.Context) error {
				return srv.Stop(ctx)
			})
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "listen address (HTTP)")
	return cmd
}

func labCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lab",
		Short: "Reverse-engineering labs (TLS ClientHello / HTTP/2 wire dissection)",
		Long: `Hands-on protocol dissection for browser-identity reverse engineering.

These commands parse raw bytes with first-principles parsers (see internal/dissect).
Read the code — the annotations are the curriculum.`,
	}

	var (
		helloProfile string
		helloUTLS    string
		helloHex     string
		helloBin     string
		sni          string
		h2Hex        string
		h2Bin        string
		hpackHex     string
		hpackBin     string
		hpackDemo    string
		permUTLS     string
		permSamples  int
	)

	tlsCmd := &cobra.Command{
		Use:   "clienthello",
		Short: "Dissect a TLS ClientHello (file, hex, or synthesized from uTLS)",
		Example: `  coherencelab lab clienthello --utls chrome_131
  coherencelab lab clienthello --profile chrome-131-win
  coherencelab lab clienthello --hex 160301...
  coherencelab lab clienthello --bin capture.bin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw []byte
			var err error
			switch {
			case helloBin != "":
				raw, err = os.ReadFile(helloBin)
			case helloHex != "":
				raw, err = decodeHex(helloHex)
			case helloUTLS != "":
				raw, err = dissect.SynthClientHello(helloUTLS, sni)
			case helloProfile != "":
				p, e := profile.FindByID(profilesDir, helloProfile)
				if e != nil {
					return e
				}
				raw, err = dissect.SynthClientHello(p.TLS.UTLSClientID, sni)
			default:
				return fmt.Errorf("provide --utls, --profile, --hex, or --bin")
			}
			if err != nil {
				return err
			}
			ch, err := dissect.ParseClientHello(raw)
			if err != nil {
				return err
			}
			dissect.FormatClientHello(os.Stdout, ch)
			return nil
		},
	}
	tlsCmd.Flags().StringVar(&helloProfile, "profile", "", "synthesize ClientHello from profile utls_client_id")
	tlsCmd.Flags().StringVar(&helloUTLS, "utls", "", "synthesize ClientHello from uTLS id (e.g. chrome_131)")
	tlsCmd.Flags().StringVar(&helloHex, "hex", "", "ClientHello as hex (record or bare handshake)")
	tlsCmd.Flags().StringVar(&helloBin, "bin", "", "path to raw ClientHello bytes")
	tlsCmd.Flags().StringVar(&sni, "sni", "example.com", "SNI used when synthesizing")

	h2Cmd := &cobra.Command{
		Use:   "h2",
		Short: "Dissect HTTP/2 preface + frames from hex or binary",
		Example: `  coherencelab lab h2 --bin capture.h2
  coherencelab lab h2 --hex 505249202a20485454502f322e30...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw []byte
			var err error
			switch {
			case h2Bin != "":
				raw, err = os.ReadFile(h2Bin)
			case h2Hex != "":
				raw, err = decodeHex(h2Hex)
			default:
				return fmt.Errorf("provide --hex or --bin")
			}
			if err != nil {
				return err
			}
			sess, err := dissect.ParseH2(raw)
			if err != nil {
				return err
			}
			dissect.FormatH2(os.Stdout, sess)
			return nil
		},
	}
	h2Cmd.Flags().StringVar(&h2Hex, "hex", "", "HTTP/2 bytes as hex")
	h2Cmd.Flags().StringVar(&h2Bin, "bin", "", "path to raw HTTP/2 bytes")

	headersCmd := &cobra.Command{
		Use:   "headers",
		Short: "Decode an HPACK header block and classify pseudo-header order",
		Example: `  coherencelab lab headers --demo chrome
  coherencelab lab headers --demo firefox
  coherencelab lab headers --bin headers.hpack`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw []byte
			var err error
			switch {
			case hpackDemo != "":
				order := dissect.PseudoChrome
				switch hpackDemo {
				case "chrome", "edge", "chromium":
					order = dissect.PseudoChrome
				case "firefox":
					order = dissect.PseudoFirefox
				case "safari":
					order = dissect.PseudoSafari
				default:
					return fmt.Errorf("demo must be chrome|firefox|safari")
				}
				raw, err = dissect.EncodeIndexedPseudoBlock(order, "example.com")
			case hpackBin != "":
				raw, err = os.ReadFile(hpackBin)
			case hpackHex != "":
				raw, err = decodeHex(hpackHex)
			default:
				return fmt.Errorf("provide --demo, --hex, or --bin")
			}
			if err != nil {
				return err
			}
			hb, err := dissect.DecodeHeaderBlock(raw)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "═══ HPACK header block ═══")
			dissect.FormatHeaderBlock(os.Stdout, hb)
			return nil
		},
	}
	headersCmd.Flags().StringVar(&hpackDemo, "demo", "", "emit chrome|firefox|safari pseudo order")
	headersCmd.Flags().StringVar(&hpackHex, "hex", "", "HPACK block as hex")
	headersCmd.Flags().StringVar(&hpackBin, "bin", "", "path to HPACK block bytes")

	permCmd := &cobra.Command{
		Use:   "permute",
		Short: "Measure ClientHello extension-order entropy across repeated uTLS hellos",
		Example: `  coherencelab lab permute --utls chrome_131 --samples 8
  coherencelab lab permute --utls firefox_133 --samples 8`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if permUTLS == "" {
				return fmt.Errorf("--utls required")
			}
			rep, err := dissect.AnalyzeExtensionPermutation(permUTLS, sni, permSamples)
			if err != nil {
				return err
			}
			dissect.FormatPermutation(os.Stdout, rep)
			return nil
		},
	}
	permCmd.Flags().StringVar(&permUTLS, "utls", "", "uTLS client id (e.g. chrome_131)")
	permCmd.Flags().IntVar(&permSamples, "samples", 8, "how many ClientHellos to synthesize")
	permCmd.Flags().StringVar(&sni, "sni", "example.com", "SNI used when synthesizing")

	var (
		corpusBin  string
		corpusHex  string
		corpusUTLS string
	)
	corpusCmd := &cobra.Command{
		Use:   "corpus",
		Short: "Diff a captured ClientHello against a uTLS parrot (ground truth vs claim)",
		Example: `  coherencelab lab corpus --bin chrome-capture.bin --utls chrome_131
  coherencelab lab corpus --bin chrome-capture.bin --utls firefox_133`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if corpusUTLS == "" {
				return fmt.Errorf("--utls required (parrot id to compare against the capture)")
			}
			var raw []byte
			var err error
			switch {
			case corpusBin != "":
				raw, err = os.ReadFile(corpusBin)
			case corpusHex != "":
				raw, err = decodeHex(corpusHex)
			default:
				return fmt.Errorf("provide --bin or --hex capture")
			}
			if err != nil {
				return err
			}
			diff, _, _, err := dissect.DiffCapturedVsUTLS(raw, corpusUTLS, sni)
			if err != nil {
				return err
			}
			dissect.FormatHelloDiff(os.Stdout, diff)
			return nil
		},
	}
	corpusCmd.Flags().StringVar(&corpusBin, "bin", "", "captured ClientHello bytes")
	corpusCmd.Flags().StringVar(&corpusHex, "hex", "", "captured ClientHello as hex")
	corpusCmd.Flags().StringVar(&corpusUTLS, "utls", "", "uTLS parrot id (e.g. chrome_131)")
	corpusCmd.Flags().StringVar(&sni, "sni", "example.com", "SNI for parrot synthesis")

	cmd.AddCommand(tlsCmd)
	cmd.AddCommand(h2Cmd)
	cmd.AddCommand(headersCmd)
	cmd.AddCommand(permCmd)
	cmd.AddCommand(corpusCmd)
	return cmd
}

func decodeHex(s string) ([]byte, error) {
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ':' {
			continue
		}
		clean = append(clean, c)
	}
	dst := make([]byte, len(clean)/2)
	n, err := parseHex(dst, clean)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func parseHex(dst, src []byte) (int, error) {
	if len(src)%2 != 0 {
		return 0, fmt.Errorf("odd hex length")
	}
	n := 0
	for i := 0; i < len(src); i += 2 {
		a := fromHex(src[i])
		b := fromHex(src[i+1])
		if a < 0 || b < 0 {
			return 0, fmt.Errorf("invalid hex at %d", i)
		}
		dst[n] = byte(a<<4 | b)
		n++
	}
	return n, nil
}

func fromHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
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
			rep1, err := scan.Run(ctx, scan.Options{Profile: p, Mode: scan.ModeLocal})
			if err != nil {
				return err
			}
			_ = report.Write(os.Stdout, rep1, report.FormatText)

			fmt.Println("=== Demo 2: Platform mismatch (mutate) ===")
			rep2, err := scan.Run(ctx, scan.Options{Profile: p, Mode: scan.ModeMutate, Mutate: "wrong-platform"})
			if err != nil {
				return err
			}
			_ = report.Write(os.Stdout, rep2, report.FormatText)

			fmt.Println("=== Demo 3: Browser mismatch (mutate) ===")
			rep3, err := scan.Run(ctx, scan.Options{Profile: p, Mode: scan.ModeMutate, Mutate: "wrong-browser"})
			if err != nil {
				return err
			}
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
			fmt.Println("coherencelab v1.8.2")
		},
	}
}

func waitForInterrupt(shutdown func(context.Context) error) error {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return shutdown(ctx)
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
