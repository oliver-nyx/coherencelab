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

  GET  /capture       Ã¢â‚¬â€ open in Chrome/Firefox/Safari to auto-capture a profile
  POST /api/capture   Ã¢â‚¬â€ receive JS runtime + write YAML + ClientHello.bin (when --capture-dir is set)
  GET  /probe         Ã¢â‚¬â€ live scan target (also writes ClientHello.bin when --capture-dir is set)
  GET  /clienthello   Ã¢â‚¬â€ download the last captured ClientHello TLS record
  GET  /observations  Ã¢â‚¬â€ recorded probe observations
  GET  /health        Ã¢â‚¬â€ health check`,
		Example: `  coherencelab serve --addr 127.0.0.1:8443 --capture-dir ./captured
  # then open https://127.0.0.1:8443/capture in your browser`,
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := probe.New(addr)
			srv.CaptureDir = captureDir
			if err := srv.Start(); err != nil {
				return err
			}
			fmt.Printf("CoherenceLab probe server listening on https://%s\n", addr)
			fmt.Printf("  GET  /capture        Ã¢â‚¬â€ browser profile capture UI\n")
			fmt.Printf("  POST /api/capture    Ã¢â‚¬â€ save capture (+ YAML + ClientHello if --capture-dir set)\n")
			fmt.Printf("  GET  /probe          Ã¢â‚¬â€ receive live probe requests\n")
			fmt.Printf("  GET  /clienthello    Ã¢â‚¬â€ download last ClientHello record\n")
			fmt.Printf("  GET  /observations   Ã¢â‚¬â€ view captured observations\n")
			fmt.Printf("  GET  /health         Ã¢â‚¬â€ health check\n")
			if captureDir != "" {
				fmt.Printf("\nCapture directory: %s\n", captureDir)
			} else {
				fmt.Println("\nTip: pass --capture-dir ./captured to write profile YAML + ClientHello.bin automatically.")
			}
			fmt.Printf("\nOpen https://%s/capture in a real browser (accept the self-signed cert).\n", addr)
			fmt.Println("Press Ctrl+C to stop.")
			return waitForInterrupt(func(ctx context.Context) error {
				return srv.Stop(ctx)
			})
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8443", "listen address")
	cmd.Flags().StringVar(&captureDir, "capture-dir", "", "directory to write captured JSON + profile YAML + ClientHello.bin")
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
		Short: "Reverse-engineering labs (TLS ClientHello / HTTP/2 / HTTP/3 wire dissection)",
		Long: `Hands-on protocol dissection for browser-identity reverse engineering.

These commands parse raw bytes with first-principles parsers (see internal/dissect).
Read the code Ã¢â‚¬â€ the annotations are the curriculum.`,
	}

	var (
		helloProfile string
		helloUTLS    string
		helloHex     string
		helloBin     string
		helloFix     string
		sni          string
		h2Hex        string
		h2Bin        string
		h2Fix        string
		h3Hex        string
		h3Bin        string
		h3Fix        string
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
  coherencelab lab clienthello --fixture chrome_131
  coherencelab lab clienthello --profile chrome-131-win
  coherencelab lab clienthello --hex 160301...
  coherencelab lab clienthello --bin capture.bin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw []byte
			var err error
			switch {
			case helloFix != "":
				fx, b, e := dissect.LoadFixtureBytes(helloFix)
				if e != nil {
					return e
				}
				if fx.Kind != "clienthello" {
					return fmt.Errorf("fixture %s is kind %s (want clienthello)", fx.Name, fx.Kind)
				}
				fmt.Fprintf(os.Stderr, "fixture %s (%s): %s\n", fx.Name, fx.Source, fx.Notes)
				raw = b
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
				return fmt.Errorf("provide --fixture, --utls, --profile, --hex, or --bin")
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
	tlsCmd.Flags().StringVar(&helloFix, "fixture", "", "bundled testdata/corpus name (e.g. chrome_131)")
	tlsCmd.Flags().StringVar(&helloHex, "hex", "", "ClientHello as hex (record or bare handshake)")
	tlsCmd.Flags().StringVar(&helloBin, "bin", "", "path to raw ClientHello bytes")
	tlsCmd.Flags().StringVar(&sni, "sni", "example.com", "SNI used when synthesizing")

	h2Cmd := &cobra.Command{
		Use:   "h2",
		Short: "Dissect HTTP/2 preface + frames from hex, binary, or fixture",
		Example: `  coherencelab lab h2 --fixture h2_chrome
  coherencelab lab h2 --bin capture.h2
  coherencelab lab h2 --hex 505249202a20485454502f322e30...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw []byte
			var err error
			switch {
			case h2Fix != "":
				fx, b, e := dissect.LoadFixtureBytes(h2Fix)
				if e != nil {
					return e
				}
				if fx.Kind != "h2" {
					return fmt.Errorf("fixture %s is kind %s (want h2)", fx.Name, fx.Kind)
				}
				fmt.Fprintf(os.Stderr, "fixture %s (%s): %s\n", fx.Name, fx.Source, fx.Notes)
				raw = b
			case h2Bin != "":
				raw, err = os.ReadFile(h2Bin)
			case h2Hex != "":
				raw, err = decodeHex(h2Hex)
			default:
				return fmt.Errorf("provide --fixture, --hex, or --bin")
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
	h2Cmd.Flags().StringVar(&h2Fix, "fixture", "", "bundled testdata/corpus name (e.g. h2_chrome)")

	h3Cmd := &cobra.Command{
		Use:   "h3",
		Short: "Dissect HTTP/3 stream frames (SETTINGS / GREASE / PRIORITY_UPDATE)",
		Example: `  coherencelab lab h3 --fixture h3_chrome
  coherencelab lab h3 --fixture h3_minimal
  coherencelab lab h3 --bin decrypted-control-stream.bin`,
		Long: `Parse post-decrypt HTTP/3 frames (QUIC varint Type/Length/Payload).

This lab intentionally starts AFTER QUIC packet protection Ã¢â‚¬â€ feed decrypted
control-stream bytes (or crafted fixtures). Compare Lab 07 (H2 type 0x10)
with RFC 9218 H3 types 0xF0700 / 0xF0701.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw []byte
			var err error
			switch {
			case h3Fix != "":
				fx, b, e := dissect.LoadFixtureBytes(h3Fix)
				if e != nil {
					return e
				}
				if fx.Kind != "h3" {
					return fmt.Errorf("fixture %s is kind %s (want h3)", fx.Name, fx.Kind)
				}
				fmt.Fprintf(os.Stderr, "fixture %s (%s): %s\n", fx.Name, fx.Source, fx.Notes)
				raw = b
			case h3Bin != "":
				raw, err = os.ReadFile(h3Bin)
			case h3Hex != "":
				raw, err = decodeHex(h3Hex)
			default:
				return fmt.Errorf("provide --fixture, --hex, or --bin")
			}
			if err != nil {
				return err
			}
			sess, err := dissect.ParseH3(raw)
			if err != nil {
				return err
			}
			dissect.FormatH3(os.Stdout, sess)
			return nil
		},
	}
	h3Cmd.Flags().StringVar(&h3Hex, "hex", "", "HTTP/3 stream bytes as hex")
	h3Cmd.Flags().StringVar(&h3Bin, "bin", "", "path to decrypted HTTP/3 stream bytes")
	h3Cmd.Flags().StringVar(&h3Fix, "fixture", "", "bundled testdata/corpus name (e.g. h3_chrome)")

	var (
		quicHex        string
		quicBin        string
		quicFix        string
		quicHeaderOnly bool
		quicTPOnly     bool
		quicODCIDHex   string
	)
	quicCmd := &cobra.Command{
		Use:   "quic",
		Short: "Dissect QUIC Initial / Retry / Version Negotiation / transport parameters",
		Long: `Parse QUIC UDP payloads (RFC 9000/9001):

  Initial  Ã¢â‚¬â€ long header Ã¢â€ â€™ HP Ã¢â€ â€™ AEAD (v1 salt) Ã¢â€ â€™ CRYPTO Ã¢â€ â€™ ClientHello Ã¢â€ â€™ TPs
  Retry    Ã¢â‚¬â€ token + integrity tag (pass --odcid to verify)
  VN       Ã¢â‚¬â€ version=0 supported-version list (incl. GREASE 0x?a?a?a?a)
  TP blob  Ã¢â‚¬â€ --tp or fixture kind quic_tp

Packet class is auto-detected unless --header-only / --tp is set.`,
		Example: `  coherencelab lab quic --fixture quic_initial_chrome
  coherencelab lab quic --fixture quic_vn
  coherencelab lab quic --fixture quic_retry --odcid 8394c8f03e515708
  coherencelab lab quic --fixture quic_tp_minimal --tp`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw []byte
			var err error
			var kindHint string
			switch {
			case quicFix != "":
				fx, b, e := dissect.LoadFixtureBytes(quicFix)
				if e != nil {
					return e
				}
				kindHint = fx.Kind
				fmt.Fprintf(os.Stderr, "fixture %s (%s): %s\n", fx.Name, fx.Source, fx.Notes)
				raw = b
			case quicBin != "":
				raw, err = os.ReadFile(quicBin)
			case quicHex != "":
				raw, err = decodeHex(quicHex)
			default:
				return fmt.Errorf("provide --fixture, --hex, or --bin")
			}
			if err != nil {
				return err
			}
			if quicTPOnly || kindHint == "quic_tp" {
				tps, err := dissect.ParseTransportParameters(raw)
				if err != nil {
					return err
				}
				fmt.Fprintln(os.Stdout, "Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â QUIC transport parameters Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â")
				dissect.FormatTransportParameters(os.Stdout, tps)
				fmt.Fprintf(os.Stdout, "\nQUIC TP golden fingerprint:\n  %s\n", dissect.TransportFingerprint(tps))
				return nil
			}
			if quicHeaderOnly {
				h, err := dissect.ParseQUICLongHeader(raw)
				if err != nil {
					return err
				}
				dissect.FormatQUICLongHeader(os.Stdout, h)
				return nil
			}

			class := dissect.DetectQUICPacketClass(raw)
			// Fixture name hints when class is ambiguous
			if quicFix == "quic_vn" {
				class = "version_negotiation"
			}
			if quicFix == "quic_retry" {
				class = "retry"
			}

			switch class {
			case "version_negotiation":
				vn, err := dissect.ParseVersionNegotiation(raw)
				if err != nil {
					return err
				}
				dissect.FormatVersionNegotiation(os.Stdout, vn)
				return nil
			case "retry":
				var odcid []byte
				if quicODCIDHex != "" {
					odcid, err = decodeHex(quicODCIDHex)
					if err != nil {
						return err
					}
				} else if quicFix == "quic_retry" {
					odcid = dissect.ODCIDFromChromeLikeInitial()
				}
				r, err := dissect.ParseRetry(raw, odcid)
				if err != nil {
					return err
				}
				dissect.FormatRetry(os.Stdout, r)
				return nil
			case "initial":
				d, err := dissect.DecryptInitialCapture(raw)
				if err != nil {
					return err
				}
				dissect.FormatQUICInitial(os.Stdout, d)
				return nil
			default:
				h, err := dissect.ParseQUICLongHeader(raw)
				if err != nil {
					return fmt.Errorf("quic: unsupported class %s: %w", class, err)
				}
				fmt.Fprintf(os.Stderr, "class=%s Ã¢â‚¬â€ showing header only\n", class)
				dissect.FormatQUICLongHeader(os.Stdout, h)
				return nil
			}
		},
	}
	quicCmd.Flags().StringVar(&quicHex, "hex", "", "QUIC UDP payload as hex")
	quicCmd.Flags().StringVar(&quicBin, "bin", "", "path to QUIC UDP payload / TP blob")
	quicCmd.Flags().StringVar(&quicFix, "fixture", "", "bundled fixture (quic_initial_chrome | quic_initial_crafted | quic_vn | quic_retry | quic_tp_minimal)")
	quicCmd.Flags().BoolVar(&quicHeaderOnly, "header-only", false, "parse long header without decrypt")
	quicCmd.Flags().BoolVar(&quicTPOnly, "tp", false, "treat input as raw transport_parameters blob")
	quicCmd.Flags().StringVar(&quicODCIDHex, "odcid", "", "original DCID hex for Retry integrity check")

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
			fmt.Fprintln(os.Stdout, "Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â HPACK header block Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â")
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
		qpackDemo string
		qpackHex  string
		qpackBin  string
		qpackFix  string
	)
	qpackCmd := &cobra.Command{
		Use:   "qpack",
		Short: "Decode QPACK Encoded Field Sections (HTTP/3 HEADERS)",
		Long: `Lab 12 Ã¢â‚¬â€ first-principles QPACK field-section decode (RFC 9204).

Focuses on Required Insert Count = 0 (static table + literals), matching
Chromium builds that advertise QPACK_MAX_TABLE_CAPACITY=0. Dynamic-table
references (RIC>0) are rejected with an explicit boundary error.

Static table indices differ from HPACK Ã¢â‚¬â€ :method GET is QPACK 17, not HPACK 2.`,
		Example: `  coherencelab lab qpack --demo chrome
  coherencelab lab qpack --fixture qpack_chrome
  coherencelab lab qpack --fixture qpack_firefox
  coherencelab lab h3 --fixture h3_chrome`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw []byte
			var err error
			switch {
			case qpackFix != "":
				fx, b, e := dissect.LoadFixtureBytes(qpackFix)
				if e != nil {
					return e
				}
				if fx.Kind != "qpack" && fx.Kind != "h3" {
					return fmt.Errorf("fixture %s is kind %s (want qpack or h3)", fx.Name, fx.Kind)
				}
				fmt.Fprintf(os.Stderr, "fixture %s (%s): %s\n", fx.Name, fx.Source, fx.Notes)
				if fx.Kind == "h3" {
					sess, e := dissect.ParseH3(b)
					if e != nil {
						return e
					}
					if sess.QPACK == nil {
						return fmt.Errorf("h3 fixture has no decodable HEADERS")
					}
					dissect.FormatQPACK(os.Stdout, sess.QPACK)
					return nil
				}
				raw = b
			case qpackDemo != "":
				raw, err = dissect.EncodeQPACKPseudoBlock(qpackDemo, sni)
			case qpackBin != "":
				raw, err = os.ReadFile(qpackBin)
			case qpackHex != "":
				raw, err = decodeHex(qpackHex)
			default:
				return fmt.Errorf("provide --demo, --fixture, --hex, or --bin")
			}
			if err != nil {
				return err
			}
			sec, err := dissect.DecodeQPACKFieldSection(raw)
			if err != nil {
				return err
			}
			dissect.FormatQPACK(os.Stdout, sec)
			return nil
		},
	}
	qpackCmd.Flags().StringVar(&qpackDemo, "demo", "", "emit chrome|firefox|safari pseudo order")
	qpackCmd.Flags().StringVar(&qpackHex, "hex", "", "QPACK field section as hex")
	qpackCmd.Flags().StringVar(&qpackBin, "bin", "", "path to QPACK field section bytes")
	qpackCmd.Flags().StringVar(&qpackFix, "fixture", "", "bundled testdata/corpus name (e.g. qpack_chrome)")
	qpackCmd.Flags().StringVar(&sni, "sni", "example.com", "authority used with --demo")

	var (
		corpusBin  string
		corpusHex  string
		corpusFix  string
		corpusUTLS string
	)
	corpusCmd := &cobra.Command{
		Use:   "corpus",
		Short: "Diff a captured ClientHello against a uTLS parrot (ground truth vs claim)",
		Example: `  coherencelab lab corpus --fixture chrome_131 --utls chrome_131
  coherencelab lab corpus --fixture chrome_131 --utls firefox_133
  coherencelab lab corpus --bin chrome-capture.bin --utls chrome_131`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var raw []byte
			var err error
			defaultUTLS := corpusUTLS
			switch {
			case corpusFix != "":
				fx, b, e := dissect.LoadFixtureBytes(corpusFix)
				if e != nil {
					return e
				}
				if fx.Kind != "clienthello" {
					return fmt.Errorf("fixture %s is kind %s (want clienthello)", fx.Name, fx.Kind)
				}
				fmt.Fprintf(os.Stderr, "fixture %s (%s): %s\n", fx.Name, fx.Source, fx.Notes)
				raw = b
				if defaultUTLS == "" {
					defaultUTLS = fx.UTLSClientID
				}
			case corpusBin != "":
				raw, err = os.ReadFile(corpusBin)
			case corpusHex != "":
				raw, err = decodeHex(corpusHex)
			default:
				return fmt.Errorf("provide --fixture, --bin, or --hex capture")
			}
			if err != nil {
				return err
			}
			if defaultUTLS == "" {
				return fmt.Errorf("--utls required when not using a clienthello fixture with a default id")
			}
			diff, _, _, err := dissect.DiffCapturedVsUTLS(raw, defaultUTLS, sni)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "parrot utls=%s sni=%s\n", defaultUTLS, sni)
			dissect.FormatHelloDiff(os.Stdout, diff)
			return nil
		},
	}
	corpusCmd.Flags().StringVar(&corpusBin, "bin", "", "captured ClientHello bytes")
	corpusCmd.Flags().StringVar(&corpusHex, "hex", "", "captured ClientHello as hex")
	corpusCmd.Flags().StringVar(&corpusFix, "fixture", "", "bundled testdata/corpus name (e.g. chrome_131)")
	corpusCmd.Flags().StringVar(&corpusUTLS, "utls", "", "uTLS parrot id (default: fixture's id)")
	corpusCmd.Flags().StringVar(&sni, "sni", "example.com", "SNI for parrot synthesis")

	var (
		goldenQUICRef string
		goldenQUICVs  string
		goldenH3Ref   string
		goldenH3Vs    string
		goldenCross   bool
	)
	goldenCmd := &cobra.Command{
		Use:   "golden",
		Short: "Diff QUIC/H3 golden fingerprints (chrome-like vs naive) + cross-layer coherence",
		Long: `Lab 11 — lock live Chrome/Firefox QUIC TP and H3 fingerprints, then score a naive
stack against them. Default run compares bundled fixtures to minimal ones and
prints Chromium + Firefox cross-layer reports plus a Chromium-vs-Firefox family contrast.`,
		Example: `  coherencelab lab golden
  coherencelab lab golden --quic quic_initial_chrome --vs quic_tp_minimal
  coherencelab lab golden --quic quic_initial_crafted --vs quic_tp_minimal
  coherencelab lab golden --h3 h3_chrome --vs-h3 h3_minimal
  coherencelab lab golden --h3 h3_firefox --vs-h3 h3_chrome
  coherencelab lab golden --cross`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ran := false
			quicRef := goldenQUICRef
			quicVs := goldenQUICVs
			h3Ref := goldenH3Ref
			h3Vs := goldenH3Vs
			doCross := goldenCross
			if !doCross && quicRef == "" && h3Ref == "" {
				quicRef, quicVs = "quic_initial_chrome", "quic_tp_minimal"
				h3Ref, h3Vs = "h3_chrome", "h3_minimal"
				doCross = true
			}
			if quicRef != "" {
				if quicVs == "" {
					return fmt.Errorf("--vs required with --quic")
				}
				refTP, notes, err := dissect.LoadTransportParamsForGolden(quicRef)
				if err != nil {
					return err
				}
				othTP, _, err := dissect.LoadTransportParamsForGolden(quicVs)
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "quic ref=%s vs=%s (%s)\n", quicRef, quicVs, notes)
				dissect.FormatGoldenDiff(os.Stdout, dissect.DiffTransportParameters(refTP, othTP))
				ran = true
			}
			if h3Ref != "" {
				if h3Vs == "" {
					return fmt.Errorf("--vs-h3 required with --h3")
				}
				_, rawA, err := dissect.LoadFixtureBytes(h3Ref)
				if err != nil {
					return err
				}
				_, rawB, err := dissect.LoadFixtureBytes(h3Vs)
				if err != nil {
					return err
				}
				a, err := dissect.ParseH3(rawA)
				if err != nil {
					return err
				}
				b, err := dissect.ParseH3(rawB)
				if err != nil {
					return err
				}
				if ran {
					fmt.Fprintln(os.Stdout)
				}
				fmt.Fprintf(os.Stderr, "h3 ref=%s vs=%s\n", h3Ref, h3Vs)
				dissect.FormatGoldenDiff(os.Stdout, dissect.DiffH3Sessions(a, b))
				ran = true
			}
			if doCross {
				r, err := dissect.AnalyzeChromeFamilyCrossLayer()
				if err != nil {
					return err
				}
				if ran {
					fmt.Fprintln(os.Stdout)
				}
				fmt.Fprintln(os.Stderr, "cross-layer: live Chrome H2/H3/QUIC")
				dissect.FormatCrossLayer(os.Stdout, r)

				ff, err := dissect.AnalyzeFirefoxFamilyCrossLayer()
				if err != nil {
					return err
				}
				fmt.Fprintln(os.Stdout)
				fmt.Fprintln(os.Stderr, "cross-layer: live Firefox H2/H3/QUIC")
				dissect.FormatCrossLayer(os.Stdout, ff)

				fam, err := dissect.AnalyzeChromiumVsFirefox()
				if err != nil {
					return err
				}
				fmt.Fprintln(os.Stdout)
				fmt.Fprintln(os.Stderr, "family contrast: Chromium vs Firefox")
				dissect.FormatFamilyContrast(os.Stdout, fam)

				teach, err := dissect.AnalyzeTeachingChromeFamilyCrossLayer()
				if err != nil {
					return err
				}
				fmt.Fprintln(os.Stdout)
				fmt.Fprintln(os.Stderr, "cross-layer: teaching fixtures (h2_continuation + quic_initial_crafted)")
				dissect.FormatCrossLayer(os.Stdout, teach)
				ran = true
			}
			if !ran {
				return fmt.Errorf("provide --quic/--vs, --h3/--vs-h3, and/or --cross (or no flags for full default)")
			}
			return nil
		},
	}
	goldenCmd.Flags().StringVar(&goldenQUICRef, "quic", "", "QUIC Initial or TP fixture (ref)")
	goldenCmd.Flags().StringVar(&goldenQUICVs, "vs", "", "QUIC Initial or TP fixture to compare")
	goldenCmd.Flags().StringVar(&goldenH3Ref, "h3", "", "HTTP/3 fixture (ref)")
	goldenCmd.Flags().StringVar(&goldenH3Vs, "vs-h3", "", "HTTP/3 fixture to compare")
	goldenCmd.Flags().BoolVar(&goldenCross, "cross", false, "H2/H3/QUIC Chrome + Firefox coherence + family contrast")

	listCmd := &cobra.Command{
		Use:   "fixtures",
		Short: "List bundled testdata/corpus samples",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("%-18s %-12s %-28s %s\n", "NAME", "KIND", "SOURCE", "NOTES")
			for _, f := range dissect.Catalog {
				fmt.Printf("%-18s %-12s %-28s %s\n", f.Name, f.Kind, f.Source, f.Notes)
			}
			fmt.Println("\nExamples:")
			fmt.Println("  coherencelab lab clienthello --fixture chrome_131")
			fmt.Println("  coherencelab lab corpus --fixture chrome_131 --utls chrome_131")
			fmt.Println("  coherencelab lab h2 --fixture h2_chrome")
			fmt.Println("  coherencelab lab h2 --fixture h2_continuation")
			fmt.Println("  coherencelab lab h3 --fixture h3_chrome")
			fmt.Println("  coherencelab lab qpack --fixture qpack_chrome")
			fmt.Println("  coherencelab lab quic --fixture quic_initial_chrome")
			fmt.Println("  coherencelab lab quic --fixture quic_initial_crafted")
			fmt.Println("  coherencelab lab quic --fixture quic_vn")
			fmt.Println("  coherencelab lab quic --fixture quic_retry")
			fmt.Println("  coherencelab lab golden")
			fmt.Println("  coherencelab lab ingest-hello --bin captured/x.clienthello.bin --name chrome_131")
			return nil
		},
	}

	var (
		ingestBin  string
		ingestName string
	)
	ingestCmd := &cobra.Command{
		Use:   "ingest-hello",
		Short: "Copy a captured ClientHello record into testdata/corpus",
		Long: `Writes raw TLS ClientHello bytes into the corpus directory.

After ingesting a live browser capture as chrome_131, update fixtures.go
Source/Notes to live-browser if you change the catalog entry. gen_corpus
never overwrites clienthello-chrome_131.bin (live); it only regenerates
chrome_131_utls.`,
		Example: `  coherencelab lab ingest-hello --bin ./captured/probe.clienthello.bin --name chrome_131
  coherencelab lab clienthello --fixture chrome_131
  coherencelab lab corpus --fixture chrome_131 --utls chrome_131`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if ingestBin == "" || ingestName == "" {
				return fmt.Errorf("--bin and --name required")
			}
			raw, err := os.ReadFile(ingestBin)
			if err != nil {
				return err
			}
			fx, err := dissect.LookupFixture(ingestName)
			basename := ""
			if err == nil && fx.Kind == "clienthello" {
				basename = fx.File
			} else {
				basename = "clienthello-" + ingestName + ".bin"
			}
			path, err := dissect.IngestClientHello(basename, raw)
			if err != nil {
				return err
			}
			fmt.Printf("wrote %s (%d bytes)\n", path, len(raw))
			if fx != nil {
				fmt.Printf("catalog: %s source=%s Ã¢â‚¬â€ %s\n", fx.Name, fx.Source, fx.Notes)
			} else {
				fmt.Println("note: name not in Catalog yet Ã¢â‚¬â€ add an entry in internal/dissect/fixtures.go")
			}
			ch, err := dissect.ParseClientHello(raw)
			if err != nil {
				return fmt.Errorf("wrote file but parse failed: %w", err)
			}
			fmt.Printf("parsed OK: SNI=%q extensions=%d JA3=%s\n", ch.SNI, len(ch.Extensions), ch.JA3Hash())
			return nil
		},
	}
	ingestCmd.Flags().StringVar(&ingestBin, "bin", "", "path to captured ClientHello TLS record")
	ingestCmd.Flags().StringVar(&ingestName, "name", "", "catalog name (e.g. chrome_131) or new basename stem")

	cmd.AddCommand(tlsCmd)
	cmd.AddCommand(h2Cmd)
	cmd.AddCommand(h3Cmd)
	cmd.AddCommand(quicCmd)
	cmd.AddCommand(headersCmd)
	cmd.AddCommand(qpackCmd)
	cmd.AddCommand(permCmd)
	cmd.AddCommand(corpusCmd)
	cmd.AddCommand(goldenCmd)
	cmd.AddCommand(listCmd)
	cmd.AddCommand(ingestCmd)
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
			fmt.Println("coherencelab v1.9.8")
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
