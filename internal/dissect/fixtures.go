package dissect

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Fixture describes a checked-in corpus sample under testdata/corpus.
type Fixture struct {
	Name        string // e.g. chrome_131
	Kind        string // clienthello | h2 | h3 | quic | quic_tp
	File        string // basename
	UTLSClientID string // for ClientHello fixtures / corpus parrot default
	Source      string // how it was produced
	Notes       string
}

// Catalog is the honest inventory of bundled fixtures.
// ClientHello sources are labeled: live-browser (real Chrome via probe) or
// utls-synth (impersonator output). gen_corpus never overwrites live bins.
var Catalog = []Fixture{
	{Name: "chrome_131", Kind: "clienthello", File: "clienthello-chrome_131.bin", UTLSClientID: "chrome_131",
		Source: "live-browser", Notes: "Real Google Chrome ClientHello via coherencelab serve (Windows); SNI=example.com"},
	{Name: "edge_live", Kind: "clienthello", File: "clienthello-edge_live.bin", UTLSClientID: "chrome_131",
		Source: "live-browser", Notes: "Real Microsoft Edge ClientHello via coherencelab serve (Windows); SNI=example.com; parrot baseline chrome_131"},
	{Name: "firefox_live", Kind: "clienthello", File: "clienthello-firefox_live.bin", UTLSClientID: "firefox_133",
		Source: "live-browser", Notes: "Real Mozilla Firefox 156 ClientHello via coherencelab serve (Windows); SNI=example.com via network.dns.localDomains; parrot baseline firefox_133"},
	{Name: "chrome_131_utls", Kind: "clienthello", File: "clienthello-chrome_131_utls.bin", UTLSClientID: "chrome_131",
		Source: "utls-synth", Notes: "uTLS HelloChrome_131 via SynthClientHello; parrot baseline for Lab 06"},
	{Name: "firefox_133", Kind: "clienthello", File: "clienthello-firefox_133.bin", UTLSClientID: "firefox_133",
		Source: "utls-synth", Notes: "uTLS Firefox Auto parrot; SNI=example.com — compare with firefox_live for Lab 06"},
	{Name: "safari_18", Kind: "clienthello", File: "clienthello-safari_18.bin", UTLSClientID: "safari_18",
		Source: "utls-synth", Notes: "uTLS Safari Auto parrot; SNI=example.com (live Safari needs macOS/iOS)"},
	{Name: "safari_ios", Kind: "clienthello", File: "clienthello-safari_ios.bin", UTLSClientID: "ios_14",
		Source: "utls-synth", Notes: "uTLS iOS Auto parrot; SNI=example.com (live Safari needs macOS/iOS)"},
	{Name: "h2_chrome", Kind: "h2", File: "h2-chrome-live.bin",
		Source: "live-browser", Notes: "Real Chrome H2 request flight (SETTINGS+WINDOW_UPDATE+HEADERS); Priority HTTP header u=0,i; Akamai …|hdr:u=0,i|m,a,s,p"},
	{Name: "h2_edge", Kind: "h2", File: "h2-edge-live.bin",
		Source: "live-browser", Notes: "Real Edge H2 request flight; Priority HTTP header u=0,i; same Chromium Akamai shape as Chrome"},
	{Name: "h2_continuation", Kind: "h2", File: "h2-chrome-like.bin",
		Source: "crafted", Notes: "Teaching fixture: SETTINGS(+NO_RFC7540)+WINDOW_UPDATE+PRIORITY_UPDATE+HEADERS/CONTINUATION m,a,s,p (Lab 05/07)"},
	{Name: "h2_firefox", Kind: "h2", File: "h2-firefox-live.bin",
		Source: "live-browser", Notes: "Real Firefox H2 request flight; Priority HTTP header u=0,i; Akamai …|hdr:u=0,i|m,p,a,s"},
	{Name: "h2_firefox_crafted", Kind: "h2", File: "h2-firefox-like.bin",
		Source: "crafted", Notes: "Firefox-like SETTINGS+HEADERS m,p,a,s teaching fixture (Lab 03 contrast)"},
	{Name: "h3_chrome", Kind: "h3", File: "h3-chrome-live.bin",
		Source: "live-browser", Notes: "Real Chrome H3 control stream via serve HTTP/3 (Windows); SETTINGS+GREASE+PRIORITY_UPDATE"},
	{Name: "h3_edge", Kind: "h3", File: "h3-edge-live.bin",
		Source: "live-browser", Notes: "Real Edge H3 control stream via serve HTTP/3 (Windows); SETTINGS+GREASE+PRIORITY_UPDATE"},
	{Name: "h3_firefox", Kind: "h3", File: "h3-firefox-live.bin",
		Source: "live-browser", Notes: "Real Firefox H3 control stream via serve HTTP/3 (Windows); SETTINGS(+Mozilla ids)+GREASE frame; no PRIORITY_UPDATE on first control flight — needs disable_when_third_party_roots_found=false for local CA"},
	{Name: "h3_chrome_crafted", Kind: "h3", File: "h3-chrome-like.bin",
		Source: "crafted", Notes: "Teaching H3 SETTINGS(+GREASE)+GREASE frame+PRIORITY_UPDATE+QPACK HEADERS"},
	{Name: "h3_minimal", Kind: "h3", File: "h3-minimal.bin",
		Source: "crafted", Notes: "H3 SETTINGS only — naive stack contrast for Lab 11"},
	{Name: "qpack_chrome", Kind: "qpack", File: "qpack-chrome.bin",
		Source: "crafted", Notes: "QPACK RIC=0 field section — Chromium pseudo order m,a,s,p"},
	{Name: "qpack_firefox", Kind: "qpack", File: "qpack-firefox.bin",
		Source: "crafted", Notes: "QPACK RIC=0 field section — Firefox pseudo order m,p,a,s"},
	{Name: "qpack_safari", Kind: "qpack", File: "qpack-safari.bin",
		Source: "crafted", Notes: "QPACK RIC=0 field section — Safari pseudo order m,s,p,a"},
	{Name: "quic_initial_chrome", Kind: "quic", File: "quic-initial-chrome-live.bin",
		Source: "live-browser", Notes: "Real Chrome QUICv1 Initial via serve UDP capture + Alt-Svc (Windows); decryptable CRYPTO+TPs+GREASE"},
	{Name: "quic_initial_edge", Kind: "quic", File: "quic-initial-edge-live.bin",
		Source: "live-browser", Notes: "Real Edge QUICv1 Initial via serve UDP capture (Windows); Chromium-family TP order differs from Chrome"},
	{Name: "quic_initial_firefox", Kind: "quic", File: "quic-initial-firefox-live.bin",
		Source: "live-browser", Notes: "Real Firefox QUICv1 Initial flight (CLQI multi-datagram when CRYPTO is fragmented)"},
	{Name: "quic_initial_crafted", Kind: "quic", File: "quic-initial-chrome-like.bin",
		Source: "crafted", Notes: "Crafted QUICv1 Initial with grease_quic_bit — Lab 09 teaching / ODCID for Retry"},
	{Name: "quic_tp_minimal", Kind: "quic_tp", File: "quic-tp-minimal.bin",
		Source: "crafted", Notes: "Raw transport_parameters blob without GREASE (naive stack)"},
	{Name: "quic_vn", Kind: "quic", File: "quic-vn-grease.bin",
		Source: "crafted", Notes: "Version Negotiation (version=0) advertising QUICv1 + GREASE versions"},
	{Name: "quic_retry", Kind: "quic", File: "quic-retry.bin",
		Source: "crafted", Notes: "QUICv1 Retry with valid integrity tag (ODCID from crafted Initial)"},
}

// CorpusDir resolves testdata/corpus relative to this package or cwd.
func CorpusDir() (string, error) {
	candidates := []string{
		filepath.Join("testdata", "corpus"),
		filepath.Join("..", "..", "testdata", "corpus"),
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		candidates = append([]string{filepath.Join(filepath.Dir(file), "..", "..", "testdata", "corpus")}, candidates...)
	}
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if st, err := os.Stat(abs); err == nil && st.IsDir() {
			return abs, nil
		}
	}
	return "", fmt.Errorf("testdata/corpus not found (run from repo root or go test ./internal/dissect)")
}

// LookupFixture finds a catalog entry by name (case-insensitive).
func LookupFixture(name string) (*Fixture, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	for i := range Catalog {
		if strings.ToLower(Catalog[i].Name) == n {
			return &Catalog[i], nil
		}
	}
	var names []string
	for _, f := range Catalog {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	return nil, fmt.Errorf("unknown fixture %q (want one of: %s)", name, strings.Join(names, ", "))
}

// LoadFixtureBytes reads a named fixture from testdata/corpus.
func LoadFixtureBytes(name string) (*Fixture, []byte, error) {
	fx, err := LookupFixture(name)
	if err != nil {
		return nil, nil, err
	}
	dir, err := CorpusDir()
	if err != nil {
		return nil, nil, err
	}
	path := filepath.Join(dir, fx.File)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w (regenerate with go run ./tools/gen_corpus.go)", path, err)
	}
	return fx, b, nil
}

// ListFixtures returns catalog names for CLI help.
func ListFixtures(kind string) []Fixture {
	var out []Fixture
	for _, f := range Catalog {
		if kind == "" || f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}
