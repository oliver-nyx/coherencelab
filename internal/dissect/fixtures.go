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
	Kind        string // clienthello | h2
	File        string // basename
	UTLSClientID string // for ClientHello fixtures / corpus parrot default
	Source      string // how it was produced
	Notes       string
}

// Catalog is the honest inventory of bundled fixtures.
// All ClientHello binaries are currently uTLS-synthesized (not live browser
// pcaps). Labels say so — replacing them with real captures is encouraged.
var Catalog = []Fixture{
	{Name: "chrome_131", Kind: "clienthello", File: "clienthello-chrome_131.bin", UTLSClientID: "chrome_131",
		Source: "utls-synth", Notes: "uTLS HelloChrome_131 via SynthClientHello; SNI=example.com"},
	{Name: "firefox_133", Kind: "clienthello", File: "clienthello-firefox_133.bin", UTLSClientID: "firefox_133",
		Source: "utls-synth", Notes: "uTLS Firefox Auto parrot; SNI=example.com"},
	{Name: "safari_18", Kind: "clienthello", File: "clienthello-safari_18.bin", UTLSClientID: "safari_18",
		Source: "utls-synth", Notes: "uTLS Safari Auto parrot; SNI=example.com"},
	{Name: "safari_ios", Kind: "clienthello", File: "clienthello-safari_ios.bin", UTLSClientID: "ios_14",
		Source: "utls-synth", Notes: "uTLS iOS Auto parrot; SNI=example.com"},
	{Name: "h2_chrome", Kind: "h2", File: "h2-chrome-like.bin",
		Source: "crafted", Notes: "SETTINGS(+NO_RFC7540_PRIORITIES)+WINDOW_UPDATE+PRIORITY_UPDATE(u=0,i)+HEADERS/CONTINUATION m,a,s,p"},
	{Name: "h2_firefox", Kind: "h2", File: "h2-firefox-like.bin",
		Source: "crafted", Notes: "Preface+Firefox-like SETTINGS+HEADERS with m,p,a,s (no PRIORITY_UPDATE)"},
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
