package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadChromeProfile(t *testing.T) {
	path := filepath.Join("..", "..", "profiles", "chrome-131-win.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skip("profiles not found")
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "chrome-131-win" {
		t.Fatalf("got id %q", p.ID)
	}
	if p.TLS.UTLSClientID == "" {
		t.Fatal("missing utls client id")
	}
}

func TestLoadDir(t *testing.T) {
	dir := filepath.Join("..", "..", "profiles")
	if _, err := os.Stat(dir); err != nil {
		t.Skip("profiles not found")
	}
	profiles, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) < 12 {
		t.Fatalf("expected at least 12 profiles, got %d", len(profiles))
	}
}

func TestValidateMissingID(t *testing.T) {
	p := &Profile{Name: "x", UserAgent: UserAgentSpec{Pattern: "ua"}, TLS: TLSSpec{UTLSClientID: "chrome_131"}}
	if err := p.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}
