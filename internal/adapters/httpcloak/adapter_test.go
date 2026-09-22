package httpcloak

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveProfileID(t *testing.T) {
	id, err := ResolveProfileID(&Export{Browser: "chrome131"})
	if err != nil || id != "chrome-131-win" {
		t.Fatalf("got %q err=%v", id, err)
	}
}

func TestLoadExportAndSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "export.json")
	content := `{
		"browser": "firefox133",
		"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"headers": {"accept-language": "en-US,en;q=0.5"},
		"tls": {"utls_client_id": "firefox_133", "alpn": "h2"}
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	e, err := LoadExport(path)
	if err != nil {
		t.Fatal(err)
	}
	snap := ToSnapshot(e, "firefox-133-win")
	if !strings.Contains(snap.UserAgent, "Firefox/133") {
		t.Fatalf("unexpected ua: %s", snap.UserAgent)
	}
}
