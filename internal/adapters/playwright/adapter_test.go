package playwright

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coherencelab/coherencelab/internal/signal"
)

func TestResolveFromChannel(t *testing.T) {
	id, err := ResolveProfileID(&Export{Channel: "chrome", Platform: "windows"})
	if err != nil || id != "chrome-131-win" {
		t.Fatalf("got %q err=%v", id, err)
	}
}

func TestInferFromUAFirefoxMac(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0"
	id, err := ResolveProfileID(&Export{UserAgent: ua})
	if err != nil || id != "firefox-133-mac" {
		t.Fatalf("got %q err=%v", id, err)
	}
}

func TestToSnapshotJSRuntime(t *testing.T) {
	wd := true
	e := &Export{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
		JSRuntime: &signal.JSObservation{
			Navigator: &signal.NavigatorObservation{
				Platform:  "Win32",
				Vendor:    "Google Inc.",
				Webdriver: &wd,
			},
		},
	}
	snap := ToSnapshot(e, "chrome-131-win")
	if snap.JS == nil || snap.JS.Navigator == nil {
		t.Fatal("expected js_runtime on snapshot")
	}
	if snap.JS.Source != "export" {
		t.Fatalf("source = %q", snap.JS.Source)
	}
	if snap.JS.Navigator.Webdriver == nil || !*snap.JS.Navigator.Webdriver {
		t.Fatal("expected webdriver true")
	}
}

func TestLoadExport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw.json")
	body := `{
		"browser": "chromium",
		"channel": "chrome",
		"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
		"extra_http_headers": {"sec-ch-ua-platform": "\"Windows\""},
		"locale": "en-US"
	}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	e, err := LoadExport(path)
	if err != nil {
		t.Fatal(err)
	}
	snap := ToSnapshot(e, "chrome-131-win")
	if !strings.Contains(snap.UserAgent, "Chrome/131") {
		t.Fatalf("ua: %s", snap.UserAgent)
	}
}
