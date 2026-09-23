package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestUIProfilesEndpoint(t *testing.T) {
	dir := filepath.Join("..", "..", "profiles")
	srv := New("127.0.0.1:0", dir)
	req := httptest.NewRequest(http.MethodGet, "/api/profiles", nil)
	rr := httptest.NewRecorder()
	srv.handleProfiles(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var list []map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) < 10 {
		t.Fatalf("expected profiles, got %d", len(list))
	}
}

func TestUIIndex(t *testing.T) {
	srv := New("127.0.0.1:0", ".")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	srv.handleIndex(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got == "" {
		t.Fatal("missing content-type")
	}
	if rr.Body.Len() < 100 {
		t.Fatal("empty html")
	}
}

func TestUIScanRejectsLiveMode(t *testing.T) {
	dir := filepath.Join("..", "..", "profiles")
	srv := New("127.0.0.1:0", dir)
	body := `{"profile":"chrome-131-win","mode":"live","probe":"https://example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.handleScan(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for live mode, got %d body=%s", rr.Code, rr.Body.String())
	}
}
