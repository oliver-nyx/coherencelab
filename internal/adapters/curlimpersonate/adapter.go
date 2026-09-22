// Package curlimpersonate adapts curl-impersonate session exports for CoherenceLab.
package curlimpersonate

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/coherencelab/coherencelab/internal/signal"
)

// Export represents a curl-impersonate or curl_cffi export.
type Export struct {
	Impersonate string            `json:"impersonate"`
	Browser     string            `json:"browser"`
	UserAgent   string            `json:"user_agent"`
	Headers     map[string]string `json:"headers"`
	HeaderOrder []string          `json:"header_order"`
	JA3         string            `json:"ja3"`
	ALPN        string            `json:"alpn"`
}

// PresetMap maps curl-impersonate targets to CoherenceLab profile IDs.
var PresetMap = map[string]string{
	"chrome131":        "chrome-131-win",
	"chrome131windows": "chrome-131-win",
	"chrome131macos":   "chrome-131-mac",
	"chrome131linux":   "chrome-131-linux",
	"chrome120":        "chrome-120-win",
	"chrome120windows": "chrome-120-win",
	"firefox133":       "firefox-133-win",
	"firefox133windows": "firefox-133-win",
	"safari18":         "safari-18-mac",
	"safari18ios":      "safari-18-ios",
	"safari15_5":       "safari-18-mac",
	"edge131":          "edge-131-win",
	"edge101":          "edge-131-win",
}

// LoadExport reads a JSON export file.
func LoadExport(path string) (*Export, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read export: %w", err)
	}
	var e Export
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("parse export: %w", err)
	}
	if e.UserAgent == "" && len(e.Headers) == 0 {
		return nil, fmt.Errorf("export missing user_agent and headers")
	}
	return &e, nil
}

// ResolveProfileID maps impersonate target to profile ID.
func ResolveProfileID(e *Export) (string, error) {
	for _, c := range []string{e.Impersonate, e.Browser} {
		if c == "" {
			continue
		}
		key := normalizeKey(c)
		if id, ok := PresetMap[key]; ok {
			return id, nil
		}
	}
	return "", fmt.Errorf("unknown curl-impersonate target: impersonate=%q browser=%q", e.Impersonate, e.Browser)
}

// ToSnapshot converts export to signal snapshot.
func ToSnapshot(e *Export) *signal.Snapshot {
	headers := make(map[string]string, len(e.Headers))
	for k, v := range e.Headers {
		headers[strings.ToLower(k)] = v
	}
	ua := e.UserAgent
	if ua == "" {
		ua = headers["user-agent"]
	}
	return &signal.Snapshot{
		UserAgent:       ua,
		Headers:         headers,
		HeaderOrder:     e.HeaderOrder,
		SecCHUA:         headers["sec-ch-ua"],
		SecCHUAMobile:   headers["sec-ch-ua-mobile"],
		SecCHUAPlatform: headers["sec-ch-ua-platform"],
		AcceptLanguage:  headers["accept-language"],
		Accept:          headers["accept"],
		AcceptEncoding:  headers["accept-encoding"],
		TLS: &signal.TLSObservation{
			JA3:  e.JA3,
			ALPN: e.ALPN,
		},
	}
}

// LoadSnapshot loads export and returns snapshot (no profile required).
func LoadSnapshot(path string) (*signal.Snapshot, string, error) {
	e, err := LoadExport(path)
	if err != nil {
		return nil, "", err
	}
	id, _ := ResolveProfileID(e)
	return ToSnapshot(e), id, nil
}

func normalizeKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}
