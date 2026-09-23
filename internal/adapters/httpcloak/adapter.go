// Package httpcloak adapts external HTTP client exports for CoherenceLab scans.
package httpcloak

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/oliver-nyx/coherencelab/internal/profile"
	"github.com/oliver-nyx/coherencelab/internal/signal"
)

// Export is a portable session export from HTTP clients like httpcloak.
type Export struct {
	Browser     string            `json:"browser"`
	Profile     string            `json:"profile"`
	UserAgent   string            `json:"user_agent"`
	Headers     map[string]string `json:"headers"`
	HeaderOrder []string          `json:"header_order"`
	TLS         *TLSExport        `json:"tls,omitempty"`
}

// TLSExport holds TLS metadata from the client.
type TLSExport struct {
	JA3          string `json:"ja3"`
	JA4          string `json:"ja4"`
	ALPN         string `json:"alpn"`
	Version      string `json:"version"`
	UTLSClientID string `json:"utls_client_id"`
}

// PresetMap maps httpcloak-style browser presets to CoherenceLab profile IDs.
var PresetMap = map[string]string{
	"chrome131":      "chrome-131-win",
	"chrome-131":     "chrome-131-win",
	"chrome131win":   "chrome-131-win",
	"chrome131mac":   "chrome-131-mac",
	"chrome131linux": "chrome-131-linux",
	"chrome131android": "chrome-131-android",
	"chrome120":      "chrome-120-win",
	"firefox133":     "firefox-133-win",
	"firefox133mac":  "firefox-133-mac",
	"firefox133linux": "firefox-133-linux",
	"safari18":       "safari-18-mac",
	"safariios18":    "safari-18-ios",
	"edge131":        "edge-131-win",
	"edge131mac":     "edge-131-mac",
}

// ResolveProfileID maps an export to a CoherenceLab profile ID.
func ResolveProfileID(e *Export) (string, error) {
	for _, candidate := range []string{e.Profile, e.Browser} {
		if candidate == "" {
			continue
		}
		key := normalizeKey(candidate)
		if id, ok := PresetMap[key]; ok {
			return id, nil
		}
	}
	return "", fmt.Errorf("unknown httpcloak preset: browser=%q profile=%q", e.Browser, e.Profile)
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

// ToSnapshot converts an export into a CoherenceLab signal snapshot.
func ToSnapshot(e *Export, profileID string) *signal.Snapshot {
	headers := make(map[string]string, len(e.Headers))
	for k, v := range e.Headers {
		headers[strings.ToLower(k)] = v
	}
	ua := e.UserAgent
	if ua == "" {
		ua = headers["user-agent"]
	}
	snap := &signal.Snapshot{
		ProfileID:   profileID,
		UserAgent:   ua,
		Headers:     headers,
		HeaderOrder: e.HeaderOrder,
		SecCHUA:         headers["sec-ch-ua"],
		SecCHUAMobile:   headers["sec-ch-ua-mobile"],
		SecCHUAPlatform: headers["sec-ch-ua-platform"],
		AcceptLanguage:  headers["accept-language"],
		Accept:          headers["accept"],
		AcceptEncoding:  headers["accept-encoding"],
	}
	if e.TLS != nil {
		snap.TLS = &signal.TLSObservation{
			JA3:          e.TLS.JA3,
			JA4:          e.TLS.JA4,
			ALPN:         e.TLS.ALPN,
			Version:      e.TLS.Version,
			UTLSClientID: e.TLS.UTLSClientID,
		}
	}
	return snap
}

// ScanExport loads an export, resolves profile, and returns snapshot + profile.
func ScanExport(path string, profilesDir string, profileOverride string) (*signal.Snapshot, *profile.Profile, error) {
	e, err := LoadExport(path)
	if err != nil {
		return nil, nil, err
	}
	profileID := profileOverride
	if profileID == "" {
		profileID, err = ResolveProfileID(e)
		if err != nil {
			return nil, nil, err
		}
	}
	p, err := profile.FindByID(profilesDir, profileID)
	if err != nil {
		return nil, nil, err
	}
	return ToSnapshot(e, profileID), p, nil
}

func normalizeKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}
