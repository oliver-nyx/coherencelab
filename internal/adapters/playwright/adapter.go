// Package playwright adapts Playwright / patchright session exports for CoherenceLab.
package playwright

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/coherencelab/coherencelab/internal/profile"
	"github.com/coherencelab/coherencelab/internal/signal"
)

// Export represents a Playwright browser context export.
type Export struct {
	Browser    string            `json:"browser"`
	Channel    string            `json:"channel"`
	Profile    string            `json:"profile"`
	UserAgent  string            `json:"user_agent"`
	Locale     string            `json:"locale"`
	Headers    map[string]string `json:"headers"`
	ExtraHTTP  map[string]string `json:"extra_http_headers"`
	HeaderOrder []string         `json:"header_order"`
	Platform   string            `json:"platform"`
}

// PresetMap maps Playwright launch hints to CoherenceLab profile IDs.
var PresetMap = map[string]string{
	"chromewin":      "chrome-131-win",
	"chromemac":      "chrome-131-mac",
	"chromelinux":    "chrome-131-linux",
	"chromeandroid":  "chrome-131-android",
	"firefoxwin":     "firefox-133-win",
	"firefoxmac":     "firefox-133-mac",
	"firefoxlinux":   "firefox-133-linux",
	"webkitmac":      "safari-18-mac",
	"webkitione":     "safari-18-ios",
	"edgewin":        "edge-131-win",
	"edgemac":        "edge-131-mac",
	"chrome":         "chrome-131-win",
	"chromium":       "chrome-131-win",
	"firefox":        "firefox-133-win",
	"webkit":         "safari-18-mac",
	"msedge":         "edge-131-win",
}

// LoadExport reads a Playwright JSON export.
func LoadExport(path string) (*Export, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read export: %w", err)
	}
	var e Export
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("parse export: %w", err)
	}
	if e.UserAgent == "" && len(e.Headers) == 0 && len(e.ExtraHTTP) == 0 {
		return nil, fmt.Errorf("export missing user_agent and headers")
	}
	return &e, nil
}

// ResolveProfileID maps export metadata to a CoherenceLab profile.
func ResolveProfileID(e *Export) (string, error) {
	for _, candidate := range []string{e.Profile, e.Channel, e.Browser, e.Platform} {
		if candidate == "" {
			continue
		}
		if id, ok := PresetMap[normalizeKey(candidate)]; ok {
			return id, nil
		}
	}
	if e.UserAgent != "" {
		if id := inferFromUA(e.UserAgent); id != "" {
			return id, nil
		}
	}
	return "", fmt.Errorf("unknown playwright export: browser=%q channel=%q profile=%q", e.Browser, e.Channel, e.Profile)
}

// ToSnapshot converts export to observed signals.
func ToSnapshot(e *Export, profileID string) *signal.Snapshot {
	headers := mergeHeaders(e.Headers, e.ExtraHTTP)
	ua := e.UserAgent
	if ua == "" {
		ua = headers["user-agent"]
	}
	if e.Locale != "" && headers["accept-language"] == "" {
		headers["accept-language"] = e.Locale + ",en;q=0.9"
	}
	return &signal.Snapshot{
		ProfileID:       profileID,
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
			UTLSClientID: guessUTLS(profileID),
		},
	}
}

// ScanExport loads and prepares a Playwright export for scanning.
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

func mergeHeaders(a, b map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range a {
		out[strings.ToLower(k)] = v
	}
	for k, v := range b {
		out[strings.ToLower(k)] = v
	}
	return out
}

func inferFromUA(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "edg/"):
		if strings.Contains(ua, "mac os x") {
			return "edge-131-mac"
		}
		return "edge-131-win"
	case strings.Contains(ua, "firefox/"):
		if strings.Contains(ua, "mac os x") {
			return "firefox-133-mac"
		}
		if strings.Contains(ua, "linux") {
			return "firefox-133-linux"
		}
		return "firefox-133-win"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "safari-18-ios"
	case strings.Contains(ua, "mac os x") && strings.Contains(ua, "version/") && !strings.Contains(ua, "chrome/"):
		return "safari-18-mac"
	case strings.Contains(ua, "android") && strings.Contains(ua, "mobile"):
		return "chrome-131-android"
	case strings.Contains(ua, "linux"):
		return "chrome-131-linux"
	case strings.Contains(ua, "mac os x"):
		return "chrome-131-mac"
	case strings.Contains(ua, "windows nt"):
		return "chrome-131-win"
	default:
		return ""
	}
}

func guessUTLS(profileID string) string {
	switch {
	case strings.HasPrefix(profileID, "firefox"):
		return "firefox_133"
	case strings.HasPrefix(profileID, "safari"):
		if strings.Contains(profileID, "ios") {
			return "safari_ios_18"
		}
		return "safari_18"
	case strings.HasPrefix(profileID, "edge"):
		return "edge_106"
	default:
		return "chrome_131"
	}
}

func normalizeKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}
