package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/coherencelab/coherencelab/internal/profile"
	"github.com/coherencelab/coherencelab/internal/signal"
)

// Input is a captured session for profile generation.
type Input struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Browser  string            `json:"browser"`
	Platform string            `json:"platform"`
	Version  string            `json:"version"`
	Snapshot signal.Snapshot   `json:"snapshot"`
}

// FromJSONFile loads capture input.
func FromJSONFile(path string) (*Input, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var in Input
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}
	return &in, nil
}

// ToProfile builds a draft CoherenceLab profile from captured signals.
func ToProfile(in *Input) (*profile.Profile, error) {
	if in.ID == "" {
		return nil, fmt.Errorf("capture id required")
	}
	s := in.Snapshot
	p := &profile.Profile{
		ID:       in.ID,
		Name:     in.Name,
		Browser:  defaultStr(in.Browser, "chrome"),
		Version:  defaultStr(in.Version, "131"),
		Platform: defaultStr(in.Platform, "windows"),
		Engine:   "blink",
		Description: "Auto-captured profile — review and refine before production use.",
		UserAgent: profile.UserAgentSpec{
			Value:     s.UserAgent,
			Pattern:   guessPattern(s.UserAgent),
			MatchMode: "contains",
		},
		ClientHints: profile.ClientHintsSpec{
			SecCHUA:         s.SecCHUA,
			SecCHUAMobile:   s.SecCHUAMobile,
			SecCHUAPlatform: s.SecCHUAPlatform,
		},
		Headers: profile.HeaderSpec{
			Order:          s.HeaderOrder,
			Required:       map[string]string{},
			Accept:         s.Accept,
			AcceptEncoding: s.AcceptEncoding,
		},
		AcceptLanguage: profile.AcceptLanguageSpec{
			Pattern: s.AcceptLanguage,
			Primary: primaryLocale(s.AcceptLanguage),
		},
		TLS: profile.TLSSpec{
			MinVersion:   "TLS 1.2",
			MaxVersion:   "TLS 1.3",
			ALPN:         []string{"h2", "http/1.1"},
			UTLSClientID: guessUTLS(in.Browser),
		},
		HTTP2: profile.HTTP2Spec{
			HeaderTableSize:   65536,
			EnablePush:        0,
			MaxConcurrent:     1000,
			InitialWindowSize: 6291456,
			MaxFrameSize:      16384,
			MaxHeaderListSize: 262144,
		},
	}
	if s.H2 != nil {
		p.HTTP2 = profile.HTTP2Spec{
			HeaderTableSize:   s.H2.HeaderTableSize,
			EnablePush:        s.H2.EnablePush,
			MaxConcurrent:     s.H2.MaxConcurrent,
			InitialWindowSize: s.H2.InitialWindowSize,
			MaxFrameSize:      s.H2.MaxFrameSize,
			MaxHeaderListSize: s.H2.MaxHeaderListSize,
		}
	}
	if s.TLS != nil && s.TLS.UTLSClientID != "" {
		p.TLS.UTLSClientID = s.TLS.UTLSClientID
	}
	if s.JS != nil {
		p.JSRuntime = jsToProfile(s.JS)
	}
	for k, v := range s.Headers {
		switch strings.ToLower(k) {
		case "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest":
			p.Headers.Required[canonicalHeader(k)] = v
		}
	}
	if p.Name == "" {
		p.Name = in.ID
	}
	return p, p.Validate()
}

// WriteYAML writes profile to path.
func WriteYAML(path string, p *profile.Profile) error {
	data, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func defaultStr(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

func guessPattern(ua string) string {
	for _, part := range []string{"Edg/", "Chrome/", "Firefox/", "Version/"} {
		if idx := strings.Index(ua, part); idx >= 0 {
			end := strings.IndexAny(ua[idx:], " ;")
			if end > 0 {
				return ua[idx : idx+end]
			}
		}
	}
	return ua
}

func primaryLocale(al string) string {
	if al == "" {
		return "en-US"
	}
	primary := strings.Split(strings.Split(al, ",")[0], ";")[0]
	return strings.TrimSpace(primary)
}

func guessUTLS(browser string) string {
	switch strings.ToLower(browser) {
	case "firefox":
		return "firefox_133"
	case "safari":
		return "safari_18"
	case "edge":
		return "edge_106"
	default:
		return "chrome_131"
	}
}

func canonicalHeader(k string) string {
	parts := strings.Split(strings.ToLower(k), "-")
	for i, p := range parts {
		if len(p) == 0 {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "-")
}

func jsToProfile(js *signal.JSObservation) *profile.JSRuntimeSpec {
	if js == nil {
		return nil
	}
	out := &profile.JSRuntimeSpec{}
	if n := js.Navigator; n != nil {
		out.Navigator = &profile.NavigatorSpec{
			Platform:            n.Platform,
			UserAgent:           n.UserAgent,
			Vendor:              n.Vendor,
			Language:            n.Language,
			Languages:           append([]string(nil), n.Languages...),
			HardwareConcurrency: n.HardwareConcurrency,
			DeviceMemory:        n.DeviceMemory,
			MaxTouchPoints:      n.MaxTouchPoints,
			Webdriver:           n.Webdriver,
		}
	}
	if w := js.WebGL; w != nil {
		out.WebGL = &profile.WebGLSpec{
			Vendor:    w.Vendor,
			Renderer:  w.Renderer,
			MatchMode: "contains",
		}
	}
	return out
}
