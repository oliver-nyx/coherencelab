package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile describes the expected identity signals for a browser + platform.
type Profile struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Browser     string   `yaml:"browser" json:"browser"`
	Version     string   `yaml:"version" json:"version"`
	Platform    string   `yaml:"platform" json:"platform"`
	Engine      string   `yaml:"engine" json:"engine"`
	Description string   `yaml:"description" json:"description"`
	Tags        []string `yaml:"tags" json:"tags"`

	UserAgent       UserAgentSpec       `yaml:"user_agent" json:"user_agent"`
	ClientHints     ClientHintsSpec     `yaml:"client_hints" json:"client_hints"`
	Headers         HeaderSpec          `yaml:"headers" json:"headers"`
	TLS             TLSSpec             `yaml:"tls" json:"tls"`
	HTTP2           HTTP2Spec           `yaml:"http2" json:"http2"`
	AcceptLanguage  AcceptLanguageSpec  `yaml:"accept_language" json:"accept_language"`
	JSRuntime       *JSRuntimeSpec      `yaml:"js_runtime,omitempty" json:"js_runtime,omitempty"`
}

type UserAgentSpec struct {
	Value       string `yaml:"value" json:"value"`           // full UA sent by clients
	Pattern     string `yaml:"pattern" json:"pattern"`       // validation pattern
	MatchMode   string `yaml:"match_mode" json:"match_mode"` // exact, contains, regex
	Major       int    `yaml:"major" json:"major"`
	FullVersion string `yaml:"full_version" json:"full_version"`
	Platform    string `yaml:"platform" json:"platform"`
	Mobile      bool   `yaml:"mobile" json:"mobile"`
}

type ClientHintsSpec struct {
	SecCHUA           string `yaml:"sec_ch_ua" json:"sec_ch_ua"`
	SecCHUAMobile     string `yaml:"sec_ch_ua_mobile" json:"sec_ch_ua_mobile"`
	SecCHUAPlatform   string `yaml:"sec_ch_ua_platform" json:"sec_ch_ua_platform"`
	SecCHUAArch       string `yaml:"sec_ch_ua_arch,omitempty" json:"sec_ch_ua_arch,omitempty"`
	SecCHUABitness    string `yaml:"sec_ch_ua_bitness,omitempty" json:"sec_ch_ua_bitness,omitempty"`
	SecCHUAFullVersion string `yaml:"sec_ch_ua_full_version,omitempty" json:"sec_ch_ua_full_version,omitempty"`
}

type HeaderSpec struct {
	Order           []string          `yaml:"order" json:"order"`
	Required        map[string]string `yaml:"required" json:"required"`
	Forbidden       []string          `yaml:"forbidden" json:"forbidden"`
	AcceptEncoding  string            `yaml:"accept_encoding" json:"accept_encoding"`
	Accept          string            `yaml:"accept" json:"accept"`
	UpgradeInsecure bool              `yaml:"upgrade_insecure_requests" json:"upgrade_insecure_requests"`
}

type TLSSpec struct {
	MinVersion     string   `yaml:"min_version" json:"min_version"`
	MaxVersion     string   `yaml:"max_version" json:"max_version"`
	ALPN           []string `yaml:"alpn" json:"alpn"`
	CipherSuites   []string `yaml:"cipher_suites,omitempty" json:"cipher_suites,omitempty"`
	JA3Hint        string   `yaml:"ja3_hint,omitempty" json:"ja3_hint,omitempty"`
	JA4Hint        string   `yaml:"ja4_hint,omitempty" json:"ja4_hint,omitempty"`
	UTLSClientID   string   `yaml:"utls_client_id" json:"utls_client_id"`
}

type HTTP2Spec struct {
	HeaderTableSize   uint32 `yaml:"header_table_size" json:"header_table_size"`
	EnablePush        uint32 `yaml:"enable_push" json:"enable_push"`
	MaxConcurrent     uint32 `yaml:"max_concurrent_streams" json:"max_concurrent_streams"`
	InitialWindowSize uint32 `yaml:"initial_window_size" json:"initial_window_size"`
	MaxFrameSize      uint32 `yaml:"max_frame_size" json:"max_frame_size"`
	MaxHeaderListSize uint32 `yaml:"max_header_list_size" json:"max_header_list_size"`
}

type AcceptLanguageSpec struct {
	Pattern string `yaml:"pattern" json:"pattern"`
	Primary string `yaml:"primary" json:"primary"`
}

// JSRuntimeSpec describes expected browser JS environment signals.
type JSRuntimeSpec struct {
	Navigator *NavigatorSpec `yaml:"navigator,omitempty" json:"navigator,omitempty"`
	WebGL     *WebGLSpec     `yaml:"webgl,omitempty" json:"webgl,omitempty"`
}

type NavigatorSpec struct {
	Platform             string   `yaml:"platform,omitempty" json:"platform,omitempty"`
	UserAgent            string   `yaml:"user_agent,omitempty" json:"user_agent,omitempty"`
	Vendor               string   `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	Language             string   `yaml:"language,omitempty" json:"language,omitempty"`
	Languages            []string `yaml:"languages,omitempty" json:"languages,omitempty"`
	HardwareConcurrency  int      `yaml:"hardware_concurrency,omitempty" json:"hardware_concurrency,omitempty"`
	DeviceMemory         float64  `yaml:"device_memory,omitempty" json:"device_memory,omitempty"`
	MaxTouchPoints       *int     `yaml:"max_touch_points,omitempty" json:"max_touch_points,omitempty"`
	Webdriver            *bool    `yaml:"webdriver,omitempty" json:"webdriver,omitempty"`
}

type WebGLSpec struct {
	Vendor    string `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	Renderer  string `yaml:"renderer,omitempty" json:"renderer,omitempty"`
	MatchMode string `yaml:"match_mode,omitempty" json:"match_mode,omitempty"` // exact | contains
}

// Load reads a profile YAML file.
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks required profile fields.
func (p *Profile) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("profile missing id")
	}
	if p.Name == "" {
		return fmt.Errorf("profile %q missing name", p.ID)
	}
	if p.UserAgent.Pattern == "" && p.UserAgent.Value == "" {
		return fmt.Errorf("profile %q missing user_agent.pattern or user_agent.value", p.ID)
	}
	if p.UserAgent.Value == "" {
		p.UserAgent.Value = p.UserAgent.Pattern
	}
	if p.UserAgent.Pattern == "" {
		p.UserAgent.Pattern = p.UserAgent.Value
	}
	if p.TLS.UTLSClientID == "" {
		return fmt.Errorf("profile %q missing tls.utls_client_id", p.ID)
	}
	return nil
}

// LoadDir loads all *.yaml profiles from a directory.
func LoadDir(dir string) ([]*Profile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read profiles dir: %w", err)
	}
	var profiles []*Profile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		p, err := Load(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// FindByID returns a profile by id from a directory.
func FindByID(dir, id string) (*Profile, error) {
	profiles, err := LoadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, p := range profiles {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, fmt.Errorf("profile %q not found in %s", id, dir)
}
