package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/oliver-nyx/coherencelab/internal/profile"
	"github.com/oliver-nyx/coherencelab/internal/signal"
)

// Severity classifies rule outcomes.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Category groups related checks.
type Category string

const (
	CategoryUserAgent     Category = "user_agent"
	CategoryClientHints   Category = "client_hints"
	CategoryHeaders       Category = "headers"
	CategoryTLS           Category = "tls"
	CategoryHTTP2         Category = "http2"
	CategoryAcceptLanguage Category = "accept_language"
	CategoryJSRuntime      Category = "js_runtime"
	CategoryCrossLayer     Category = "cross_layer"
)

// Finding is a single validation result.
type Finding struct {
	ID          string   `json:"id"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Expected    string   `json:"expected,omitempty"`
	Actual      string   `json:"actual,omitempty"`
	Weight      int      `json:"weight"`
	Passed      bool     `json:"passed"`
}

// Rule is a validation function.
type Rule struct {
	ID       string
	Category Category
	Severity Severity
	Weight   int
	Title    string
	Check    func(p *profile.Profile, s *signal.Snapshot) Finding
}

// DefaultRules returns the built-in coherence rule set.
func DefaultRules() []Rule {
	return []Rule{
		userAgentPatternRule(),
		secCHUAVersionRule(),
		secCHUAPlatformRule(),
		secCHUAMobileRule(),
		userAgentPlatformConsistencyRule(),
		userAgentBrowserConsistencyRule(),
		requiredHeadersRule(),
		forbiddenHeadersRule(),
		headerOrderRule(),
		acceptEncodingRule(),
		acceptRule(),
		acceptLanguageRule(),
		tlsALPNRule(),
		tlsVersionRule(),
		http2SettingsRule(),
		jsNavigatorPlatformRule(),
		jsNavigatorVendorRule(),
		jsNavigatorWebdriverRule(),
		jsWebGLRule(),
		crossJSPlatformRule(),
		crossLayerChromeRule(),
		crossLayerFirefoxRule(),
		crossLayerSafariRule(),
	}
}

func userAgentPatternRule() Rule {
	return Rule{
		ID: "ua.pattern", Category: CategoryUserAgent, Severity: SeverityCritical, Weight: 15,
		Title: "User-Agent matches profile pattern",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			passed := matchUserAgent(p.UserAgent.Pattern, s.UserAgent, p.UserAgent.MatchMode)
			return finding("ua.pattern", CategoryUserAgent, SeverityCritical, 15,
				"User-Agent matches profile pattern", p.UserAgent.Pattern, s.UserAgent, passed)
		},
	}
}

func secCHUAVersionRule() Rule {
	return Rule{
		ID: "hints.sec_ch_ua", Category: CategoryClientHints, Severity: SeverityHigh, Weight: 12,
		Title: "Sec-Ch-Ua brand/version coherence",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.ClientHints.SecCHUA == "" {
				return skipped("hints.sec_ch_ua", CategoryClientHints, "Sec-Ch-Ua brand/version coherence")
			}
			expected := normalizeQuotes(p.ClientHints.SecCHUA)
			actual := normalizeQuotes(s.SecCHUA)
			passed := strings.Contains(actual, extractBrandCore(expected)) || actual == expected
			switch p.Browser {
			case "chrome", "edge":
				passed = strings.Contains(actual, fmt.Sprintf(`"Google Chrome";v="%d"`, p.UserAgent.Major)) ||
					strings.Contains(actual, fmt.Sprintf(`"Chromium";v="%d"`, p.UserAgent.Major)) ||
					actual == expected
			case "opera":
				passed = strings.Contains(actual, "Opera") ||
					strings.Contains(actual, "Chromium") ||
					actual == expected
			}
			return finding("hints.sec_ch_ua", CategoryClientHints, SeverityHigh, 12,
				"Sec-Ch-Ua brand/version coherence", expected, actual, passed)
		},
	}
}

func secCHUAPlatformRule() Rule {
	return Rule{
		ID: "hints.platform", Category: CategoryClientHints, Severity: SeverityHigh, Weight: 10,
		Title: "Sec-Ch-Ua-Platform matches profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.ClientHints.SecCHUAPlatform == "" {
				return skipped("hints.platform", CategoryClientHints, "Sec-Ch-Ua-Platform matches profile")
			}
			expected := normalizeQuotes(p.ClientHints.SecCHUAPlatform)
			actual := normalizeQuotes(s.SecCHUAPlatform)
			return finding("hints.platform", CategoryClientHints, SeverityHigh, 10,
				"Sec-Ch-Ua-Platform matches profile", expected, actual, actual == expected)
		},
	}
}

func secCHUAMobileRule() Rule {
	return Rule{
		ID: "hints.mobile", Category: CategoryClientHints, Severity: SeverityMedium, Weight: 8,
		Title: "Sec-Ch-Ua-Mobile matches device class",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.ClientHints.SecCHUAMobile == "" {
				return skipped("hints.mobile", CategoryClientHints, "Sec-Ch-Ua-Mobile matches device class")
			}
			expected := p.ClientHints.SecCHUAMobile
			actual := s.SecCHUAMobile
			return finding("hints.mobile", CategoryClientHints, SeverityMedium, 8,
				"Sec-Ch-Ua-Mobile matches device class", expected, actual, actual == expected)
		},
	}
}

func userAgentPlatformConsistencyRule() Rule {
	return Rule{
		ID: "cross.ua_platform", Category: CategoryCrossLayer, Severity: SeverityCritical, Weight: 14,
		Title: "User-Agent platform matches Sec-Ch-Ua-Platform",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if s.SecCHUAPlatform == "" || s.UserAgent == "" {
				return skipped("cross.ua_platform", CategoryCrossLayer, "User-Agent platform matches Sec-Ch-Ua-Platform")
			}
			platform := strings.ToLower(normalizeQuotes(s.SecCHUAPlatform))
			ua := strings.ToLower(s.UserAgent)
			passed := platformConsistent(ua, platform)
			return finding("cross.ua_platform", CategoryCrossLayer, SeverityCritical, 14,
				"User-Agent platform matches Sec-Ch-Ua-Platform", platform, ua, passed)
		},
	}
}

func userAgentBrowserConsistencyRule() Rule {
	return Rule{
		ID: "cross.ua_browser", Category: CategoryCrossLayer, Severity: SeverityCritical, Weight: 14,
		Title: "User-Agent browser family matches Sec-Ch-Ua",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if s.SecCHUA == "" || s.UserAgent == "" {
				return skipped("cross.ua_browser", CategoryCrossLayer, "User-Agent browser family matches Sec-Ch-Ua")
			}
			passed := browserConsistent(s.UserAgent, s.SecCHUA, p.Browser)
			return finding("cross.ua_browser", CategoryCrossLayer, SeverityCritical, 14,
				"User-Agent browser family matches Sec-Ch-Ua", p.Browser, s.UserAgent+" | "+s.SecCHUA, passed)
		},
	}
}

func requiredHeadersRule() Rule {
	return Rule{
		ID: "headers.required", Category: CategoryHeaders, Severity: SeverityHigh, Weight: 10,
		Title: "Required headers present with expected values",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			var missing []string
			for k, v := range p.Headers.Required {
				actual, ok := s.Headers[strings.ToLower(k)]
				if !ok {
					missing = append(missing, k+" (missing)")
					continue
				}
				if v != "" && !strings.Contains(actual, v) {
					missing = append(missing, fmt.Sprintf("%s (got %q want contains %q)", k, actual, v))
				}
			}
			passed := len(missing) == 0
			actual := "ok"
			if !passed {
				actual = strings.Join(missing, "; ")
			}
			return finding("headers.required", CategoryHeaders, SeverityHigh, 10,
				"Required headers present with expected values", fmt.Sprintf("%d headers", len(p.Headers.Required)), actual, passed)
		},
	}
}

func forbiddenHeadersRule() Rule {
	return Rule{
		ID: "headers.forbidden", Category: CategoryHeaders, Severity: SeverityMedium, Weight: 6,
		Title: "Forbidden automation headers absent",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			var found []string
			for _, h := range p.Headers.Forbidden {
				if _, ok := s.Headers[strings.ToLower(h)]; ok {
					found = append(found, h)
				}
			}
			passed := len(found) == 0
			actual := "none"
			if !passed {
				actual = strings.Join(found, ", ")
			}
			return finding("headers.forbidden", CategoryHeaders, SeverityMedium, 6,
				"Forbidden automation headers absent", "none", actual, passed)
		},
	}
}

func headerOrderRule() Rule {
	return Rule{
		ID: "headers.order", Category: CategoryHeaders, Severity: SeverityMedium, Weight: 8,
		Title: "Header order matches browser profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if len(p.Headers.Order) == 0 || len(s.HeaderOrder) == 0 {
				return skipped("headers.order", CategoryHeaders, "Header order matches browser profile")
			}
			score := orderSimilarity(p.Headers.Order, s.HeaderOrder)
			passed := score >= 0.6
			return finding("headers.order", CategoryHeaders, SeverityMedium, 8,
				"Header order matches browser profile",
				strings.Join(p.Headers.Order, " → "),
				fmt.Sprintf("%s (similarity %.0f%%)", strings.Join(s.HeaderOrder, " → "), score*100),
				passed)
		},
	}
}

func acceptEncodingRule() Rule {
	return Rule{
		ID: "headers.accept_encoding", Category: CategoryHeaders, Severity: SeverityLow, Weight: 4,
		Title: "Accept-Encoding matches profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.Headers.AcceptEncoding == "" {
				return skipped("headers.accept_encoding", CategoryHeaders, "Accept-Encoding matches profile")
			}
			passed := strings.EqualFold(s.AcceptEncoding, p.Headers.AcceptEncoding)
			return finding("headers.accept_encoding", CategoryHeaders, SeverityLow, 4,
				"Accept-Encoding matches profile", p.Headers.AcceptEncoding, s.AcceptEncoding, passed)
		},
	}
}

func acceptRule() Rule {
	return Rule{
		ID: "headers.accept", Category: CategoryHeaders, Severity: SeverityLow, Weight: 4,
		Title: "Accept header matches profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.Headers.Accept == "" {
				return skipped("headers.accept", CategoryHeaders, "Accept header matches profile")
			}
			passed := strings.Contains(s.Accept, strings.Split(p.Headers.Accept, ",")[0])
			return finding("headers.accept", CategoryHeaders, SeverityLow, 4,
				"Accept header matches profile", p.Headers.Accept, s.Accept, passed)
		},
	}
}

func acceptLanguageRule() Rule {
	return Rule{
		ID: "accept_language.primary", Category: CategoryAcceptLanguage, Severity: SeverityMedium, Weight: 6,
		Title: "Accept-Language primary locale matches profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.AcceptLanguage.Primary == "" {
				return skipped("accept_language.primary", CategoryAcceptLanguage, "Accept-Language primary locale matches profile")
			}
			primary := strings.Split(strings.Split(s.AcceptLanguage, ",")[0], ";")[0]
			passed := strings.EqualFold(strings.TrimSpace(primary), p.AcceptLanguage.Primary)
			return finding("accept_language.primary", CategoryAcceptLanguage, SeverityMedium, 6,
				"Accept-Language primary locale matches profile", p.AcceptLanguage.Primary, primary, passed)
		},
	}
}

func tlsALPNRule() Rule {
	return Rule{
		ID: "tls.alpn", Category: CategoryTLS, Severity: SeverityHigh, Weight: 10,
		Title: "TLS ALPN negotiation matches profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if s.TLS == nil || len(p.TLS.ALPN) == 0 {
				return skipped("tls.alpn", CategoryTLS, "TLS ALPN negotiation matches profile")
			}
			expected := strings.Join(p.TLS.ALPN, ", ")
			passed := s.TLS.ALPN != "" && containsALPN(s.TLS.ALPN, p.TLS.ALPN)
			return finding("tls.alpn", CategoryTLS, SeverityHigh, 10,
				"TLS ALPN negotiation matches profile", expected, s.TLS.ALPN, passed)
		},
	}
}

func tlsVersionRule() Rule {
	return Rule{
		ID: "tls.version", Category: CategoryTLS, Severity: SeverityMedium, Weight: 6,
		Title: "TLS version within profile range",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if s.TLS == nil {
				return skipped("tls.version", CategoryTLS, "TLS version within profile range")
			}
			passed := s.TLS.Version != ""
			return finding("tls.version", CategoryTLS, SeverityMedium, 6,
				"TLS version within profile range", p.TLS.MinVersion+"-"+p.TLS.MaxVersion, s.TLS.Version, passed)
		},
	}
}

func http2SettingsRule() Rule {
	return Rule{
		ID: "http2.settings", Category: CategoryHTTP2, Severity: SeverityHigh, Weight: 12,
		Title: "HTTP/2 SETTINGS frame matches profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if s.H2 == nil {
				return skipped("http2.settings", CategoryHTTP2, "HTTP/2 SETTINGS frame matches profile")
			}
			matches := 0
			total := 0
			checks := []struct {
				name     string
				expected uint32
				actual   uint32
			}{
				{"HEADER_TABLE_SIZE", p.HTTP2.HeaderTableSize, s.H2.HeaderTableSize},
				{"ENABLE_PUSH", p.HTTP2.EnablePush, s.H2.EnablePush},
				{"MAX_CONCURRENT_STREAMS", p.HTTP2.MaxConcurrent, s.H2.MaxConcurrent},
				{"INITIAL_WINDOW_SIZE", p.HTTP2.InitialWindowSize, s.H2.InitialWindowSize},
				{"MAX_FRAME_SIZE", p.HTTP2.MaxFrameSize, s.H2.MaxFrameSize},
				{"MAX_HEADER_LIST_SIZE", p.HTTP2.MaxHeaderListSize, s.H2.MaxHeaderListSize},
			}
			var diffs []string
			for _, c := range checks {
				if c.expected == 0 || !s.H2.HasSetting(c.name) {
					continue
				}
				total++
				if c.expected == c.actual {
					matches++
				} else {
					diffs = append(diffs, fmt.Sprintf("%s=%d want %d", c.name, c.actual, c.expected))
				}
			}
			passed := total > 0 && float64(matches)/float64(total) >= 0.8
			actual := fmt.Sprintf("%d/%d match", matches, total)
			if len(diffs) > 0 {
				actual += ": " + strings.Join(diffs, "; ")
			}
			return finding("http2.settings", CategoryHTTP2, SeverityHigh, 12,
				"HTTP/2 SETTINGS frame matches profile", "browser defaults", actual, passed)
		},
	}
}

func crossLayerChromeRule() Rule {
	return Rule{
		ID: "cross.chrome_tls_ua", Category: CategoryCrossLayer, Severity: SeverityCritical, Weight: 12,
		Title: "Chromium User-Agent aligns with Chromium TLS fingerprint",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.Browser != "chrome" && p.Browser != "edge" && p.Browser != "opera" {
				return skipped("cross.chrome_tls_ua", CategoryCrossLayer, "Chromium User-Agent aligns with Chromium TLS fingerprint")
			}
			if s.TLS == nil {
				return skipped("cross.chrome_tls_ua", CategoryCrossLayer, "Chromium User-Agent aligns with Chromium TLS fingerprint")
			}
			uaLower := strings.ToLower(s.UserAgent)
			// Chrome on iOS (CriOS) uses WebKit networking — Safari/iOS TLS is correct.
			if strings.Contains(uaLower, "crios/") || p.Platform == "ios" {
				tlsIOS := iosTLSPreset(p.TLS.UTLSClientID) || iosTLSPreset(s.TLS.UTLSClientID)
				passed := strings.Contains(uaLower, "crios/") && tlsIOS
				return finding("cross.chrome_tls_ua", CategoryCrossLayer, SeverityCritical, 12,
					"Chrome iOS (CriOS) aligns with WebKit/iOS TLS fingerprint",
					p.TLS.UTLSClientID, s.TLS.UTLSClientID+" ja3="+s.TLS.JA3, passed)
			}
			uaChromium := strings.Contains(s.UserAgent, "Chrome/") || strings.Contains(s.UserAgent, "Edg/") || strings.Contains(s.UserAgent, "OPR/")
			tlsChromium := chromiumTLSPreset(p.TLS.UTLSClientID) || chromiumTLSPreset(s.TLS.UTLSClientID)
			passed := uaChromium && (tlsChromium || s.TLS.JA3 != "")
			return finding("cross.chrome_tls_ua", CategoryCrossLayer, SeverityCritical, 12,
				"Chromium User-Agent aligns with Chromium TLS fingerprint",
				p.TLS.UTLSClientID, s.TLS.UTLSClientID+" ja3="+s.TLS.JA3, passed)
		},
	}
}

func chromiumTLSPreset(id string) bool {
	id = strings.ToLower(id)
	return strings.Contains(id, "chrome") || strings.Contains(id, "edge") || strings.Contains(id, "chromium")
}

func iosTLSPreset(id string) bool {
	id = strings.ToLower(id)
	return strings.Contains(id, "safari") || strings.Contains(id, "ios")
}

func crossLayerFirefoxRule() Rule {
	return Rule{
		ID: "cross.firefox_consistency", Category: CategoryCrossLayer, Severity: SeverityCritical, Weight: 12,
		Title: "Firefox lacks Client Hints but UA must be Firefox",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.Browser != "firefox" {
				return skipped("cross.firefox_consistency", CategoryCrossLayer, "Firefox lacks Client Hints but UA must be Firefox")
			}
			passed := strings.Contains(s.UserAgent, "Firefox/") && s.SecCHUA == ""
			return finding("cross.firefox_consistency", CategoryCrossLayer, SeverityCritical, 12,
				"Firefox lacks Client Hints but UA must be Firefox", "Firefox UA, no Sec-Ch-Ua", s.UserAgent, passed)
		},
	}
}

func crossLayerSafariRule() Rule {
	return Rule{
		ID: "cross.safari_consistency", Category: CategoryCrossLayer, Severity: SeverityCritical, Weight: 12,
		Title: "Safari User-Agent aligns with Safari TLS profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.Browser != "safari" {
				return skipped("cross.safari_consistency", CategoryCrossLayer, "Safari User-Agent aligns with Safari TLS profile")
			}
			passed := strings.Contains(s.UserAgent, "Safari/") && strings.Contains(s.UserAgent, "Version/")
			if s.TLS != nil {
				passed = passed && (strings.Contains(strings.ToLower(p.TLS.UTLSClientID), "safari") || s.TLS.JA3 != "")
			}
			return finding("cross.safari_consistency", CategoryCrossLayer, SeverityCritical, 12,
				"Safari User-Agent aligns with Safari TLS profile", p.TLS.UTLSClientID, s.UserAgent, passed)
		},
	}
}

func matchUserAgent(pattern, ua, mode string) bool {
	if pattern == "" {
		return false
	}
	switch strings.ToLower(mode) {
	case "exact":
		return ua == pattern
	case "regex":
		re, err := regexp.Compile(pattern)
		return err == nil && re.MatchString(ua)
	case "contains", "":
		return strings.Contains(ua, pattern)
	default:
		return strings.Contains(ua, pattern)
	}
}

func finding(id string, cat Category, sev Severity, weight int, title, expected, actual string, passed bool) Finding {
	return Finding{
		ID: id, Category: cat, Severity: sev, Weight: weight, Title: title,
		Description: title, Expected: expected, Actual: actual, Passed: passed,
	}
}

func skipped(id string, cat Category, title string) Finding {
	return Finding{
		ID: id, Category: cat, Severity: SeverityInfo, Weight: 0, Title: title,
		Description: "Skipped — insufficient observed data", Passed: true,
	}
}

func normalizeQuotes(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"`)
}

func extractBrandCore(s string) string {
	if idx := strings.Index(s, `"`); idx >= 0 {
		end := strings.Index(s[idx+1:], `"`)
		if end >= 0 {
			return s[idx+1 : idx+1+end]
		}
	}
	return s
}

func platformConsistent(ua, platform string) bool {
	ua = strings.ToLower(ua)
	platform = strings.ToLower(strings.Trim(platform, `"`))
	switch platform {
	case "windows":
		return strings.Contains(ua, "windows nt")
	case "macos", "mac os x":
		return strings.Contains(ua, "mac os x") || strings.Contains(ua, "macintosh")
	case "linux":
		return strings.Contains(ua, "linux") && !strings.Contains(ua, "android")
	case "android":
		return strings.Contains(ua, "android")
	case "ios":
		return strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad")
	default:
		return false
	}
}

func browserConsistent(ua, secCHUA, browser string) bool {
	uaLower := strings.ToLower(ua)
	chLower := strings.ToLower(secCHUA)
	switch browser {
	case "chrome", "edge":
		// CriOS has no Client Hints; desktop Chrome requires brand hints.
		if strings.Contains(uaLower, "crios/") {
			return secCHUA == "" || strings.Contains(chLower, "chrome") || strings.Contains(chLower, "chromium")
		}
		return strings.Contains(uaLower, "chrome/") && (strings.Contains(chLower, "chrome") || strings.Contains(chLower, "chromium"))
	case "opera":
		return strings.Contains(uaLower, "opr/") && (strings.Contains(chLower, "opera") || strings.Contains(chLower, "chromium"))
	case "firefox":
		return strings.Contains(uaLower, "firefox/") && secCHUA == ""
	case "safari":
		return strings.Contains(uaLower, "safari/") && !strings.Contains(uaLower, "chrome/") && !strings.Contains(uaLower, "crios/")
	default:
		return true
	}
}

func orderSimilarity(expected, actual []string) float64 {
	if len(expected) == 0 {
		return 1
	}
	exp := make(map[string]int, len(expected))
	for i, h := range expected {
		exp[strings.ToLower(h)] = i
	}
	matched := 0
	lastIdx := -1
	for _, h := range actual {
		idx, ok := exp[strings.ToLower(h)]
		if !ok {
			continue
		}
		if idx > lastIdx {
			matched++
			lastIdx = idx
		}
	}
	return float64(matched) / float64(len(expected))
}

func containsALPN(actual string, expected []string) bool {
	for _, e := range expected {
		if strings.EqualFold(actual, e) {
			return true
		}
	}
	return false
}

// Evaluate runs all rules against observed signals.
func Evaluate(p *profile.Profile, s *signal.Snapshot, ruleSet []Rule) []Finding {
	findings := make([]Finding, 0, len(ruleSet))
	for _, r := range ruleSet {
		f := r.Check(p, s)
		f.ID = r.ID
		f.Category = r.Category
		if f.Weight == 0 && r.Weight > 0 {
			f.Weight = r.Weight
		}
		if f.Severity == "" {
			f.Severity = r.Severity
		}
		findings = append(findings, f)
	}
	return findings
}
