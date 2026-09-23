package rules

import (
	"fmt"
	"strings"

	"github.com/coherencelab/coherencelab/internal/profile"
	"github.com/coherencelab/coherencelab/internal/signal"
)

func jsNavigatorPlatformRule() Rule {
	return Rule{
		ID: "js.navigator_platform", Category: CategoryJSRuntime, Severity: SeverityHigh, Weight: 8,
		Title: "navigator.platform matches profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			exp, obs, ok := jsNavPair(p, s)
			if !ok || exp.Platform == "" || obs.Platform == "" {
				return skipped("js.navigator_platform", CategoryJSRuntime, "navigator.platform matches profile")
			}
			return finding("js.navigator_platform", CategoryJSRuntime, SeverityHigh, 8,
				"navigator.platform matches profile", exp.Platform, obs.Platform, exp.Platform == obs.Platform)
		},
	}
}

func jsNavigatorVendorRule() Rule {
	return Rule{
		ID: "js.navigator_vendor", Category: CategoryJSRuntime, Severity: SeverityMedium, Weight: 6,
		Title: "navigator.vendor matches profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.JSRuntime == nil || p.JSRuntime.Navigator == nil || s.JS == nil || s.JS.Navigator == nil {
				return skipped("js.navigator_vendor", CategoryJSRuntime, "navigator.vendor matches profile")
			}
			exp := p.JSRuntime.Navigator.Vendor
			obs := s.JS.Navigator.Vendor
			// Empty expected vendor (Firefox) requires empty observed vendor.
			if exp == "" && p.Browser == "firefox" {
				return finding("js.navigator_vendor", CategoryJSRuntime, SeverityMedium, 6,
					"navigator.vendor matches profile", "(empty)", obs, obs == "")
			}
			if exp == "" {
				return skipped("js.navigator_vendor", CategoryJSRuntime, "navigator.vendor matches profile")
			}
			return finding("js.navigator_vendor", CategoryJSRuntime, SeverityMedium, 6,
				"navigator.vendor matches profile", exp, obs, obs == exp)
		},
	}
}

func jsNavigatorWebdriverRule() Rule {
	return Rule{
		ID: "js.navigator_webdriver", Category: CategoryJSRuntime, Severity: SeverityCritical, Weight: 10,
		Title: "navigator.webdriver matches profile expectation",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.JSRuntime == nil || p.JSRuntime.Navigator == nil || p.JSRuntime.Navigator.Webdriver == nil {
				return skipped("js.navigator_webdriver", CategoryJSRuntime, "navigator.webdriver matches profile expectation")
			}
			if s.JS == nil || s.JS.Navigator == nil || s.JS.Navigator.Webdriver == nil {
				return skipped("js.navigator_webdriver", CategoryJSRuntime, "navigator.webdriver matches profile expectation")
			}
			want := *p.JSRuntime.Navigator.Webdriver
			got := *s.JS.Navigator.Webdriver
			return finding("js.navigator_webdriver", CategoryJSRuntime, SeverityCritical, 10,
				"navigator.webdriver matches profile expectation",
				fmt.Sprintf("%v", want), fmt.Sprintf("%v", got), want == got)
		},
	}
}

func jsWebGLRule() Rule {
	return Rule{
		ID: "js.webgl_vendor_renderer", Category: CategoryJSRuntime, Severity: SeverityMedium, Weight: 8,
		Title: "WebGL vendor/renderer match profile",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if p.JSRuntime == nil || p.JSRuntime.WebGL == nil {
				return skipped("js.webgl_vendor_renderer", CategoryJSRuntime, "WebGL vendor/renderer match profile")
			}
			if s.JS == nil || s.JS.WebGL == nil {
				return skipped("js.webgl_vendor_renderer", CategoryJSRuntime, "WebGL vendor/renderer match profile")
			}
			exp := p.JSRuntime.WebGL
			obs := s.JS.WebGL
			if exp.Vendor == "" && exp.Renderer == "" {
				return skipped("js.webgl_vendor_renderer", CategoryJSRuntime, "WebGL vendor/renderer match profile")
			}
			mode := strings.ToLower(exp.MatchMode)
			if mode == "" {
				mode = "contains"
			}
			vendorOK := exp.Vendor == "" || matchText(exp.Vendor, obs.Vendor, mode)
			rendererOK := exp.Renderer == "" || matchText(exp.Renderer, obs.Renderer, mode)
			passed := vendorOK && rendererOK
			expected := fmt.Sprintf("vendor~%s renderer~%s", exp.Vendor, exp.Renderer)
			actual := fmt.Sprintf("vendor=%s renderer=%s", obs.Vendor, obs.Renderer)
			return finding("js.webgl_vendor_renderer", CategoryJSRuntime, SeverityMedium, 8,
				"WebGL vendor/renderer match profile", expected, actual, passed)
		},
	}
}

func crossJSPlatformRule() Rule {
	return Rule{
		ID: "cross.js_ua_platform", Category: CategoryCrossLayer, Severity: SeverityCritical, Weight: 12,
		Title: "navigator.platform aligns with User-Agent / Client Hints",
		Check: func(p *profile.Profile, s *signal.Snapshot) Finding {
			if s.JS == nil || s.JS.Navigator == nil || s.JS.Navigator.Platform == "" {
				return skipped("cross.js_ua_platform", CategoryCrossLayer, "navigator.platform aligns with User-Agent / Client Hints")
			}
			navPlat := s.JS.Navigator.Platform
			ua := s.UserAgent
			if ua == "" {
				ua = p.UserAgent.Value
			}
			passed := navigatorPlatformConsistent(navPlat, ua, s.SecCHUAPlatform, p.Platform)
			return finding("cross.js_ua_platform", CategoryCrossLayer, SeverityCritical, 12,
				"navigator.platform aligns with User-Agent / Client Hints",
				p.Platform+" / "+s.SecCHUAPlatform, navPlat+" | "+ua, passed)
		},
	}
}

func jsNavPair(p *profile.Profile, s *signal.Snapshot) (*profile.NavigatorSpec, *signal.NavigatorObservation, bool) {
	if p.JSRuntime == nil || p.JSRuntime.Navigator == nil || s.JS == nil || s.JS.Navigator == nil {
		return nil, nil, false
	}
	return p.JSRuntime.Navigator, s.JS.Navigator, true
}

func matchText(expected, actual, mode string) bool {
	switch mode {
	case "exact":
		return actual == expected
	default:
		return strings.Contains(strings.ToLower(actual), strings.ToLower(expected))
	}
}

func navigatorPlatformConsistent(navPlatform, ua, secCHUAPlatform, profilePlatform string) bool {
	nav := strings.ToLower(navPlatform)
	uaLower := strings.ToLower(ua)
	hint := strings.ToLower(normalizeQuotes(secCHUAPlatform))
	prof := strings.ToLower(profilePlatform)

	switch {
	case strings.HasPrefix(nav, "win"):
		return strings.Contains(uaLower, "windows") || hint == "windows" || prof == "windows"
	case strings.HasPrefix(nav, "mac"):
		return strings.Contains(uaLower, "mac os x") || strings.Contains(uaLower, "macintosh") ||
			hint == "macos" || hint == "mac os x" || prof == "macos" || prof == "ios"
	case strings.Contains(nav, "linux") && (strings.Contains(nav, "arm") || strings.Contains(uaLower, "android")):
		return strings.Contains(uaLower, "android") || hint == "android" || prof == "android"
	case strings.Contains(nav, "linux") || nav == "x11":
		return (strings.Contains(uaLower, "linux") && !strings.Contains(uaLower, "android")) ||
			hint == "linux" || prof == "linux"
	case strings.Contains(nav, "iphone") || strings.Contains(nav, "ipad"):
		return strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipad") || prof == "ios"
	default:
		return false
	}
}
