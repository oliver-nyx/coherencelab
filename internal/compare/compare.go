package compare

import (
	"fmt"
	"strings"

	"github.com/coherencelab/coherencelab/internal/signal"
)

// Severity of a diff finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Diff is a single mismatch between two snapshots.
type Diff struct {
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	Field    string   `json:"field"`
	Left     string   `json:"left"`
	Right    string   `json:"right"`
	Note     string   `json:"note,omitempty"`
}

// Result holds a full comparison.
type Result struct {
	LabelA   string `json:"label_a"`
	LabelB   string `json:"label_b"`
	Diffs    []Diff `json:"diffs"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Total    int    `json:"total"`
	Coherent bool   `json:"coherent"`
}

// Snapshots compares two identity snapshots layer by layer.
func Snapshots(labelA string, a *signal.Snapshot, labelB string, b *signal.Snapshot) *Result {
	res := &Result{LabelA: labelA, LabelB: labelB}
	add := func(cat, field, left, right string, sev Severity, note string) {
		if left == right {
			return
		}
		if left == "" && right == "" {
			return
		}
		res.Diffs = append(res.Diffs, Diff{
			Category: cat, Severity: sev, Field: field,
			Left: left, Right: right, Note: note,
		})
		switch sev {
		case SeverityCritical:
			res.Critical++
		case SeverityHigh:
			res.High++
		}
		res.Total++
	}

	addStr := func(cat, field, la, lb string, sev Severity) {
		add(cat, field, la, lb, sev, "")
	}

	addStr("user_agent", "user_agent", a.UserAgent, b.UserAgent, SeverityCritical)
	addStr("client_hints", "sec_ch_ua", a.SecCHUA, b.SecCHUA, SeverityHigh)
	addStr("client_hints", "sec_ch_ua_platform", a.SecCHUAPlatform, b.SecCHUAPlatform, SeverityCritical)
	addStr("client_hints", "sec_ch_ua_mobile", a.SecCHUAMobile, b.SecCHUAMobile, SeverityMedium)
	addStr("headers", "accept_language", a.AcceptLanguage, b.AcceptLanguage, SeverityMedium)
	addStr("headers", "accept", a.Accept, b.Accept, SeverityLow)
	addStr("headers", "accept_encoding", a.AcceptEncoding, b.AcceptEncoding, SeverityLow)

	if a.TLS != nil || b.TLS != nil {
		ta, tb := tlsStr(a.TLS), tlsStr(b.TLS)
		addStr("tls", "fingerprint", ta, tb, SeverityCritical)
	}
	if a.H2 != nil || b.H2 != nil {
		ha, hb := h2Str(a.H2), h2Str(b.H2)
		addStr("http2", "settings", ha, hb, SeverityHigh)
	}
	if a.JS != nil || b.JS != nil {
		addStr("js_runtime", "navigator", jsNavStr(a.JS), jsNavStr(b.JS), SeverityCritical)
		addStr("js_runtime", "webgl", jsWebGLStr(a.JS), jsWebGLStr(b.JS), SeverityMedium)
	}

	// Cross-layer inference between A's layers
	if note := crossLayerNote(a); note != "" {
		res.Diffs = append(res.Diffs, Diff{
			Category: "cross_layer", Severity: SeverityCritical,
			Field: "cross_layer.a", Left: note, Right: "internal mismatch",
		})
		res.Critical++
		res.Total++
	}
	if note := crossLayerNote(b); note != "" {
		res.Diffs = append(res.Diffs, Diff{
			Category: "cross_layer", Severity: SeverityCritical,
			Field: "cross_layer.b", Left: note, Right: "internal mismatch",
		})
		res.Critical++
		res.Total++
	}

	// Cross between A and B browser families
	if note := crossBetween(a, b); note != "" {
		res.Diffs = append(res.Diffs, Diff{
			Category: "cross_export", Severity: SeverityCritical,
			Field: "cross_export", Left: labelA, Right: labelB, Note: note,
		})
		res.Critical++
		res.Total++
	}

	res.Coherent = res.Critical == 0 && res.Total == 0
	return res
}

func tlsStr(t *signal.TLSObservation) string {
	if t == nil {
		return ""
	}
	parts := []string{t.Version, t.ALPN, t.UTLSClientID, t.JA3}
	return strings.Join(filterEmpty(parts), " | ")
}

func h2Str(h *signal.H2Observation) string {
	if h == nil {
		return ""
	}
	return fmt.Sprintf("table=%d concurrent=%d window=%d", h.HeaderTableSize, h.MaxConcurrent, h.InitialWindowSize)
}

func jsNavStr(js *signal.JSObservation) string {
	if js == nil || js.Navigator == nil {
		return ""
	}
	n := js.Navigator
	wd := "unknown"
	if n.Webdriver != nil {
		wd = fmt.Sprintf("%v", *n.Webdriver)
	}
	return fmt.Sprintf("platform=%s vendor=%q webdriver=%s", n.Platform, n.Vendor, wd)
}

func jsWebGLStr(js *signal.JSObservation) string {
	if js == nil || js.WebGL == nil {
		return ""
	}
	return fmt.Sprintf("%s | %s", js.WebGL.Vendor, js.WebGL.Renderer)
}

func filterEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func crossLayerNote(s *signal.Snapshot) string {
	if s.UserAgent == "" {
		return ""
	}
	ua := strings.ToLower(s.UserAgent)
	platform := strings.ToLower(strings.Trim(s.SecCHUAPlatform, `"`))

	if platform == "windows" && !strings.Contains(ua, "windows nt") {
		return "Sec-Ch-Ua-Platform says Windows but User-Agent does not"
	}
	if platform == "linux" && !strings.Contains(ua, "linux") {
		return "Sec-Ch-Ua-Platform says Linux but User-Agent does not"
	}
	if strings.Contains(ua, "firefox/") && s.SecCHUA != "" {
		return "Firefox User-Agent with Client Hints present"
	}
	if strings.Contains(ua, "chrome/") && s.SecCHUA != "" && !strings.Contains(strings.ToLower(s.SecCHUA), "chrome") && !strings.Contains(strings.ToLower(s.SecCHUA), "chromium") {
		return "Chrome User-Agent with non-Chromium Sec-Ch-Ua"
	}
	if s.TLS != nil {
		if strings.Contains(ua, "firefox/") && strings.Contains(strings.ToLower(s.TLS.UTLSClientID), "chrome") {
			return "Firefox User-Agent with Chrome TLS preset"
		}
		if strings.Contains(ua, "chrome/") && strings.Contains(strings.ToLower(s.TLS.UTLSClientID), "firefox") {
			return "Chrome User-Agent with Firefox TLS preset"
		}
	}
	if s.JS != nil && s.JS.Navigator != nil && s.JS.Navigator.Webdriver != nil && *s.JS.Navigator.Webdriver {
		return "navigator.webdriver is true (automation leak)"
	}
	return ""
}

func crossBetween(a, b *signal.Snapshot) string {
	fa, fb := browserFamily(a.UserAgent), browserFamily(b.UserAgent)
	if fa != "" && fb != "" && fa != fb {
		return fmt.Sprintf("browser family mismatch: %s vs %s", fa, fb)
	}
	return ""
}

func browserFamily(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "firefox/"):
		return "firefox"
	case strings.Contains(ua, "edg/"):
		return "edge"
	case strings.Contains(ua, "chrome/"):
		return "chrome"
	case strings.Contains(ua, "safari/") && strings.Contains(ua, "version/"):
		return "safari"
	default:
		return ""
	}
}
