package capture

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coherencelab/coherencelab/internal/signal"
)

// BrowserPayload is the JS-collected portion posted from /capture.
type BrowserPayload struct {
	ID        string                `json:"id"`
	Name      string                `json:"name"`
	JSRuntime *signal.JSObservation `json:"js_runtime"`
}

// FromHTTP builds capture input from an HTTP request's headers plus optional JS payload.
func FromHTTP(ua string, headers map[string]string, order []string, tlsObs *signal.TLSObservation, h2 *signal.H2Observation, payload *BrowserPayload) *Input {
	if headers == nil {
		headers = map[string]string{}
	}
	lower := map[string]string{}
	for k, v := range headers {
		lower[strings.ToLower(k)] = v
	}
	if ua == "" {
		ua = lower["user-agent"]
	}
	meta := InferFromUA(ua)

	id := ""
	name := ""
	if payload != nil {
		id = payload.ID
		name = payload.Name
	}
	if id == "" {
		id = fmt.Sprintf("%s-%s-captured", meta.Browser, meta.Platform)
		if meta.Version != "" {
			id = fmt.Sprintf("%s-%s-%s-captured", meta.Browser, meta.Version, meta.Platform)
		}
	}
	if name == "" {
		name = fmt.Sprintf("Captured %s %s (%s)", titleCase(meta.Browser), meta.Version, meta.Platform)
	}

	snap := signal.Snapshot{
		UserAgent:       ua,
		Headers:         lower,
		HeaderOrder:     normalizeOrder(order),
		SecCHUA:         lower["sec-ch-ua"],
		SecCHUAMobile:   lower["sec-ch-ua-mobile"],
		SecCHUAPlatform: lower["sec-ch-ua-platform"],
		AcceptLanguage:  lower["accept-language"],
		Accept:          lower["accept"],
		AcceptEncoding:  lower["accept-encoding"],
		TLS:             tlsObs,
		H2:              h2,
	}
	if payload != nil && payload.JSRuntime != nil {
		js := *payload.JSRuntime
		if js.Source == "" {
			js.Source = "probe"
		}
		snap.JS = &js
	}

	return &Input{
		ID:       sanitizeID(id),
		Name:     name,
		Browser:  meta.Browser,
		Platform: meta.Platform,
		Version:  meta.Version,
		Snapshot: snap,
	}
}

// Meta holds inferred browser identity from a User-Agent.
type Meta struct {
	Browser  string
	Platform string
	Version  string
	Engine   string
	Mobile   bool
}

// InferFromUA guesses browser/platform/version from a User-Agent string.
func InferFromUA(ua string) Meta {
	lower := strings.ToLower(ua)
	meta := Meta{Browser: "chrome", Platform: "windows", Version: "131", Engine: "blink"}

	switch {
	case strings.Contains(lower, "android"):
		meta.Platform = "android"
		meta.Mobile = true
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad"):
		meta.Platform = "ios"
		meta.Mobile = true
	case strings.Contains(lower, "mac os x") || strings.Contains(lower, "macintosh"):
		meta.Platform = "macos"
	case strings.Contains(lower, "linux"):
		meta.Platform = "linux"
	case strings.Contains(lower, "windows"):
		meta.Platform = "windows"
	}

	switch {
	case strings.Contains(lower, "edg/"):
		meta.Browser = "edge"
		meta.Engine = "blink"
		meta.Version = extractVersion(ua, `Edg/(\d+)`)
	case strings.Contains(lower, "opr/") || strings.Contains(lower, "opera"):
		meta.Browser = "opera"
		meta.Engine = "blink"
		meta.Version = extractVersion(ua, `OPR/(\d+)`)
		if meta.Version == "" {
			meta.Version = extractVersion(ua, `Chrome/(\d+)`)
		}
	case strings.Contains(lower, "firefox/"):
		meta.Browser = "firefox"
		meta.Engine = "gecko"
		meta.Version = extractVersion(ua, `Firefox/(\d+)`)
	case strings.Contains(lower, "crios/"):
		meta.Browser = "chrome"
		meta.Engine = "webkit"
		meta.Version = extractVersion(ua, `CriOS/(\d+)`)
	case strings.Contains(lower, "version/") && strings.Contains(lower, "safari/") && !strings.Contains(lower, "chrome/") && !strings.Contains(lower, "crios/"):
		meta.Browser = "safari"
		meta.Engine = "webkit"
		meta.Version = extractVersion(ua, `Version/(\d+)`)
	case strings.Contains(lower, "chrome/"):
		meta.Browser = "chrome"
		meta.Engine = "blink"
		meta.Version = extractVersion(ua, `Chrome/(\d+)`)
	}

	if meta.Version == "" {
		meta.Version = "0"
	}
	return meta
}

func extractVersion(ua, pattern string) string {
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(ua)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func sanitizeID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	id = strings.ReplaceAll(id, " ", "-")
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return fmt.Sprintf("captured-%d", time.Now().Unix())
	}
	return out
}

func normalizeOrder(order []string) []string {
	out := make([]string, 0, len(order))
	for _, h := range order {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

// GuessMajor parses the major version int from a version string.
func GuessMajor(version string) int {
	n, _ := strconv.Atoi(version)
	return n
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
