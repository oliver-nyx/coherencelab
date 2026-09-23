package signal

// JSObservation captures browser JavaScript environment signals.
type JSObservation struct {
	Source    string                `json:"source,omitempty"` // profile | export | probe
	Navigator *NavigatorObservation `json:"navigator,omitempty"`
	WebGL     *WebGLObservation     `json:"webgl,omitempty"`
	Canvas    *CanvasObservation    `json:"canvas,omitempty"`
}

type NavigatorObservation struct {
	Platform             string   `json:"platform,omitempty"`
	UserAgent            string   `json:"user_agent,omitempty"`
	Vendor               string   `json:"vendor,omitempty"`
	Language             string   `json:"language,omitempty"`
	Languages            []string `json:"languages,omitempty"`
	HardwareConcurrency  int      `json:"hardware_concurrency,omitempty"`
	DeviceMemory         float64  `json:"device_memory,omitempty"`
	MaxTouchPoints       *int     `json:"max_touch_points,omitempty"`
	Webdriver            *bool    `json:"webdriver,omitempty"`
}

type WebGLObservation struct {
	Vendor   string `json:"vendor,omitempty"`
	Renderer string `json:"renderer,omitempty"`
}

// CanvasObservation is observe-only in v1 (not scored against profiles).
type CanvasObservation struct {
	Hash2D string `json:"hash_2d,omitempty"`
}

// BoolPtr returns a *bool for JSON/YAML literals.
func BoolPtr(v bool) *bool { return &v }

// IntPtr returns a *int for JSON/YAML literals.
func IntPtr(v int) *int { return &v }
