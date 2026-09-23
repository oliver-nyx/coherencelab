package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/coherencelab/coherencelab/internal/client"
	"github.com/coherencelab/coherencelab/internal/profile"
	"github.com/coherencelab/coherencelab/internal/rules"
	"github.com/coherencelab/coherencelab/internal/score"
	"github.com/coherencelab/coherencelab/internal/signal"
)

// Mode defines scan execution mode.
type Mode string

const (
	ModeLocal  Mode = "local"
	ModeLive   Mode = "live"
	ModeMutate Mode = "mutate"
	ModeImport Mode = "import"
)

// Options configures a coherence scan.
type Options struct {
	Profile   *profile.Profile
	Mode      Mode
	ProbeURL  string
	Mutate    string // e.g. "wrong-platform" for intentional mismatch demo
	Timeout   time.Duration
	Insecure  bool
	Snapshot  *signal.Snapshot // for import mode
}

// Report is the full scan output.
type Report struct {
	ProfileID   string           `json:"profile_id"`
	ProfileName string           `json:"profile_name"`
	Mode        Mode             `json:"mode"`
	ProbeURL    string           `json:"probe_url,omitempty"`
	Timestamp   time.Time        `json:"timestamp"`
	Signals     *signal.Snapshot `json:"signals"`
	Result      score.Result     `json:"result"`
}

// Run executes a coherence scan.
func Run(ctx context.Context, opts Options) (*Report, error) {
	if opts.Profile == nil {
		return nil, fmt.Errorf("profile required")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.Mode == "" {
		opts.Mode = ModeLocal
	}

	var snap *signal.Snapshot
	var err error

	switch opts.Mode {
	case ModeLocal:
		snap = client.LocalSnapshot(opts.Profile)
	case ModeLive:
		if opts.ProbeURL == "" {
			return nil, fmt.Errorf("probe URL required for live mode")
		}
		snap, _, err = client.Probe(ctx, opts.ProbeURL, opts.Profile, opts.Insecure)
		if err != nil {
			return nil, err
		}
	case ModeMutate:
		snap = client.LocalSnapshot(opts.Profile)
		applyMutation(snap, opts.Mutate)
	case ModeImport:
		if opts.Snapshot == nil {
			return nil, fmt.Errorf("snapshot required for import mode")
		}
		snap = opts.Snapshot
	default:
		return nil, fmt.Errorf("unknown mode %q", opts.Mode)
	}

	findings := rules.Evaluate(opts.Profile, snap, rules.DefaultRules())
	result := score.Compute(findings)

	return &Report{
		ProfileID:   opts.Profile.ID,
		ProfileName: opts.Profile.Name,
		Mode:        opts.Mode,
		ProbeURL:    opts.ProbeURL,
		Timestamp:   time.Now().UTC(),
		Signals:     snap,
		Result:      result,
	}, nil
}

func applyMutation(s *signal.Snapshot, mutation string) {
	switch mutation {
	case "wrong-platform":
		s.SecCHUAPlatform = `"Linux"`
		s.Headers["sec-ch-ua-platform"] = `"Linux"`
	case "wrong-browser":
		s.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
		s.Headers["user-agent"] = s.UserAgent
	case "automation-leak":
		s.Headers["x-coherencelab-test"] = "selenium"
		s.HeaderOrder = append(s.HeaderOrder, "x-coherencelab-test")
	case "tls-mismatch":
		if s.TLS != nil {
			s.TLS.UTLSClientID = "firefox_120"
		}
	case "js-webdriver":
		if s.JS == nil {
			s.JS = &signal.JSObservation{Source: "mutate"}
		}
		if s.JS.Navigator == nil {
			s.JS.Navigator = &signal.NavigatorObservation{}
		}
		s.JS.Navigator.Webdriver = signal.BoolPtr(true)
	case "js-wrong-platform":
		if s.JS == nil {
			s.JS = &signal.JSObservation{Source: "mutate"}
		}
		if s.JS.Navigator == nil {
			s.JS.Navigator = &signal.NavigatorObservation{}
		}
		s.JS.Navigator.Platform = "Linux x86_64"
	}
}
