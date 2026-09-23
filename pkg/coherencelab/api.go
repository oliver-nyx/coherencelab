// Package coherencelab provides the public API for browser identity coherence validation.
package coherencelab

import (
	"context"

	"github.com/oliver-nyx/coherencelab/internal/profile"
	"github.com/oliver-nyx/coherencelab/internal/scan"
)

// Profile is a browser identity profile.
type Profile = profile.Profile

// Report is a scan report.
type Report = scan.Report

// ScanMode defines how a scan is executed.
type ScanMode = scan.Mode

const (
	ScanLocal  = scan.ModeLocal
	ScanLive   = scan.ModeLive
	ScanMutate = scan.ModeMutate
	ScanImport = scan.ModeImport
)

// LoadProfile loads a profile from a YAML file.
func LoadProfile(path string) (*Profile, error) {
	return profile.Load(path)
}

// LoadProfiles loads all profiles from a directory.
func LoadProfiles(dir string) ([]*Profile, error) {
	return profile.LoadDir(dir)
}

// Options configures a library Scan call.
type Options struct {
	Mode     ScanMode
	ProbeURL string
	Mutate   string
	Insecure bool
}

// Scan runs a coherence scan.
func Scan(ctx context.Context, p *Profile, mode ScanMode, probeURL, mutate string) (*Report, error) {
	return ScanWithOptions(ctx, p, Options{Mode: mode, ProbeURL: probeURL, Mutate: mutate})
}

// ScanWithOptions runs a coherence scan with full options (including Insecure).
func ScanWithOptions(ctx context.Context, p *Profile, opts Options) (*Report, error) {
	return scan.Run(ctx, scan.Options{
		Profile:  p,
		Mode:     opts.Mode,
		ProbeURL: opts.ProbeURL,
		Mutate:   opts.Mutate,
		Insecure: opts.Insecure,
	})
}
