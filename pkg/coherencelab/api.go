// Package coherencelab provides the public API for browser identity coherence validation.
package coherencelab

import (
	"context"

	"github.com/coherencelab/coherencelab/internal/profile"
	"github.com/coherencelab/coherencelab/internal/scan"
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
)

// LoadProfile loads a profile from a YAML file.
func LoadProfile(path string) (*Profile, error) {
	return profile.Load(path)
}

// LoadProfiles loads all profiles from a directory.
func LoadProfiles(dir string) ([]*Profile, error) {
	return profile.LoadDir(dir)
}

// Scan runs a coherence scan.
func Scan(ctx context.Context, p *Profile, mode ScanMode, probeURL, mutate string) (*Report, error) {
	return scan.Run(ctx, scan.Options{
		Profile:  p,
		Mode:     mode,
		ProbeURL: probeURL,
		Mutate:   mutate,
	})
}
