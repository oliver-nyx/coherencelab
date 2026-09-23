package scan

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/oliver-nyx/coherencelab/internal/profile"
	"github.com/oliver-nyx/coherencelab/internal/score"
)

func TestAllProfilesCoherentLocally(t *testing.T) {
	dir := filepath.Join("..", "..", "profiles")
	profiles, err := profile.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) < 17 {
		t.Fatalf("expected at least 17 profiles, got %d", len(profiles))
	}

	ctx := context.Background()
	for _, p := range profiles {
		t.Run(p.ID, func(t *testing.T) {
			rep, err := Run(ctx, Options{Profile: p, Mode: ModeLocal})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Result.CriticalFails > 0 {
				t.Fatalf("critical failures: %+v", rep.Result.FailedFindings)
			}
			if rep.Result.Grade != score.GradeExcellent {
				t.Fatalf("grade %s (%.1f%%), failures: %d", rep.Result.Grade, rep.Result.Percentage, rep.Result.Failed)
			}
		})
	}
}
