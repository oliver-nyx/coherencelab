package scan

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/coherencelab/coherencelab/internal/profile"
)

func loadChrome(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.Load(filepath.Join("..", "..", "profiles", "chrome-131-win.yaml"))
	if err != nil {
		t.Skip(err)
	}
	return p
}

func TestLocalScanCoherent(t *testing.T) {
	p := loadChrome(t)
	rep, err := Run(context.Background(), Options{Profile: p, Mode: ModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result.CriticalFails > 0 {
		t.Fatalf("coherent local scan should not have critical fails: %+v", rep.Result.FailedFindings)
	}
	if rep.Result.Percentage < 80 {
		t.Fatalf("expected high score, got %.1f", rep.Result.Percentage)
	}
}

func TestMutateWrongPlatform(t *testing.T) {
	p := loadChrome(t)
	rep, err := Run(context.Background(), Options{Profile: p, Mode: ModeMutate, Mutate: "wrong-platform"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result.CriticalFails == 0 {
		t.Fatal("expected critical failure for platform mismatch")
	}
	if rep.Result.Grade != "F" {
		t.Fatalf("expected grade F, got %s", rep.Result.Grade)
	}
}

func TestMutateWrongBrowser(t *testing.T) {
	p := loadChrome(t)
	rep, err := Run(context.Background(), Options{Profile: p, Mode: ModeMutate, Mutate: "wrong-browser"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result.Failed == 0 {
		t.Fatal("expected failures for browser mismatch")
	}
}
