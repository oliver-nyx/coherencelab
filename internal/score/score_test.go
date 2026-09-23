package score

import (
	"testing"

	"github.com/oliver-nyx/coherencelab/internal/rules"
)

func TestSkippedFindingsExcludedFromMaxScore(t *testing.T) {
	findings := []rules.Finding{
		{ID: "a", Weight: 10, Passed: true, Severity: rules.SeverityHigh},
		{ID: "b", Weight: 0, Passed: true, Severity: rules.SeverityInfo, Skipped: true},
		{ID: "c", Weight: 12, Passed: true, Severity: rules.SeverityCritical}, // legacy bug restored weight
	}
	// Explicit skipped must not count even if Weight somehow non-zero after bug.
	findings[1].Weight = 12
	res := Compute(findings)
	if res.Skipped != 1 {
		t.Fatalf("Skipped=%d want 1", res.Skipped)
	}
	if res.MaxScore != 22 {
		t.Fatalf("MaxScore=%d want 22 (skipped excluded)", res.MaxScore)
	}
}
