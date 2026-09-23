package score

import (
	"sort"

	"github.com/oliver-nyx/coherencelab/internal/rules"
)

// Grade represents an overall coherence grade.
type Grade string

const (
	GradeExcellent Grade = "A"
	GradeGood      Grade = "B"
	GradeFair      Grade = "C"
	GradePoor      Grade = "D"
	GradeFail      Grade = "F"
)

// Result is the scored output of a coherence scan.
type Result struct {
	Score           int             `json:"score"`
	MaxScore        int             `json:"max_score"`
	Percentage      float64         `json:"percentage"`
	Grade           Grade           `json:"grade"`
	Passed          int             `json:"passed"`
	Failed          int             `json:"failed"`
	Skipped         int             `json:"skipped"`
	CriticalFails   int             `json:"critical_fails"`
	Findings        []rules.Finding `json:"findings"`
	FailedFindings  []rules.Finding `json:"failed_findings"`
	CategoryScores  map[string]int  `json:"category_scores"`
	CategoryMax     map[string]int  `json:"category_max"`
}

// Compute scores findings into a result.
func Compute(findings []rules.Finding) Result {
	var totalWeight, earned int
	passed, failed, skipped, critical := 0, 0, 0, 0
	catScores := make(map[string]int)
	catMax := make(map[string]int)
	var failedFindings []rules.Finding

	for _, f := range findings {
		if f.Weight == 0 && f.Severity == rules.SeverityInfo {
			skipped++
			continue
		}
		totalWeight += f.Weight
		catMax[string(f.Category)] += f.Weight
		if f.Passed {
			passed++
			earned += f.Weight
			catScores[string(f.Category)] += f.Weight
		} else {
			failed++
			if f.Severity == rules.SeverityCritical {
				critical++
			}
			failedFindings = append(failedFindings, f)
		}
	}

	sort.Slice(failedFindings, func(i, j int) bool {
		if failedFindings[i].Severity == failedFindings[j].Severity {
			return failedFindings[i].Weight > failedFindings[j].Weight
		}
		return severityRank(failedFindings[i].Severity) > severityRank(failedFindings[j].Severity)
	})

	pct := 100.0
	if totalWeight > 0 {
		pct = float64(earned) / float64(totalWeight) * 100
	}

	return Result{
		Score:          earned,
		MaxScore:       totalWeight,
		Percentage:     pct,
		Grade:          gradeFor(pct, critical),
		Passed:         passed,
		Failed:         failed,
		Skipped:        skipped,
		CriticalFails:  critical,
		Findings:       findings,
		FailedFindings: failedFindings,
	 CategoryScores:  catScores,
		CategoryMax:     catMax,
	}
}

func gradeFor(pct float64, critical int) Grade {
	if critical > 0 {
		return GradeFail
	}
	switch {
	case pct >= 95:
		return GradeExcellent
	case pct >= 85:
		return GradeGood
	case pct >= 70:
		return GradeFair
	case pct >= 55:
		return GradePoor
	default:
		return GradeFail
	}
}

func severityRank(s rules.Severity) int {
	switch s {
	case rules.SeverityCritical:
		return 5
	case rules.SeverityHigh:
		return 4
	case rules.SeverityMedium:
		return 3
	case rules.SeverityLow:
		return 2
	default:
		return 1
	}
}
