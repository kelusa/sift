package triage

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"sift/audit"
)

// Issue represnets a correlated set of findings for a single resource.
type Issue struct {
	ResourceID string
	Service    string
	Profile    string
	RiskLevel  string
	Tags       map[string]string
	Security   []audit.Finding
	Cost       []audit.Finding
	Governance []audit.Finding
	TotalWaste float64
	Score      int
	QuickWin   bool
	Actions    []string
	FixRisk    string
}

// Triage correlates finfindgs by resource and ranks them.
func Triage(findings []audit.Finding) []Issue {
	// Group by resource
	grouped := map[string]*Issue{}
	for _, f := range findings {
		if f.Status == "PASS" || f.ResourceID == "" {
			continue
		}
		if strings.HasPrefix(f.Detail, "audit failed:") {
			continue
		}
		key := f.Service + "/" + f.ResourceID
		issue, ok := grouped[key]
		if !ok {
			issue = &Issue{
				ResourceID: f.ResourceID,
				Service:    f.Service,
				Profile:    f.Profile,
				Tags:       f.Tags,
			}
			grouped[key] = issue
		}
		switch f.Module {
		case "security":
			issue.Security = append(issue.Security, f)
		case "cost":
			issue.Cost = append(issue.Cost, f)
			issue.TotalWaste += f.EstimatedMonthlyCost
		case "governance":
			issue.Governance = append(issue.Governance, f)
		}
	}

	// Score and rank
	var issues []Issue
	for _, issue := range grouped {
		issue.RiskLevel = highestRisk(issue)
		issue.Score = computeScore(issue)
		issue.QuickWin = isQuickWin(issue)
		issue.FixRisk = computeFixRisk(issue)
		issue.Actions = buildActions(issue)
		issues = append(issues, *issue)
	}

	sort.Slice(issues, func(i, j int) bool {
		return issues[i].Score > issues[j].Score
	})

	return issues
}

func highestRisk(issue *Issue) string {
	best := 0
	for _, f := range issue.Security {
		if r := riskOrd(f.RiskLevel); r > best {
			best = r
		}
	}
	for _, f := range issue.Cost {
		if r := riskOrd(f.RiskLevel); r > best {
			best = r
		}
	}
	for _, f := range issue.Governance {
		if r := riskOrd(f.RiskLevel); r > best {
			best = r
		}
	}
	switch best {
	case 4:
		return "CRITICAL"
	case 3:
		return "HIGH"
	case 2:
		return "MEDIUM"
	case 1:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

func computeScore(issue *Issue) int {
	score := 0
	// Risk weight
	switch issue.RiskLevel {
	case "CRITICAL":
		score += 100
	case "HIGH":
		score += 60
	case "MEDIUM":
		score += 30
	case "LOW":
		score += 10
	}
	// Multi-module bonus (correlated issues are worse)
	modules := 0
	if len(issue.Security) > 0 {
		modules++
	}
	if len(issue.Cost) > 0 {
		modules++
	}
	if len(issue.Governance) > 0 {
		modules++
	}
	score += modules * 15

	// Cost impact
	if issue.TotalWaste > 100 {
		score += 20
	} else if issue.TotalWaste > 0 {
		score += 10
	}

	// Production blast radius
	if issue.Tags != nil {
		env := strings.ToLower(issue.Tags["Environment"])
		if env == "production" || env == "prod" || env == "prd" {
			score += 30
		}
	}

	return score
}

func isQuickWin(issue *Issue) bool {
	// Quick win: all remediations are low action_risk
	for _, f := range issue.Security {
		if f.Remediation != nil && strings.ToUpper(f.Remediation.ActionRisk) != "LOW" {
			return false
		}
	}
	for _, f := range issue.Cost {
		if f.Remediation != nil && strings.ToUpper(f.Remediation.ActionRisk) != "LOW" {
			return false
		}
	}
	return true
}

func computeFixRisk(issue *Issue) string {
	highest := "LOW"
	for _, f := range append(issue.Security, issue.Cost...) {
		if f.Remediation != nil {
			r := strings.ToUpper(f.Remediation.ActionRisk)
			if riskOrd(r) > riskOrd(highest) {
				highest = r
			}
		}
	}
	return highest
}

func buildActions(issue *Issue) []string {
	var actions []string
	seen := map[string]bool{}
	for _, f := range append(issue.Security, append(issue.Cost, issue.Governance...)...) {
		if f.Remediation != nil && f.Remediation.Action != "" && !seen[f.Remediation.Action] {
			actions = append(actions, f.Remediation.Action)
			seen[f.Remediation.Action] = true
		}
	}
	return actions
}

func riskOrd(level string) int {
	switch strings.ToUpper(level) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// RenderTextOutput writes the prioritized triage to outputs.
func RenderTextOutput(w io.Writer, issues []Issue, profiles []string) {
	fmt.Fprintf(w, "=== SIFT ISSUE TRIAGE ===\n")
	fmt.Fprintf(
		w,
		"Profiles: %s | %d triaged issues\n\n",
		strings.Join(profiles, ", "),
		len(issues),
	)

	var quickWins, planned int
	var qwSavings, planSavings float64
	for _, issue := range issues {
		if issue.QuickWin {
			quickWins++
			qwSavings += issue.TotalWaste
		} else {
			planned++
			planSavings += issue.TotalWaste
		}
	}

	for i, issue := range issues {
		qw := ""
		if issue.QuickWin {
			qw = "★ QUICK WIN"
		}
		fmt.Fprintf(
			w,
			"#%d [%s] %s/%s%s\n",
			i+1,
			issue.RiskLevel,
			issue.Service,
			issue.ResourceID,
			qw,
		)

		if len(issue.Security) > 0 {
			var details []string
			for _, f := range issue.Security {
				details = append(details, f.Check)
			}
			fmt.Fprintf(w, "  Security: %s\n", strings.Join(details, ", "))
		}
		if len(issue.Cost) > 0 {
			var details []string
			for _, f := range issue.Cost {
				details = append(details, f.Check)
			}
			fmt.Fprintf(
				w,
				"  Cost: %s ($%.0f/mo waste)\n",
				strings.Join(details, ", "),
				issue.TotalWaste,
			)
		}
		if len(issue.Governance) > 0 {
			var details []string
			for _, f := range issue.Governance {
				details = append(details, f.Check)
			}
			fmt.Fprintf(w, "  Governance: %s\n", strings.Join(details, ", "))
		}

		if len(issue.Tags) > 0 {
			var tags []string
			for k, v := range issue.Tags {
				tags = append(tags, k+"="+v)
			}
			fmt.Fprintf(w, "  Tags: %s\n", strings.Join(tags, ", "))
		}

		if len(issue.Actions) > 0 {
			fmt.Fprintf(w, "  Action: %s\n", strings.Join(issue.Actions, " → "))
		}
		fmt.Fprintf(w, "  Risk to fix: %s\n\n", issue.FixRisk)
	}

	fmt.Fprintf(w, "------------------------\n")
	fmt.Fprintf(w, "SUMMARY:\n")
	fmt.Fprintf(w, "  Quick wins:  %d ($%.0f/mo savings, LOW risk)\n", quickWins, qwSavings)
	fmt.Fprintf(w, "  Needs planning: %d ($%.0f/mo savings)\n", planned, planSavings)
}
