package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sift/audit"
	"sift/audit/history"
)

func Build(db *history.DB, provider string, profiles []string) *ReportData {
	r := &ReportData{
		Profiles: profiles,
		Risks:    make(map[string]int),
	}

	// Gather findings
	var allFindings []audit.Finding
	for _, p := range profiles {
		for _, mod := range []string{"security", "cost", "governance"} {
			meta, findings, err := db.LatestScan(provider, strings.TrimSpace(p), mod)
			if err != nil || meta == nil {
				continue
			}
			if r.Timestamp == "" || meta.Timestamp.Format("2006-01-02 15:04") > r.Timestamp {
				r.Timestamp = meta.Timestamp.Format("2006-01-02 15:04")
			}
			for i := range findings {
				findings[i].Module = mod
				findings[i].Profile = strings.TrimSpace(p)
			}
			allFindings = append(allFindings, findings...)
		}
	}

	// Issues (non-PASS)
	var issues []audit.Finding
	for _, f := range allFindings {
		if f.Status != "PASS" {
			if strings.HasPrefix(f.Detail, "audit failed:") {
				continue
			}
			issues = append(issues, f)
			r.Risks[f.RiskLevel]++
			r.TotalWaste += f.EstimatedMonthlyCost
		}
	}

	// Top issues per module
	var secIssues, costIssues []audit.Finding
	for _, f := range issues {
		switch f.Module {
		case "security":
			secIssues = append(secIssues, f)
		case "cost":
			costIssues = append(costIssues, f)
		}
	}
	sortByRisk := func(s []audit.Finding) {
		sort.Slice(s, func(i, j int) bool {
			ri := riskOrd(s[i].RiskLevel)
			rj := riskOrd(s[j].RiskLevel)
			if ri != rj {
				return ri > rj
			}
			return s[i].EstimatedMonthlyCost > s[j].EstimatedMonthlyCost
		})
	}
	sortByRisk(secIssues)
	sortByRisk(costIssues)
	if len(secIssues) > 5 {
		secIssues = secIssues[:5]
	}
	if len(costIssues) > 5 {
		costIssues = costIssues[:5]
	}
	r.TopSecurity = secIssues
	r.TopCost = costIssues

	// Health score
	totalResources := map[string]bool{}
	var penalty float64
	for _, f := range allFindings {
		if f.ResourceID == "" {
			continue
		}
		totalResources[f.ResourceID] = true
		switch f.RiskLevel {
		case "CRITICAL":
			penalty += 4
		case "HIGH":
			penalty += 3
		case "MEDIUM":
			penalty += 2
		case "LOW":
			penalty += 1
		}
	}
	if len(totalResources) > 0 {
		maxPenalty := float64(len(totalResources)) * 4
		r.HealthScore = 100 - (penalty/maxPenalty)*100
		if r.HealthScore < 0 {
			r.HealthScore = 0
		}
	}

	// Trend
	var prevFindings []audit.Finding
	for _, p := range profiles {
		for _, mod := range []string{"security", "cost", "governance"} {
			_, prev, _ := db.PreviousScan(strings.TrimSpace(p), mod)
			if prev != nil {
				for i := range prev {
					prev[i].Profile = strings.TrimSpace(p)
				}
				prevFindings = append(prevFindings, prev...)
			}
		}
	}
	if len(prevFindings) > 0 {
		d := history.ComputeDiff(prevFindings, allFindings)
		r.Trend = &Trend{
			New:           len(d.New),
			Resolved:      len(d.Resolved),
			Ongoing:       len(d.Ongoing),
			NewItems:      d.New,
			ResolvedItems: d.Resolved,
			OngoingItems:  d.Ongoing,
		}
	}

	// Compliance
	for _, mod := range []string{"security", "cost", "governance"} {
		resources := map[string]bool{}
		nonCompliant := map[string]bool{}
		for _, f := range allFindings {
			if f.Module != mod || f.ResourceID == "" {
				continue
			}
			resources[f.ResourceID] = true
			if f.Status != "PASS" {
				nonCompliant[f.ResourceID] = true
			}
		}
		total := len(resources)
		if total > 0 {
			compliant := total - len(nonCompliant)
			label := mod
			if mod == "governance" {
				label = "tagging"
			}
			r.Compliance = append(r.Compliance, ComplianceScore{
				Label:     label,
				Percent:   float64(compliant) / float64(total) * 100,
				Compliant: compliant,
				Total:     total,
			})
		}
	}

	// Aging
	r.Aging, _ = db.AgingFindings(7)

	// Cost attribution
	costTags := []string{"Project"}
	if home, err := os.UserHomeDir(); err == nil {
		if data, err := os.ReadFile(filepath.Join(home, ".sift", "tagging.json")); err == nil {
			var tc struct {
				CostTags []string `json:"cost_tags"`
			}
			if json.Unmarshal(data, &tc) == nil && len(tc.CostTags) > 0 {
				costTags = tc.CostTags
			}
		}
	}

	var totalCostAttr, attrCost float64
	var fullyTagged, partiallyTagged, untagged int
	for _, f := range allFindings {
		if f.Module != "cost" || f.Status == "PASS" {
			continue
		}
		totalCostAttr += f.EstimatedMonthlyCost
		if len(f.Tags) == 0 {
			untagged++
			continue
		}
		hasAll := true
		hasAny := false
		for _, tag := range costTags {
			if _, ok := f.Tags[tag]; ok {
				hasAny = true
			} else {
				hasAll = false
			}
		}
		if hasAll {
			fullyTagged++
			attrCost += f.EstimatedMonthlyCost
		} else if hasAny {
			partiallyTagged++
			attrCost += f.EstimatedMonthlyCost
		} else {
			untagged++
		}
	}
	total := fullyTagged + partiallyTagged + untagged
	if total > 0 {
		r.CostAttribution = &CostAttribution{
			Tags:            costTags,
			TotalCost:       totalCostAttr,
			AttributedCost:  attrCost,
			FullyTagged:     fullyTagged,
			PartiallyTagged: partiallyTagged,
			Untagged:        untagged,
			TotalResources:  total,
		}

		// Breakdown by first cost tag value
		tagKey := costTags[0]
		valCosts := map[string]float64{}
		valCounts := map[string]int{}
		for _, f := range allFindings {
			if f.Module != "cost" || f.Status == "PASS" || f.EstimatedMonthlyCost == 0 {
				continue
			}
			val := f.Tags[tagKey]
			if val == "" {
				val = "(untagged)"
			}
			valCosts[val] += f.EstimatedMonthlyCost
			valCounts[val]++
		}
		for val, cost := range valCosts {
			pct := 0.0
			if totalCostAttr > 0 {
				pct = cost / totalCostAttr * 100
			}
			r.CostAttribution.ByValue = append(r.CostAttribution.ByValue, TagValueCost{
				Value:   val,
				Cost:    cost,
				Percent: pct,
				Count:   valCounts[val],
			})
		}
		sort.Slice(r.CostAttribution.ByValue, func(i, j int) bool {
			return r.CostAttribution.ByValue[i].Cost > r.CostAttribution.ByValue[j].Cost
		})
	}

	// Security attribution by tags
	secByVal := map[string]*TagValueSecurity{}
	var totalSecIssues int
	var secFullyTagged, secPartiallyTagged, secUntagged int
	for _, f := range issues {
		if f.Module != "security" {
			continue
		}
		totalSecIssues++
		if len(f.Tags) == 0 {
			secUntagged++
		} else {
			hasAll := true
			hasAny := false
			for _, tag := range costTags {
				if _, ok := f.Tags[tag]; ok {
					hasAny = true
				} else {
					hasAll = false
				}
			}
			if hasAll {
				secFullyTagged++
			} else if hasAny {
				secPartiallyTagged++
			} else {
				secUntagged++
			}
		}
		val := "(untagged)"
		for _, tag := range costTags {
			if v, ok := f.Tags[tag]; ok && v != "" {
				val = v
				break
			}
		}
		sv, ok := secByVal[val]
		if !ok {
			sv = &TagValueSecurity{Value: val}
			secByVal[val] = sv
		}
		sv.Count++
		switch f.RiskLevel {
		case "CRITICAL":
			sv.Critical++
		case "HIGH":
			sv.High++
		}
	}
	if totalSecIssues > 0 {
		var secVals []TagValueSecurity
		for _, sv := range secByVal {
			sv.Percent = float64(sv.Count) / float64(totalSecIssues) * 100
			secVals = append(secVals, *sv)
		}
		sort.Slice(secVals, func(i, j int) bool { return secVals[i].Count > secVals[j].Count })
		r.SecurityAttribution = &SecurityAttribution{
			Tags:            costTags,
			FullyTagged:     secFullyTagged,
			PartiallyTagged: secPartiallyTagged,
			Untagged:        secUntagged,
			TotalResources:  totalSecIssues,
			ByValue:         secVals,
		}
	}

	// Services
	svcCounts := map[string]int{}
	for _, f := range issues {
		svcCounts[f.Service]++
	}
	for k, v := range svcCounts {
		r.Services = append(r.Services, ServiceCount{k, v})
	}
	sort.Slice(r.Services, func(i, j int) bool { return r.Services[i].Count > r.Services[j].Count })

	// Spend overview from Cost Explorer data
	if len(costTags) > 0 {
		spendRows, _ := db.GetSpend(profiles, costTags[0])
		if len(spendRows) > 0 {
			for _, sr := range spendRows {
				r.SpendOverview = append(r.SpendOverview, SpendByTag{
					Value: sr.TagValue,
					Spend: sr.Spend,
				})
			}
			sort.Slice(r.SpendOverview, func(i, j int) bool {
				return r.SpendOverview[i].Spend > r.SpendOverview[j].Spend
			})
		}
	}

	// Spend by service
	svcRows, _ := db.GetSpend(profiles, "__SERVICE__")
	if len(svcRows) > 0 {
		for _, sr := range svcRows {
			r.SpendByService = append(r.SpendByService, SpendByTag{
				Value: sr.TagValue,
				Spend: sr.Spend,
			})
		}
		sort.Slice(r.SpendByService, func(i, j int) bool {
			return r.SpendByService[i].Spend > r.SpendByService[j].Spend
		})
	}

	return r
}

func riskOrd(level string) int {
	switch level {
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
