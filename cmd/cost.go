package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"sift/audit"
	"sift/audit/aws/cost"
	"sift/audit/history"

	"github.com/spf13/cobra"
)

var (
	costServices string
	groupBy      string
)

var costCmd = &cobra.Command{
	Use:   "cost",
	Short: "Detect cost waste across AWS resources",
	Run: func(cmd *cobra.Command, args []string) {
		runAudit("cost", costServices, audit.ValidServices(cost.Module), cost.Audit)

		if groupBy != "" {
			printCostGroupBy(groupBy)
		}
		fetchAndSaveSpend()
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	},
}

func printCostGroupBy(tagKey string) {
	db, err := history.OpenDB()
	if err != nil {
		return
	}
	defer db.Close()

	findings, err := db.Query("aws", "", "", "", "cost", profile)
	if err != nil || len(findings) == 0 {
		return
	}

	type group struct {
		name     string
		cost     float64
		findings int
	}

	groups := map[string]*group{}
	for _, f := range findings {
		if f.Status == "PASS" || f.EstimatedMonthlyCost == 0 {
			continue
		}
		val := f.Tags[tagKey]
		if val == "" {
			val = "(untagged)"
		}
		g, ok := groups[val]
		if !ok {
			g = &group{name: val}
			groups[val] = g
		}
		g.cost += f.EstimatedMonthlyCost
		g.findings++
	}

	var sorted []*group
	for _, g := range groups {
		sorted = append(sorted, g)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].cost > sorted[j].cost
	})

	var total float64
	fmt.Fprintf(os.Stderr, "\nCOST BY %s:\n", tagKey)
	for _, g := range sorted {
		fmt.Fprintf(os.Stderr, "  %-24s $%.0f/mo  (%d findings)\n", g.name, g.cost, g.findings)
		total += g.cost
	}
	fmt.Fprintf(os.Stderr, "\n  TOTAL: $%.0f/mo\n", total)
}

func fetchAndSaveSpend() {
	costTags := loadCostTags()
	if len(costTags) == 0 {
		return
	}
	tagKey := costTags[0]

	ctx, configs, cancel, err := buildAWSConfigs()
	if err != nil {
		return
	}
	defer cancel()

	cfg := configs[0] // Cost Explorer is region-agnostic, use first config

	db, err := history.OpenDB()
	if err != nil {
		return
	}
	defer db.Close()

	// Fetch spend by tag
	slog.Info("fetching Cost Explorer spend by tag", "tag", tagKey)
	spend, period, err := cost.FetchSpendByTag(ctx, cfg, tagKey)
	if err != nil {
		slog.Warn("Cost Explorer unavailable", "error", err)
		return
	}
	slog.Info("Cost Explorer data received", "period", period, "groups", len(spend))
	db.SaveSpend(profile, tagKey, spend, period)

	// Fetch spend by service
	slog.Info("fetching Cost Explorer spend by service")
	svcSpend, svcPeriod, err := cost.FetchSpendByService(ctx, cfg)
	if err == nil {
		slog.Info(
			"Cost Explorer service data received",
			"period",
			svcPeriod,
			"services",
			len(svcSpend),
		)
		db.SaveSpend(profile, "__SERVICE__", svcSpend, svcPeriod)
	}
}

func loadCostTags() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(home, ".sift", "tagging.json"))
	if err != nil {
		return nil
	}
	var tc struct {
		CostTags []string `json:"cost_tags"`
	}
	if json.Unmarshal(data, &tc) != nil {
		return nil
	}
	return tc.CostTags
}

func init() {
	costCmd.Flags().
		StringVar(&costServices, "service", "", serviceUsage(audit.ValidServices(cost.Module)))
	costCmd.Flags().
		StringVar(&groupBy, "group-by", "", "Group cost by tag key (e.g., Project, Team)")
	awsCmd.AddCommand(costCmd)
}
