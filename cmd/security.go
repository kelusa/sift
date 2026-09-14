package cmd

import (
	"fmt"
	"os"
	"sort"

	"sift/audit"
	"sift/audit/history"
	"sift/audit/security"

	"github.com/spf13/cobra"
)

var (
	securityServices string
	secGroupBy       string
)

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Audit AWS resource security posture",
	Run: func(cmd *cobra.Command, args []string) {
		runAudit("security", securityServices, audit.ValidServices(security.Module), security.Audit)
		if secGroupBy != "" {
			printSecurityGroupBy(secGroupBy)
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	},
}

func printSecurityGroupBy(tagKey string) {
	db, err := history.OpenDB()
	if err != nil {
		return
	}
	defer db.Close()

	findings, err := db.Query("", "", "", "security", profile)
	if err != nil || len(findings) == 0 {
		return
	}

	type group struct {
		name     string
		total    int
		critical int
		high     int
	}

	groups := map[string]*group{}
	for _, f := range findings {
		if f.Status == "PASS" {
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
		g.total++
		switch f.RiskLevel {
		case "CRITICAL":
			g.critical++
		case "HIGH":
			g.high++
		}
	}

	var sorted []*group
	for _, g := range groups {
		sorted = append(sorted, g)
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].critical != sorted[j].critical {
			return sorted[i].critical > sorted[j].critical
		}
		return sorted[i].total > sorted[j].total
	})

	fmt.Fprintf(os.Stderr, "\nFINDINGS BY%s:\n", tagKey)
	for _, g := range sorted {
		detail := fmt.Sprintf("%d issues", g.total)
		if g.critical > 0 || g.high > 0 {
			detail += " ("
			if g.critical > 0 {
				detail += fmt.Sprintf("%d CRITICAL", g.critical)
				if g.high > 0 {
					detail += ", "
				}
			}
			if g.high > 0 {
				detail += fmt.Sprintf("%d issues", g.total)
				if g.critical > 0 || g.high > 0 {
					detail += " ("
					if g.critical > 0 {
						detail += fmt.Sprintf("%d CRITICAL", g.critical)
						if g.high > 0 {
							detail += ", "
						}
					}
					if g.high > 0 {
						detail += fmt.Sprintf("%d HIGH", g.high)
					}
					detail += ")"
				}
			}
			fmt.Fprintf(os.Stderr, "  %-24s %s\n", g.name, detail)
		}
	}
}

func init() {
	securityCmd.Flags().
		StringVar(&securityServices, "service", "", serviceUsage(audit.ValidServices(security.Module)))
	securityCmd.Flags().
		StringVar(&secGroupBy, "group-by", "", "Group findings by tag key (e.g., Project, Team)")
	awsCmd.AddCommand(securityCmd)
}
