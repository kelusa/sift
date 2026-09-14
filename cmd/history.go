package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"sift/audit"
	"sift/audit/history"

	"github.com/spf13/cobra"
)

var (
	historyFinding string
	historyService string
	historyRisk    string
	historyLast    int
	historyModule  string
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Query scan history from local database",
	Run: func(cmd *cobra.Command, args []string) {
		histProfile := account
		db, err := history.OpenDB()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer db.Close()

		switch {
		case historyFinding != "":
			findings, err := db.FindingHistory(historyFinding)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			if len(findings) == 0 {
				fmt.Fprintf(os.Stderr, "No history found for finding %s\n", historyFinding)
				return
			}
			output(findings)

		case historyLast > 0:
			scans, err := db.RecentScans(historyLast)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			if format == "json" {
				b, _ := json.MarshalIndent(scans, "", "  ")
				fmt.Println(string(b))
			} else {
				fmt.Printf("  %-20s  %-10s  %-10s  %s\n", "TIMESTAMP", "COMMAND", "PROFILE", "REGION")
				for _, s := range scans {
					fmt.Printf("  %-20s  %-10s  %-10s  %s\n",
						s.Timestamp.Format("2006-01-02 15:04:05"),
						s.Command, s.Profile, s.Region)
				}
			}

		default:
			// show latest scan for both 'history' and 'cost'
			var findings []audit.Finding
			if historyModule != "" {
				findings, err = db.Query(
					providerFilter,
					historyService,
					historyRisk,
					"",
					historyModule,
					histProfile,
				)
			} else {
				for _, mod := range []string{"security", "cost"} {
					f, e := db.Query(providerFilter, historyService, historyRisk, "", mod, histProfile)
					if e != nil {
						err = e
						break
					}
					findings = append(findings, f...)
				}
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			if len(findings) == 0 {
				fmt.Fprintln(os.Stderr, "No findings found.")
				return
			}
			output(findings)
		}
	},
}

func output(findings []audit.Finding) {
	if format == "json" {
		b, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("  %-16s  %-10s  %-10s  %-8s  %-30s  %s\n", "ID", "MODULE", "SERVICE", "RISK", "RESOURCE", "CHECK")
		for _, f := range findings {
			fmt.Printf("  %-16s  %-10s  %-10s  %-8s  %-30s  %s\n",
				f.ID, f.Module, f.Service, f.RiskLevel, truncateStr(f.ResourceID, 30), f.Check)
		}
	}
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func init() {
	historyCmd.Flags().
		StringVar(&historyFinding, "finding", "", "Show history for a specific finding ID")
	historyCmd.Flags().StringVar(&historyService, "service", "", "Filter by service")
	historyCmd.Flags().StringVar(&historyRisk, "risk", "", "Filter by risk level")
	historyCmd.Flags().IntVar(&historyLast, "last", 0, "Show last N scans")
	historyCmd.Flags().StringVar(&historyModule, "module", "", "Filter by module (security, cost)")
	addFilterFlags(historyCmd.Flags())
	rootCmd.AddCommand(historyCmd)
}
