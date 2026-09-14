package cmd

import (
	"fmt"
	"os"
	"strings"

	"sift/audit/history"
	"sift/audit/report"

	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Executive summary of latest scan findings",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := history.OpenDB()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer db.Close()

		// Determine accounts (stored scan identity). --account filters; empty
		// means "all accounts seen in history".
		var profiles []string
		if account != "" {
			profiles = strings.Split(account, ",")
		} else {
			scans, _ := db.RecentScans(100)
			seen := map[string]bool{}
			for _, s := range scans {
				if providerFilter != "" && s.Provider != providerFilter {
					continue
				}
				if !seen[s.Profile] {
					seen[s.Profile] = true
					profiles = append(profiles, s.Profile)
				}
			}
		}

		r := report.Build(db, providerFilter, profiles)
		if r.Timestamp == "" {
			fmt.Fprintln(os.Stderr, "No scan data found. Run sift security/cost first.")
			os.Exit(2)
		}

		useAI, _ := cmd.Flags().GetBool("ai")
		if useAI {
			if err := report.Enrich(r); err != nil {
				fmt.Fprintf(os.Stderr, "AI enrichment failed: %v\n", err)
			}
		}

		out := os.Stdout
		if outputFile != "" {
			f, err := os.Create(outputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			defer f.Close()
			out = f
		}

		switch format {
		case "html":
			if err := report.RenderHTML(out, r); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
		case "json":
			report.RenderJSON(out, r)
		default:
			report.RenderText(out, r)
		}
	},
}

func init() {
	reportCmd.Flags().
		Bool("ai", false, "Enrich report with AI-generated summary and recommendations")
	addFilterFlags(reportCmd.Flags())
	rootCmd.AddCommand(reportCmd)
}
