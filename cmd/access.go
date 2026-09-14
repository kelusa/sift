package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"sift/audit/access"

	"github.com/spf13/cobra"
)

var accessDays int

var accessCmd = &cobra.Command{
	Use:   "access <service>",
	Short: "Audit who is accessing a service via CloudTrail",
	Long: "Query CloudTrail to show which principals access a service, what operations they perform, and when. \n\nAvailable services:\n " +
		strings.Join(
			access.Services(),
			", ",
		),
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		service := args[0]

		ctx, cfg, cancel, err := buildAWSConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer cancel()

		result, err := access.Audit(ctx, cfg, service, accessDays)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		if len(result.Principals) == 0 {
			fmt.Printf("No access events found for %s in the last %d days.\n", service, accessDays)
			return
		}

		out := os.Stdout
		if outputFile != "" {
			f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			defer f.Close()
			out = f
		}

		switch format {
		case "json":
			writeAccessJSON(out, result)
		case "csv":
			writeAccessCSV(out, result)
		default:
			writeAccessTable(out, result)
		}
	},
}

func writeAccessTable(out io.Writer, result *access.Result) {
	fmt.Fprintf(out, "Access audit: %s (last %d days)\n\n", result.Service, result.Days)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PRINCIPAL\tOPERATIONS\tCOUNT\tLAST_ACCESS")
	for _, p := range result.Principals {
		ops := topOperations(p.Operations, 5)
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n",
			p.ARN,
			ops,
			p.Count,
			p.LastAccess.Format("2006-01-02"),
		)
	}
	w.Flush()
	fmt.Fprintf(out, "\nTotal principals: %d\n", len(result.Principals))
}

func writeAccessCSV(out io.Writer, result *access.Result) {
	fmt.Fprintln(out, "principal,operations,count,last_access")
	for _, p := range result.Principals {
		ops := topOperations(p.Operations, 0)
		fmt.Fprintf(out, "\"%s\",\"%s\",%d,%s\n",
			p.ARN,
			ops,
			p.Count,
			p.LastAccess.Format(time.RFC3339),
		)
	}
}

func writeAccessJSON(out io.Writer, result *access.Result) {
	type jsonPrincipal struct {
		Principal  string         `json:"principal"`
		Operations map[string]int `json:"operations"`
		Count      int            `json:"count"`
		LastAccess string         `json:"last_access"`
	}
	type jsonResult struct {
		Service    string          `json:"service"`
		Days       int             `json:"days"`
		Principals []jsonPrincipal `json:"principals"`
	}

	jr := jsonResult{Service: result.Service, Days: result.Days}
	for _, p := range result.Principals {
		jr.Principals = append(jr.Principals, jsonPrincipal{
			Principal:  p.ARN,
			Operations: p.Operations,
			Count:      p.Count,
			LastAccess: p.LastAccess.Format(time.RFC3339),
		})
	}

	b, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Fprintln(out, string(b))
}

func topOperations(ops map[string]int, limit int) string {
	type opCount struct {
		name  string
		count int
	}
	var sorted []opCount
	for k, v := range ops {
		sorted = append(sorted, opCount{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	if limit > 0 && len(sorted) > limit {
		sorted = sorted[:limit]
	}
	var names []string
	for _, o := range sorted {
		names = append(names, o.name)
	}
	return strings.Join(names, ", ")
}

func init() {
	accessCmd.Flags().IntVar(&accessDays, "days", 30, "Number of days to look back")
	awsCmd.AddCommand(accessCmd)
}
