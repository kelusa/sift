package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/history"
	"sift/audit/progress"
	"sift/audit/security"
	"sift/audit/triage"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"
)

var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Issue triage: posture correlation or incident investigation",
}

// `posture` subcommand
var triagePostureCmd = &cobra.Command{
	Use:   "posture",
	Short: "Correlate findings across modules and rank by impact",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := history.OpenDB()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer db.Close()

		var profiles []string
		if cmd.Flags().Changed("profile") {
			profiles = strings.Split(profile, ",")
		} else {
			scans, _ := db.RecentScans(100)
			seen := map[string]bool{}
			for _, s := range scans {
				if !seen[s.Profile] {
					seen[s.Profile] = true
					profiles = append(profiles, s.Profile)
				}
			}
		}

		var allFindings []audit.Finding
		for _, p := range profiles {
			for _, mod := range []string{"security", "cost", "governance"} {
				_, findings, err := db.LatestScan("aws", strings.TrimSpace(p), mod)
				if err != nil {
					continue
				}
				for i := range findings {
					findings[i].Module = mod
					findings[i].Profile = strings.TrimSpace(p)
				}
				allFindings = append(allFindings, findings...)
			}
		}

		issues := triage.Triage(allFindings)
		triage.RenderTextOutput(os.Stdout, issues, profiles)
	},
}

// `incident` subcommand
var triageIncidentCmd = &cobra.Command{
	Use:   "incident",
	Short: "Investigate a specific service during an incident",
}

// `incident` EC2
var (
	triageLogGroup string
	triageInstance string
)

var triageIncidentEC2Cmd = &cobra.Command{
	Use:   "ec2",
	Short: "Deep EC2 investigation: posture + IAM + flow logs",
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		ctx, configs, cancel, err := buildAWSConfigs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer cancel()
		if !showProgress {
			ctx = progress.WithQuiet(ctx, true)
		}
		var mu sync.Mutex
		var allResults []audit.Finding
		var wg sync.WaitGroup
		for _, cfg := range configs {
			slog.Info("scanning region", "region", cfg.Region)
			wg.Add(1)
			go func(cfg aws.Config) {
				defer wg.Done()
				var targets []security.TriageTarget
				if triageInstance != "" {
					t, err := security.ListEC2TargetByID(ctx, cfg, triageInstance)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error in %s: %v\n", cfg.Region, err)
						return
					}
					targets = []security.TriageTarget{*t}
				} else {
					var err error
					targets, err = security.ListEC2Targets(ctx, cfg)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error in %s: %v\n", cfg.Region, err)
						return
					}
				}
				results, err := triage.Run(ctx, cfg, triageLogGroup, targets)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error in %s: %v\n", cfg.Region, err)
					return
				}
				baselineResults, err := security.AuditBaseline(ctx, cfg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Baseline check error in %s: %v\n", cfg.Region, err)
				} else {
					results = append(results, baselineResults...)
				}

				for i := range results {
					results[i].Region = cfg.Region
				}
				mu.Lock()
				allResults = append(allResults, results...)
				mu.Unlock()
			}(cfg)
		}
		wg.Wait()
		if err := audit.OutputWithFilter(format, allResults, riskLevel, sortBy, start, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		if audit.HasHighRiskFindings(allResults) {
			os.Exit(1)
		}
	},
}

func init() {
	triageIncidentEC2Cmd.Flags().
		StringVar(&triageLogGroup, "log-group", "", "VPC flow log group name (required)")
	triageIncidentEC2Cmd.Flags().
		StringVar(&triageInstance, "instance", "", "Specific EC2 instance ID")
	triageIncidentEC2Cmd.MarkFlagRequired("log-group")

	triageIncidentCmd.AddCommand(triageIncidentEC2Cmd)
	triageCmd.AddCommand(triagePostureCmd, triageIncidentCmd)
	awsCmd.AddCommand(triageCmd)
}
