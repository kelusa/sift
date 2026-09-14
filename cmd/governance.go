package cmd

import (
	"context"
	"os"
	"strings"

	"sift/audit"
	"sift/audit/aws/governance"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"
)

var (
	govServices string
	govCheck    string
)

var governanceCmd = &cobra.Command{
	Use:   "governance",
	Short: "Audit governance compliance (tagging, naming)",
	Run: func(cmd *cobra.Command, args []string) {
		if govCheck != "" {
			checksCtxOverride = strings.Split(govCheck, ",")
		}

		var services []string
		if govServices != "" {
			services = strings.Split(govServices, ",")
		}

		runAudit(
			"governance",
			"",
			nil,
			func(ctx context.Context, cfg aws.Config, _ []string) ([]audit.Finding, error) {
				return governance.Audit(ctx, cfg, services)
			},
		)

		if exitCode != 0 {
			os.Exit(exitCode)
		}
	},
}

func init() {
	governanceCmd.Flags().
		StringVar(&govServices, "service", "", "Comma-separated AWS services to scope (e.g., ec2,rds,s3)")
	governanceCmd.Flags().
		StringVar(&govCheck, "check", "", "Comma-separated governance checks (e.g., tagging)")
	awsCmd.AddCommand(governanceCmd)
}
