package cmd

import (
	"os"
	"strings"

	"sift/audit"
	"sift/audit/aws/ops"

	"github.com/spf13/cobra"
)

var (
	opsServices string
	opsCheck    string
)

var opsCmd = &cobra.Command{
	Use:   "ops",
	Short: "Audit operational risks and service limits",
	Run: func(cmd *cobra.Command, args []string) {
		if opsCheck != "" {
			checksCtxOverride = strings.Split(opsCheck, ",")
		}

		runAudit("ops", opsServices, audit.ValidServices("aws", ops.Module), ops.Audit)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	},
}

func init() {
	opsCmd.Flags().
		StringVar(&opsServices, "service", "", serviceUsage(audit.ValidServices("aws", ops.Module)))
	opsCmd.Flags().StringVar(&opsCheck, "check", "", "Comma-separated checks within a service")
	awsCmd.AddCommand(opsCmd)
}
