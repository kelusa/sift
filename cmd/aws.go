package cmd

import (
	"github.com/spf13/cobra"

	_ "sift/audit/aws"
)

// awsCmd is the parent for all AWS provider-scoped audit commands.
// AWS-specific flags (--profile, --region) live here so they only appear
// where they are meaningful. Provider-neutral commands (report, history, ai,
// fix) remain at the root level.
var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Audit AWS resources (security, cost, ops, governance, ...)",
}

func init() {
	awsCmd.PersistentFlags().StringVar(&profile, "profile", "default", "AWS profile name")
	awsCmd.PersistentFlags().
		StringVar(&region, "region", "", "AWS region(s), comma-separated or 'all' (default: profile region)")
	rootCmd.AddCommand(awsCmd)
}
