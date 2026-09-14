package cmd

import "github.com/spf13/pflag"

// Shared filter flags for the cross-provider commands (report, history, ai).
// These filter previously-stored findings rather than selecting live
// credentials: --provider selects the source cloud (aws|aria), --account
// selects the stored scan identity (an AWS profile, an Aria host, ...).
// Empty values mean "all".
var (
	providerFilter string
	account        string
)

// addFilterFlags wires --provider/--account onto a cross-provider command.
func addFilterFlags(flags *pflag.FlagSet) {
	flags.StringVar(&providerFilter, "provider", "", "Filter stored findings by provider (aws|aria). Default: all")
	flags.StringVar(&account, "account", "", "Filter stored findings by account/identity. Default: all")
}
