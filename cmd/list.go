package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/aws/list"
	"sift/audit/progress"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list <service> [subtype]",
	Short: "List AWS resources with metadata",
	Long: func() string {
		s := "List AWS resources with metadata. \n\nAvailable services:\n"
		for _, l := range list.All() {
			if len(l.SubTypes) > 0 {
				s += fmt.Sprintf("  %s [%s]\n", l.Service, strings.Join(l.SubTypes, ", "))
			} else {
				s += fmt.Sprintf("  %s\n", l.Service)
			}
		}
		return s
	}(),
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		service := args[0]
		lister := list.Get(service)
		if lister == nil {
			fmt.Fprintf(os.Stderr, "Error: unknown service %q (available: %s)\n",
				service, strings.Join(list.Services(), ", "))
			os.Exit(2)
		}

		subType := ""
		if len(args) == 2 {
			subType = args[1]
			if len(lister.SubTypes) > 0 {
				valid := false
				for _, st := range lister.SubTypes {
					if st == subType {
						valid = true
						break
					}
				}
				if !valid {
					fmt.Fprintf(os.Stderr, "Error: unknown subtype %q (available: %s)\n",
						subType, strings.Join(lister.SubTypes, ", "))
					os.Exit(2)
				}
			}
		}

		start := time.Now()
		ctx, cfg, cancel, err := buildAWSConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer cancel()

		if !showProgress {
			ctx = progress.WithQuiet(ctx, true)
		}

		resources, err := lister.Fn(ctx, cfg, subType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		for i := range resources {
			resources[i].Region = cfg.Region
		}

		if err := audit.OutputResources(format, resources, start, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
	},
}

func init() {
	awsCmd.AddCommand(listCmd)
}
