package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"sift/audit"
	"sift/audit/aria"

	"github.com/spf13/cobra"
)

var (
	ariaHost     string
	ariaInsecure bool
)

// ariaCmd is the parent for all Aria Automation provider-scoped commands.
// Connection config: --host (or ~/.sift/providers.json) and the SIFT_ARIA_TOKEN
// environment variable for the bearer token (never passed on the CLI).
var ariaCmd = &cobra.Command{
	Use:   "aria",
	Short: "Audit VMware Aria Automation resources",
	Long: "Audit VMware Aria Automation (on-prem 8.x) resources.\n\n" +
		"Authentication uses a bearer token from the " + aria.TokenEnvVar +
		" environment variable, obtained from an authenticated browser session.",
}

var ariaListCmd = &cobra.Command{
	Use:   "list <resource>",
	Short: "List Aria Automation resources with metadata",
	Long:  "List Aria Automation resources.\n\nAvailable resources:\n deployments\n",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		resource := args[0]
		if resource != "deployments" {
			fmt.Fprintf(os.Stderr, "Error: unknown resource %q (available: deployments)\n", resource)
			os.Exit(2)
		}

		if err := resolveFormat(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		cfg, err := aria.LoadConfig(ariaHost, ariaInsecure)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		c, err := aria.NewClient(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		deployments, err := c.ListDeployments(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		resources := make([]audit.Resource, 0, len(deployments))
		for _, d := range deployments {
			resources = append(resources, audit.Resource{
				Service:    "deployments",
				Type:       "deployment",
				ResourceID: firstNonEmpty(d.Name, d.ID),
				Properties: map[string]string{
					"id":        d.ID,
					"project":   d.ProjectID,
					"status":    d.Status,
					"owned_by":  d.OwnedBy,
					"blueprint": d.BlueprintID,
					"catalog":   d.CatalogItemID,
					"created":   d.CreatedAt,
				},
			})
		}

		if err := audit.OutputResources(format, resources, start, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
	},
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func init() {
	ariaCmd.PersistentFlags().StringVar(&ariaHost, "host", "", "Aria Automation host URL (https://...); overrides ~/.sift/providers.json")
	ariaCmd.PersistentFlags().BoolVar(&ariaInsecure, "insecure", false, "Skip TLS certificate verification (self-signed on-prem certs)")

	audit.RegisterColumns("deployments/deployment", []audit.ResourceColumn{
		{Key: "project", Header: "PROJECT"},
		{Key: "status", Header: "STATUS"},
		{Key: "owned_by", Header: "OWNER"},
		{Key: "blueprint", Header: "BLUEPRINT"},
		{Key: "catalog", Header: "CATALOG"},
	})

	ariaCmd.AddCommand(ariaListCmd)
	rootCmd.AddCommand(ariaCmd)
}
