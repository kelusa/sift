package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"sift/audit"
	"sift/audit/aria"
	"sift/audit/aria/client"
	"sift/audit/history"
	"sift/audit/progress"

	// Register Aria checkers via their init().
	_ "sift/audit/aria/governance"

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
	Long:  "List Aria Automation resources.\n\nAvailable resources:\n deployments\n projects\n",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		resource := args[0]
		if resource != "deployments" && resource != "projects" {
			fmt.Fprintf(os.Stderr, "Error: unknown resource %q (available: deployments, projects)\n", resource)
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

		var resources []audit.Resource
		switch resource {
		case "deployments":
			resources, err = listAriaDeployments(ctx, c)
		case "projects":
			resources, err = listAriaProjects(ctx, c)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		if err := audit.OutputResources(format, resources, start, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
	},
}

func listAriaDeployments(ctx context.Context, c *client.Client) ([]audit.Resource, error) {
	deployments, err := c.ListDeployments(ctx)
	if err != nil {
		return nil, err
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
	return resources, nil
}

func listAriaProjects(ctx context.Context, c *client.Client) ([]audit.Resource, error) {
	projects, err := c.ListProjects(ctx)
	if err != nil {
		return nil, err
	}
	resources := make([]audit.Resource, 0, len(projects))
	for _, p := range projects {
		resources = append(resources, audit.Resource{
			Service:    "projects",
			Type:       "project",
			ResourceID: firstNonEmpty(p.Name, p.ID),
			Properties: map[string]string{
				"id":     p.ID,
				"org_id": firstNonEmpty(p.OrgID, p.OrganizationID),
			},
		})
	}
	return resources, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

var ariaGovernanceCmd = &cobra.Command{
	Use:   "governance",
	Short: "Audit Aria Automation governance compliance",
	Run: func(cmd *cobra.Command, args []string) {
		runAriaAudit("governance", audit.CheckersFor("aria", aria.ModuleGovernance), "Auditing Aria Governance")
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	},
}

// runAriaAudit builds an Aria scope, runs the given checkers via the neutral
// orchestrator, then outputs and (unless --no-save) persists findings tagged
// with provider="aria" and the host as the account identity.
func runAriaAudit(command string, checkers []audit.Checker, label string) {
	start := time.Now()

	if err := resolveFormat(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	cfg, err := aria.LoadConfig(ariaHost, ariaInsecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	prov := aria.NewProvider(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if !showProgress {
		ctx = progress.WithQuiet(ctx, true)
	}

	scopes, err := prov.Scopes(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	var allFindings []audit.Finding
	for _, scope := range scopes {
		findings, err := audit.RunScopedChecks(ctx, scope, nil, checkers, label)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		allFindings = append(allFindings, findings...)
	}

	if err := audit.OutputWithFilter(format, allFindings, riskLevel, sortBy, start, outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	host := cfg.Host
	db, dbErr := history.OpenDB()
	if dbErr == nil {
		defer db.Close()
		if diff {
			_, prev, err := db.LatestScan("aria", host, command)
			if err == nil && prev != nil {
				d := history.ComputeDiff(prev, allFindings)
				fmt.Fprintf(os.Stderr, "\nDiff vs previous scan\n")
				fmt.Fprintf(os.Stderr, " New:	%d\n", len(d.New))
				fmt.Fprintf(os.Stderr, " Resolved: %d\n", len(d.Resolved))
				fmt.Fprintf(os.Stderr, " Ongoing:	%d\n", len(d.Ongoing))
			}
		}
		if !noSave {
			meta := history.ScanMeta{
				ID:         fmt.Sprintf("%d", time.Now().UnixNano()),
				Provider:   "aria",
				Profile:    host,
				Command:    command,
				Region:     host,
				Timestamp:  time.Now().UTC(),
				DurationMs: time.Since(start).Milliseconds(),
			}
			if err := db.SaveScan(meta, allFindings); err != nil {
				slog.Warn("failed to save history", "error", err)
			}
		}
	}

	if audit.HasHighRiskFindings(allFindings) {
		exitCode = 1
	}
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

	audit.RegisterColumns("projects/project", []audit.ResourceColumn{
		{Key: "id", Header: "ID"},
		{Key: "org_id", Header: "ORG"},
	})

	ariaCmd.AddCommand(ariaListCmd)
	ariaCmd.AddCommand(ariaGovernanceCmd)
	rootCmd.AddCommand(ariaCmd)
}
