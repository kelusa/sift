package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"sift/audit"
	"sift/audit/ai"
	"sift/audit/history"

	"github.com/spf13/cobra"
)

var (
	aiService  string
	aiFinding  string
	aiQuestion string
	aiModule   string
	aiPrompt   string
)

var aiCmd = &cobra.Command{
	Use:   "ai [question]",
	Short: "Analyze findings with AI",
	Long:  "Query a local or remote LLM with audit findings as context. Configure endpoint in ~/.sift/ai.json",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := history.OpenDB()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		defer db.Close()

		var findings []audit.Finding
		var context string

		switch {
		case aiFinding != "":
			findings, err = db.FindingHistory(aiFinding)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			context = ai.BuildContext(map[string][]audit.Finding{"finding": findings})
		case aiService != "":
			findings, err = db.Query(providerFilter, aiService, "", "", "", profile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			context = ai.BuildContext(map[string][]audit.Finding{aiService: findings})
		default:
			findings, err = db.Query(providerFilter, "", "", "", "", profile)
			modules := []string{"security", "cost"}
			if aiModule != "" {
				modules = []string{aiModule}
			}
			grouped, err := db.FindingsByCommand(providerFilter, profile, modules)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			context = ai.BuildContext(grouped)
		}

		question := "Summarize the findings and recommend the top 3 actions to take."
		if len(args) > 0 {
			question = strings.Join(args, " ")
		}
		if aiQuestion != "" {
			question = aiQuestion
		}

		cfg := ai.LoadConfig()
		fmt.Fprintf(os.Stderr, "Querying %s (%s)...\n", cfg.Model, cfg.Endpoint)

		stats, err := ai.AnalyzeWithContext(cfg, context, question, aiPrompt, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		if stats != nil {
			slog.Info("AI analysis complete",
				"model", stats.Model,
				"prompt_tokens", stats.PromptTokens,
				"completion_tokens", stats.CompletionTokens,
				"duration_ms", stats.DurationMs,
			)
		}
	},
}

func init() {
	aiCmd.Flags().StringVar(&aiModule, "module", "", "Scope to a module (security, cost)")
	aiCmd.Flags().StringVar(&aiService, "service", "", "Scope to findings from a specific service")
	aiCmd.Flags().StringVar(&aiFinding, "finding", "", "Analyze a specific finding by ID")
	aiCmd.Flags().StringVar(&aiQuestion, "question", "", "Custom question to ask")
	aiCmd.Flags().
		StringVar(&aiPrompt, "prompt", "", "Prompt template name (e.g., executive, incident, compliance)")
	addFilterFlags(aiCmd.Flags())
	rootCmd.AddCommand(aiCmd)
}
