package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	"sift/audit"
	"sift/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	profile      string
	format       string
	riskLevel    string
	region       string
	verbose      bool
	showProgress bool
	outputFile   string
	concurrency  int
	sortBy       string
	noSave       bool
	diff         bool
)

var rootCmd = &cobra.Command{
	Use:   "sift",
	Short: "AWS security and cost audit tool",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Load .env (if present) so SIFT_* variables are available.
		// Real environment variables already set take precedence (godotenv default).
		_ = godotenv.Load()
		setupLogging()
	},
}

func setupLogging() {
	// Always log to file (JSON, info level)
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, ".sift")
	os.MkdirAll(logDir, 0o755)
	logFile, err := os.OpenFile(
		filepath.Join(logDir, "sift.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0o644,
	)

	var handlers []slog.Handler

	if err == nil {
		handlers = append(
			handlers,
			slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	// Stderr: info only by default, debug with --verbose
	stderrLevel := slog.LevelInfo
	if verbose {
		stderrLevel = slog.LevelDebug
	}
	handlers = append(
		handlers,
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: stderrLevel}),
	)

	slog.SetDefault(slog.New(multiHandler(handlers...)))
}

// multiHandler fans out log records to multiple handlers.
type fanoutHandler struct {
	handlers []slog.Handler
}

func multiHandler(handlers ...slog.Handler) slog.Handler {
	return &fanoutHandler{handlers: handlers}
}

func (h *fanoutHandler) Enabled(_ context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(context.Background(), level) {
			return true
		}
	}
	return false
}

func (h *fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, r.Level) {
			handler.Handle(ctx, r)
		}
	}
	return nil
}

func (h *fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var handlers []slog.Handler
	for _, handler := range h.handlers {
		handlers = append(handlers, handler.WithAttrs(attrs))
	}
	return &fanoutHandler{handlers: handlers}
}

func (h *fanoutHandler) WithGroup(name string) slog.Handler {
	var handlers []slog.Handler
	for _, handler := range h.handlers {
		handlers = append(handlers, handler.WithGroup(name))
	}
	return &fanoutHandler{handlers: handlers}
}

func SetVersion(version, commit, date string) {
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.PersistentFlags().
		StringVar(&format, "format", "", "Output format (json|csv|table). Default: table for terminal, json for pipes")
	rootCmd.PersistentFlags().
		StringVar(&riskLevel, "risk-level", "", "Minimum risk level to show (MINIMAL|LOW|MEDIUM|HIGH|CRITICAL)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Show debug-level log output")
	rootCmd.PersistentFlags().BoolVar(&showProgress, "progress", false, "Show progress bars")
	rootCmd.PersistentFlags().
		StringVarP(&outputFile, "output", "o", "", "Write results to file instead of stdout")
	rootCmd.PersistentFlags().
		IntVar(&concurrency, "concurrency", 10, "Max parallel AWS API calls per service")
	rootCmd.PersistentFlags().
		StringVar(&sortBy, "sort-by", "risk", "Sort results by: risk or cost")
	rootCmd.PersistentFlags().
		BoolVar(&noSave, "no-save", false, "Don't save scan results to history")
	rootCmd.PersistentFlags().BoolVar(&diff, "diff", false, "Compare results to previous scan")
}

func buildAWSConfig() (context.Context, aws.Config, context.CancelFunc, error) {
	if format == "" {
		if term.IsTerminal(int(os.Stdout.Fd())) {
			format = "table"
		} else {
			format = "json"
		}
	}
	if format != "json" && format != "csv" && format != "table" {
		return nil, aws.Config{}, nil, fmt.Errorf(
			"unknown format %q (use json, csv or table)",
			format,
		)
	}
	if riskLevel != "" {
		valid := map[string]bool{
			"MINIMAL":  true,
			"LOW":      true,
			"MEDIUM":   true,
			"HIGH":     true,
			"CRITICAL": true,
		}
		if !valid[strings.ToUpper(riskLevel)] {
			return nil, aws.Config{}, nil, fmt.Errorf(
				"unknown risk level %q (use MINIMAL, LOW, MEDIUM, HIGH, or CRITICAL)",
				riskLevel,
			)
		}
	}

	// Signal-based context cancellation for graceful Ctrl+C shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)

	// Load from config file, then let CLI flags override
	t := audit.LoadThresholds()
	if rootCmd.PersistentFlags().Changed("concurrency") {
		t.Concurrency = concurrency
	}
	ctx = audit.WithThresholds(ctx, t)
	cfg, err := config.BuildConfig(ctx, profile)
	if err != nil {
		cancel()
		return nil, aws.Config{}, nil, err
	}
	return ctx, cfg, cancel, nil
}

func buildAWSConfigs() (context.Context, []aws.Config, context.CancelFunc, error) {
	ctx, baseCfg, cancel, err := buildAWSConfig()
	if err != nil {
		return nil, nil, nil, err
	}

	if region == "" {
		return ctx, []aws.Config{baseCfg}, cancel, nil
	}

	var regions []string
	if region == "all" {
		regions, err = listEnabledRegions(ctx, baseCfg)
		if err != nil {
			cancel()
			return nil, nil, nil, fmt.Errorf("listing regions: %w", err)
		}
		slog.Info("scanning all enabled regions", "count", len(regions))
	} else {
		regions = strings.Split(region, ",")
	}

	var configs []aws.Config
	for _, r := range regions {
		cfg := baseCfg.Copy()
		cfg.Region = r
		configs = append(configs, cfg)
	}
	return ctx, configs, cancel, nil
}

func listEnabledRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	client := ec2.NewFromConfig(cfg)
	resp, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
	})
	if err != nil {
		return nil, err
	}
	var regions []string
	for _, r := range resp.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	return regions, nil
}

func serviceUsage(services map[string]bool) string {
	keys := make([]string, 0, len(services))
	for k := range services {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "Services to audit (comma-separated). Default: all\nAvailable: " + strings.Join(
		keys,
		", ",
	)
}
