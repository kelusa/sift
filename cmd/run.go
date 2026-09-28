package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/history"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type auditFunc func(context.Context, aws.Config, []string) ([]audit.Finding, error)

var (
	checksCtxOverride []string
	exitCode          int
)

func runAudit(command, serviceFlag string, validServices map[string]bool, fn auditFunc) {
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

	if len(checksCtxOverride) > 0 {
		ctx = audit.WithChecks(ctx, checksCtxOverride)
		checksCtxOverride = nil
	}

	var services []string
	if serviceFlag != "" {
		services = strings.Split(serviceFlag, ",")
		for _, s := range services {
			if !validServices[s] {
				fmt.Fprintf(os.Stderr, "Error: unknown service %q\n", s)
				os.Exit(2)
			}
		}
	}

	var mu sync.Mutex
	var allFindings []audit.Finding
	var wg sync.WaitGroup
	for _, cfg := range configs {
		slog.Info("scanning region", "region", cfg.Region)
		wg.Add(1)
		go func(cfg aws.Config) {
			defer wg.Done()
			findings, err := fn(ctx, cfg, services)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error in %s: %v\n", cfg.Region, err)
				return
			}
			for i := range findings {
				findings[i].Region = cfg.Region
			}
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(cfg)
	}
	wg.Wait()

	slog.Info("scan complete",
		"command", command,
		"findings", len(allFindings),
		"duration_ms", time.Since(start).Milliseconds(),
	)

	// Enrich findings with application names
	audit.ApplyApplications(allFindings, audit.LoadAppMatcher())

	if err := audit.OutputWithFilter(format, allFindings, riskLevel, sortBy, start, outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	// Save to history and show diff
	db, dbErr := history.OpenDB()
	if dbErr == nil {
		defer db.Close()
		if diff {
			_, prev, err := db.LatestScan("aws", profile, command)
			if err == nil && prev != nil {
				d := history.ComputeDiff(prev, allFindings)
				fmt.Fprintf(os.Stderr, "\nDiff vs previous scan")
				fmt.Fprintf(os.Stderr, " New:		%d\n", len(d.New))
				fmt.Fprintf(os.Stderr, " Resolved: 	%d\n", len(d.Resolved))
				fmt.Fprintf(os.Stderr, " Ongoing: 	%d\n", len(d.Ongoing))
			} else if prev == nil {
				fmt.Fprintf(os.Stderr, "\nNo previous scan found for diff.")
			}
		}
		if !noSave {
			meta := history.ScanMeta{
				ID:         fmt.Sprintf("%d", time.Now().UnixNano()),
				Provider:   "aws",
				Profile:    profile,
				Command:    command,
				Region:     strings.Join(regions(configs), ","),
				Services:   serviceFlag,
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

func regions(configs []aws.Config) []string {
	var r []string
	for _, c := range configs {
		r = append(r, c.Region)
	}
	return r
}
