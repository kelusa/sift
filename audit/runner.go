package audit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"sift/audit/progress"
)

// Checker is a named, provider-neutral audit unit.
// CheckFn and the Scope it receives are defined in provider.go
type Checker struct {
	Name string
	Fn   CheckFn
}

// RunScopedChecks is the provider-neutral orchestrator. It runs the given
// checkers against a single Scope (an AWS region, an Aria host, etc.),
// filtering by service name when services is non-empty.
func RunScopedChecks(
	ctx context.Context,
	scope Scope,
	services []string,
	all []Checker,
	label string,
) ([]Finding, error) {
	checks := all
	if len(services) > 0 {
		svcSet := make(map[string]bool, len(services))
		for _, s := range services {
			svcSet[s] = true
		}
		checks = nil
		for _, c := range all {
			if svcSet[c.Name] {
				checks = append(checks, c)
			}
		}
	}
	if len(checks) == 0 {
		return nil, nil
	}

	results := make([][]Finding, len(checks))

	if len(checks) == 1 {
		subCtx := progress.WithSubProgress(ctx, true)
		slog.Info("checking service", "service", checks[0].Name)
		start := time.Now()
		findings, err := checks[0].Fn(subCtx, scope)
		if err != nil {
			if scope.SkipError != nil && scope.SkipError(err) {
				slog.Debug("service not available", "service", checks[0].Name, "error", err)
				results[0] = []Finding{{
					Service:   checks[0].Name,
					Check:     "service_availability",
					Status:    "PASS",
					Detail:    "service not active or not subscribed in this account",
					RiskLevel: "MINIMAL",
				}}
			} else {
				slog.Warn("check failed", "service", checks[0].Name, "error", err)
				results[0] = []Finding{ErrorFinding(checks[0].Name, "", "service_error", err)}
			}
		} else {
			slog.Info("service complete", "service", checks[0].Name, "findings", len(findings), "duration_ms", time.Since(start).Milliseconds())
			results[0] = findings
		}
	} else {
		subCtx := progress.WithSubProgress(ctx, false)
		bar := progress.NewOrchestratorBar(ctx, int64(len(checks)), label)
		var wg sync.WaitGroup
		for i, c := range checks {
			wg.Add(1)
			go func(i int, name string, fn CheckFn) {
				defer wg.Done()
				slog.Info("checking service", "service", name)
				start := time.Now()
				findings, err := fn(subCtx, scope)
				if err != nil {
					if scope.SkipError != nil && scope.SkipError(err) {
						slog.Debug("service not available", "service", name, "error", err)
						results[i] = []Finding{{
							Service:   name,
							Check:     "service_availability",
							Status:    "PASS",
							Detail:    "service not active or not subscribed in this account",
							RiskLevel: "MINIMAL",
						}}
					} else {
						slog.Warn("check failed", "service", name, "error", err)
						results[i] = []Finding{{
							Service:   name,
							Check:     "service_error",
							Status:    "ERROR",
							Detail:    fmt.Sprintf("audit failed: %v", err),
							RiskLevel: "UNKNOWN",
						}}
					}
				} else {
					slog.Info("service complete", "service", name, "findings", len(findings), "duration_ms", time.Since(start).Milliseconds())
					results[i] = findings
				}
				bar.Done(name)
			}(i, c.Name, c.Fn)
		}
		wg.Wait()
	}

	var out []Finding
	for _, f := range results {
		out = append(out, f...)
	}
	for i := range out {
		out[i].ComputeID()
	}
	return out, nil
}
