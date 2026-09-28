// Package ops holds Aria Automation operational-health checkers. They register
// via the provider-neutral audit.Register and run through RunScopedChecks with
// an Aria scope.
package ops

import (
	"context"
	"fmt"
	"strings"

	"sift/audit"
	"sift/audit/aria"
)

func init() {
	audit.Register("aria", aria.ModuleOps, audit.Checker{
		Name: "resources",
		Fn:   auditResourceHealth,
	})
}

// auditResourceHealth flags deployment resources whose provisioning is not
// clean:
//   - state != "OK": the resource is in an error/partial state or has drifted.
//   - syncStatus != "SUCCESS": Aria's record is out of sync with the actual
//     backing resource (stale/failed sync).
//
// Resources that are both OK and SUCCESS pass. The stable resource ID is the
// finding identity so history/diff tracks each resource across renames.
func auditResourceHealth(ctx context.Context, scope audit.Scope) ([]audit.Finding, error) {
	c := aria.ClientFrom(scope)

	items, err := c.ListResources(ctx)
	if err != nil {
		return nil, err
	}

	var findings []audit.Finding
	for _, r := range items {
		state := strings.ToUpper(strings.TrimSpace(r.State))
		sync := strings.ToUpper(strings.TrimSpace(r.SyncStatus))

		badState := state != "" && state != "OK"
		badSync := sync != "" && sync != "SUCCESS"

		label := fmt.Sprintf("%q (%s)", r.Name, r.Type)

		status := "PASS"
		risk := "MINIMAL"
		detail := fmt.Sprintf("resource %s is healthy (state=%s, sync=%s)", label, r.State, r.SyncStatus)

		switch {
		case badState && badSync:
			status, risk = "FAIL", "HIGH"
			detail = fmt.Sprintf("resource %s is unhealthy: state=%s, sync=%s", label, r.State, r.SyncStatus)
		case badState:
			status, risk = "WARN", "MEDIUM"
			detail = fmt.Sprintf("resource %s is not in OK state: state=%s", label, r.State)
		case badSync:
			status, risk = "WARN", "MEDIUM"
			detail = fmt.Sprintf("resource %s is out of sync with Aria: sync=%s", label, r.SyncStatus)
		}

		findings = append(findings, audit.Finding{
			Service:    "resources",
			ResourceID: fmt.Sprintf("%s (%s)", firstNonEmpty(r.Name, r.ID), r.Type),
			Check:      "resource_health",
			Status:     status,
			RiskLevel:  risk,
			Detail:     detail,
		})
	}

	return findings, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
