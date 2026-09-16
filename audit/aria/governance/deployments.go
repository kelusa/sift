// Package governance holds Aria Automation governance checkers. They register
// via the provider-neutral audit.Register and run through RunScopedChecks with
// an Aria scope.
package governance

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/aria"
)

func init() {
	audit.Register(aria.ModuleGovernance, audit.Checker{
		Name: "deployments",
		Fn:   auditDeployments,
	})
}

// auditDeployments flags governance risks on Aria deployments:
//   - provenance: deployments created outside the catalog/blueprint
//     (no blueprintId and no catalogItemId) are ungoverned.
//   - ownership: deployments with no owner are orphaned.
func auditDeployments(ctx context.Context, scope audit.Scope) ([]audit.Finding, error) {
	c := aria.ClientFrom(scope)

	deployments, err := c.ListDeployments(ctx)
	if err != nil {
		return nil, err
	}

	var findings []audit.Finding
	for _, d := range deployments {
		resourceID := d.ID
		if resourceID == "" {
			resourceID = d.Name
		}

		ungoverned := d.BlueprintID == "" && d.CatalogItemID == ""
		orphaned := d.OwnedBy == ""

		// Human-readable context prefix; the stable deployment ID remains the
		// finding identity so history/diff tracks it across renames:
		label := fmt.Sprintf("%q in project %s", d.Name, d.ProjectID)

		status := "PASS"
		risk := "MINIMAL"
		detail := fmt.Sprintf("deployment %s is catalog/blueprint-managed and owned", label)

		switch {
		case ungoverned && orphaned:
			status, risk = "FAIL", "HIGH"
			detail = fmt.Sprintf("deployment %s has no blueprint/catalog source and no owner (ungoverned and orphaned)", label)
		case ungoverned:
			status, risk = "WARN", "MEDIUM"
			detail = fmt.Sprintf("deployment %s has no blueprint or catalog source (created outside the catalog)", label)
		case orphaned:
			status, risk = "WARN", "MEDIUM"
			detail = fmt.Sprintf("deployment %s has no owner (orphaned)", label)
		}

		findings = append(findings, audit.Finding{
			Service:    "deployments",
			ResourceID: fmt.Sprintf("%s (%s)", d.Name, d.ProjectID),
			Check:      "deployment_governance",
			Status:     status,
			RiskLevel:  risk,
			Detail:     detail,
		})
	}

	return findings, nil
}
