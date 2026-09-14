package triage

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"sift/audit"
	"sift/audit/aws/security"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

type result struct {
	target      security.TriageTarget
	iamRisk     string
	iamDetails  []string
	publicConns []security.FlowEvent
}

func Run(
	ctx context.Context,
	cfg aws.Config,
	logGroup string,
	targets []security.TriageTarget,
) ([]audit.Finding, error) {
	cwClient := cloudwatchlogs.NewFromConfig(cfg)
	roleCache := security.NewRoleCache()

	results := audit.FetchAll(
		ctx,
		targets,
		"Triaging instances",
		func(ctx context.Context, t security.TriageTarget) result {
			r := result{target: t}

			if t.RoleARN != nil {
				finding, err := security.CachedAnalyzeRole(ctx, cfg, *t.RoleARN, roleCache)
				if err != nil {
					slog.Warn("IAM check failed", "instance", t.ResourceID, "error", err)
				} else {
					r.iamRisk = finding.RiskLevel
					for _, f := range finding.Findings {
						r.iamDetails = append(r.iamDetails, fmt.Sprintf("%s:%s(%s)", f.PolicyType, f.PolicyName, f.Issue))
					}
				}
			}

			if t.PrivateIP != nil {
				conns, err := security.FindPublicConnections(ctx, cwClient, logGroup, *t.PrivateIP)
				if err != nil {
					slog.Warn("flow log query failed", "resource", t.ResourceID, "error", err)
				} else {
					r.publicConns = conns
				}
			}
			return r
		},
	)

	var findings []audit.Finding
	for _, r := range results {
		connCount := len(r.publicConns)
		risk := triageRisk(r.target.OpenToWorld, r.target.IMDSv1, r.iamRisk, connCount)

		detail := fmt.Sprintf(
			"service=%s, open_to_world=%t, imdsv1=%t, public_connection=%d",
			r.target.Service,
			r.target.OpenToWorld,
			r.target.IMDSv1,
			connCount,
		)
		if r.iamRisk != "" {
			detail += fmt.Sprintf(", iam_risk=%s", r.iamRisk)
		}
		if len(r.iamDetails) > 0 {
			detail += fmt.Sprintf(", iam_findings=%s", strings.Join(r.iamDetails, ";"))
		}

		status := "FAIL"
		if risk == "LOW" {
			status = "PASS"
		}

		findings = append(findings, audit.Finding{
			Service:    r.target.Service,
			ResourceID: r.target.ResourceID,
			Check:      "triage",
			Status:     status,
			Detail:     detail,
			RiskLevel:  risk,
		})
	}
	return findings, nil
}

func triageRisk(openToWorld, imdsv1 bool, iamRisk string, connCount int) string {
	if connCount > 0 && openToWorld {
		return "CRITICAL"
	}
	if connCount > 0 {
		return "HIGH"
	}
	if iamRisk == "HIGH" && openToWorld {
		return "HIGH"
	}
	if openToWorld || imdsv1 {
		return "MEDIUM"
	}
	return "LOW"
}
