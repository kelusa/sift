package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

func init() {
	audit.RegisterAWS(Module, "baseline", AuditBaseline)
}

func baselineRisk(check string) string {
	switch check {
	case "no_trails", "logging_disabled", "not_enabled", "detector_disabled":
		return "CRITICAL"
	case "single_region":
		return "HIGH"
	case "no_log_validation":
		return "MEDIUM"
	default:
		return "MINIMAL"
	}
}

// AuditBaseline runs both CloudTrail and GuardDuty checks (used by triage).
func AuditBaseline(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	ct, err := auditCloudTrail(ctx, cfg)
	if err != nil {
		return nil, err
	}
	gd, err := auditGuardDuty(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return append(ct, gd...), nil
}

func auditCloudTrail(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := cloudtrail.NewFromConfig(cfg)

	resp, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe trails: %w", err)
	}

	if len(resp.TrailList) == 0 {
		risk := baselineRisk("no_trails")
		detail := "no CloudTrail trails configured"
		return []audit.Finding{{
			Service:   "cloudtrail",
			Check:     "no_trails",
			Status:    statusFromRisk(risk),
			Detail:    detail,
			RiskLevel: risk,
			Remediation: remediation.Recommend(
				"security",
				"cloudtrail",
				"no_trails",
				"account",
				detail,
			),
		}}, nil
	}

	var findings []audit.Finding
	for _, trail := range resp.TrailList {
		name := aws.ToString(trail.Name)

		status, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		if err != nil {
			findings = append(findings, audit.ErrorFinding("cloudtrail", name, "trail_status", err))
			continue
		}

		if !aws.ToBool(status.IsLogging) {
			risk := baselineRisk("logging_disabled")
			detail := "trail exists but logging is disabled"
			findings = append(findings, audit.Finding{
				Service:    "cloudtrail",
				ResourceID: name,
				Check:      "logging_disabled",
				Status:     statusFromRisk(risk),
				Detail:     detail,
				RiskLevel:  risk,
				Remediation: remediation.Recommend(
					"security",
					"cloudtrail",
					"logging_disabled",
					name,
					detail,
				),
			})
			continue
		}

		if !aws.ToBool(trail.IsMultiRegionTrail) {
			risk := baselineRisk("single_region")
			detail := "trail is not multi-region"
			findings = append(findings, audit.Finding{
				Service:    "cloudtrail",
				ResourceID: name,
				Check:      "single_region",
				Status:     statusFromRisk(risk),
				Detail:     detail,
				RiskLevel:  risk,
				Remediation: remediation.Recommend(
					"security", "cloudtrail", "single_region", name, detail,
				),
			})
		}

		if !aws.ToBool(trail.LogFileValidationEnabled) {
			risk := baselineRisk("no_log_validation")
			detail := "trail has no log file validation"
			findings = append(findings, audit.Finding{
				Service:    "cloudtrail",
				ResourceID: name,
				Check:      "no_log_validation",
				Status:     statusFromRisk(risk),
				Detail:     detail,
				RiskLevel:  risk,
				Remediation: remediation.Recommend(
					"security", "cloudtrail", "no_log_validation", name, detail,
				),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			Service:   "cloudtrail",
			Check:     "enabled",
			Status:    "PASS",
			Detail:    "CloudTrail is properly configured",
			RiskLevel: "MINIMAL",
		})
	}

	return findings, nil
}

func auditGuardDuty(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := guardduty.NewFromConfig(cfg)

	resp, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, fmt.Errorf("list detectors: %w", err)
	}

	if len(resp.DetectorIds) == 0 {
		risk := baselineRisk("not_enabled")
		detail := "GuardDuty is not enabled"
		return []audit.Finding{{
			Service:   "guardduty",
			Check:     "not_enabled",
			Status:    statusFromRisk(risk),
			Detail:    detail,
			RiskLevel: risk,
			Remediation: remediation.Recommend(
				"security", "guardduty", "not_enabled", "account", detail,
			),
		}}, nil
	}

	var findings []audit.Finding
	for _, id := range resp.DetectorIds {
		det, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{
			DetectorId: &id,
		})
		if err != nil {
			findings = append(findings, audit.ErrorFinding("guardduty", id, "detector_status", err))
			continue
		}

		if string(det.Status) != "ENABLED" {
			risk := baselineRisk("detector_disabled")
			detail := "detector is not enabled"
			findings = append(findings, audit.Finding{
				Service:    "guardduty",
				ResourceID: id,
				Check:      "detector_disabled",
				Status:     statusFromRisk(risk),
				Detail:     detail,
				RiskLevel:  risk,
				Remediation: remediation.Recommend(
					"security", "guardduty", "detector_disabled", id, detail,
				),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			Service:   "guardduty",
			Check:     "enabled",
			Status:    "PASS",
			Detail:    "GuardDuty is enabled",
			RiskLevel: "MINIMAL",
		})
	}

	return findings, nil
}
