package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

func init() {
	audit.RegisterAWS(Module, "awsconfig", AuditConfig)
}

func AuditConfig(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := configservice.NewFromConfig(cfg)

	resp, err := client.DescribeConfigurationRecorders(
		ctx,
		&configservice.DescribeConfigurationRecordersInput{},
	)
	if err != nil {
		return nil, fmt.Errorf("describe configuration recorders: %w", err)
	}

	if len(resp.ConfigurationRecorders) == 0 {
		d := "AWS Config recorder not configured"
		return []audit.Finding{{
			Service:   "awsconfig",
			Check:     "not_enabled",
			Status:    "FAIL",
			Detail:    d,
			RiskLevel: "CRITICAL",
			Remediation: remediation.Recommend(
				"security", "awsconfig", "not_enabled", "account", d,
			),
		}}, nil
	}

	var results []audit.Finding
	for _, rec := range resp.ConfigurationRecorders {
		name := aws.ToString(rec.Name)

		// Check if recording
		statusResp, err := client.DescribeConfigurationRecorderStatus(
			ctx,
			&configservice.DescribeConfigurationRecorderStatusInput{
				ConfigurationRecorderNames: []string{name},
			},
		)
		if err != nil {
			results = append(results, audit.ErrorFinding("awsconfig", name, "recorder_status", err))
			continue
		}

		if len(statusResp.ConfigurationRecordersStatus) > 0 &&
			!statusResp.ConfigurationRecordersStatus[0].Recording {
			d := "Config recorder exists but is not recording"
			results = append(results, audit.Finding{
				Service:    "awsconfig",
				ResourceID: name,
				Check:      "not_recording",
				Status:     "FAIL",
				Detail:     d,
				RiskLevel:  "CRITICAL",
				Remediation: remediation.Recommend(
					"security", "awsconfig", "not_recording", name, d,
				),
			})
			continue
		}

		// Check if recording all resource types
		if rec.RecordingGroup != nil && !rec.RecordingGroup.AllSupported {
			d := "Config recorder is not recording all resource types"
			results = append(results, audit.Finding{
				Service:    "awsconfig",
				ResourceID: name,
				Check:      "partial_recording",
				Status:     "WARN",
				Detail:     d,
				RiskLevel:  "HIGH",
				Remediation: remediation.Recommend(
					"security", "awsconfig", "partial_recording", name, d,
				),
			})
		}
	}

	if len(results) == 0 {
		results = append(results, audit.Finding{
			Service:   "awsconfig",
			Check:     "config_posture",
			Status:    "PASS",
			Detail:    "AWS Config is recording all resource types",
			RiskLevel: "MINIMAL",
		})
	}

	return results, nil
}
