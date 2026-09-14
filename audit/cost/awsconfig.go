package cost

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

func init() {
	audit.RegisterAWS(Module, "awsconfig", AuditConfigCost)
}

func AuditConfigCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := configservice.NewFromConfig(cfg)

	var findings []audit.Finding

	// Check recorders
	recResp, err := client.DescribeConfigurationRecorders(
		ctx,
		&configservice.DescribeConfigurationRecordersInput{},
	)
	if err != nil {
		return nil, fmt.Errorf("describe configuration recorders: %w", err)
	}

	for _, rec := range recResp.ConfigurationRecorders {
		name := aws.ToString(rec.Name)
		allResources := rec.RecordingGroup != nil && rec.RecordingGroup.AllSupported

		if allResources {
			findings = append(findings, audit.Finding{
				Service:    "config",
				ResourceID: name,
				Check:      "record_all_resources",
				Status:     "WARN",
				Detail:     "recording all resource types ($0.003/item/mo), consider scoping to specific types",
				RiskLevel:  "MEDIUM",
				Remediation: remediation.Recommend(
					"cost",
					"config",
					"record_all_resources",
					name,
					"recording all resource types",
				),
			})
		}
	}

	// Check unused rules
	var rules []string
	input := &configservice.DescribeConfigRulesInput{}
	for {
		resp, err := client.DescribeConfigRules(ctx, input)
		if err != nil {
			break
		}
		for _, r := range resp.ConfigRules {
			rules = append(rules, aws.ToString(r.ConfigRuleName))
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	ruleFindings := audit.ProcessAll(
		ctx,
		rules,
		"Auditing Config rules",
		func(ctx context.Context, ruleName string) audit.Finding {
			compResp, err := client.GetComplianceDetailsByConfigRule(
				ctx,
				&configservice.GetComplianceDetailsByConfigRuleInput{
					ConfigRuleName: &ruleName,
					Limit:          1,
				},
			)
			if err != nil || len(compResp.EvaluationResults) == 0 {
				return audit.Finding{
					Service:              "config",
					ResourceID:           ruleName,
					Check:                "unused_rule",
					Status:               "WARN",
					Detail:               "rule has zero evaluations, $1/mo waste",
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: 1.0,
					Remediation: remediation.Recommend(
						"cost",
						"config",
						"unused_rule",
						ruleName,
						"zero evaluations",
					),
				}
			}
			return audit.Finding{
				Service:    "config",
				ResourceID: ruleName,
				Check:      "unused_rule",
				Status:     "PASS",
				Detail: fmt.Sprintf(
					"rule active, last evaluation=%s",
					compResp.EvaluationResults[0].ResultRecordedTime.Format("2006-01-02"),
				),
				RiskLevel: "MINIMAL",
			}
		},
	)
	findings = append(findings, ruleFindings...)

	return findings, nil
}
