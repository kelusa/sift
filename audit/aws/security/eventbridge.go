package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

func init() {
	audit.RegisterAWS(Module, "eventbridge", AuditEventBridge)
}

func AuditEventBridge(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := eventbridge.NewFromConfig(cfg)

	resp, err := client.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{})
	if err != nil {
		return nil, fmt.Errorf("list event buses: %w", err)
	}

	return audit.ProcessAllMulti(ctx, resp.EventBuses, "Auditing EventBridge security",
		func(ctx context.Context, bus ebtypes.EventBus) []audit.Finding {
			name := aws.ToString(bus.Name)
			var results []audit.Finding

			// Check for open policy
			policy := aws.ToString(bus.Policy)
			if policy != "" &&
				(strings.Contains(policy, `"Principal":"*"`) || strings.Contains(policy, `"Principal": "*"`)) {
				d := "event bus policy allows wildcard principal"
				results = append(results, audit.Finding{
					Service:    "eventbridge",
					ResourceID: name,
					Check:      "public_bus",
					Status:     "FAIL",
					Detail:     d,
					RiskLevel:  "HIGH",
					Remediation: remediation.Recommend(
						"security",
						"eventbridge",
						"public_bus",
						name,
						d,
					),
				})
			}

			// Check rules for DLQ
			rulesResp, err := client.ListRules(
				ctx,
				&eventbridge.ListRulesInput{EventBusName: &name},
			)
			if err == nil {
				for _, rule := range rulesResp.Rules {
					ruleName := aws.ToString(rule.Name)
					targetsResp, err := client.ListTargetsByRule(
						ctx,
						&eventbridge.ListTargetsByRuleInput{
							Rule:         &ruleName,
							EventBusName: &name,
						},
					)
					if err != nil {
						continue
					}
					for _, target := range targetsResp.Targets {
						if target.DeadLetterConfig == nil ||
							aws.ToString(target.DeadLetterConfig.Arn) == "" {
							d := fmt.Sprintf(
								"rule=%s, target=%s, no dead-letter queue",
								ruleName,
								aws.ToString(target.Id),
							)
							results = append(results, audit.Finding{
								Service:    "eventbridge",
								ResourceID: ruleName,
								Check:      "no_dlq",
								Status:     "FAIL",
								Detail:     d,
								RiskLevel:  "MEDIUM",
								Remediation: remediation.Recommend(
									"security",
									"eventbridge",
									"no_dlq",
									ruleName+"/"+aws.ToString(target.Id),
									d,
								),
							})
							break // one finding per rule is enough
						}
					}
				}
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "eventbridge",
					ResourceID: name,
					Check:      "eventbridge_posture",
					Status:     "PASS",
					Detail:     "no public access, DLQs configured",
					RiskLevel:  "MINIMAL",
				})
			}
			return results
		},
	), nil
}
