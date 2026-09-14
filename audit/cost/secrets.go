package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

func init() {
	audit.RegisterAWS(Module, "secrets", AuditSecretsCost)
}

type secretCostEntry struct {
	name             string
	lastAccessedDays int
	tags             map[string]string
}

func AuditSecretsCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := secretsmanager.NewFromConfig(cfg)

	var allSecrets []smtypes.SecretListEntry
	paginator := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		allSecrets = append(allSecrets, page.SecretList...)
	}

	t := audit.GetThresholds(ctx)

	return audit.ProcessAll(
		ctx,
		allSecrets,
		"Auditing Secrets Manager cost",
		func(_ context.Context, secret smtypes.SecretListEntry) audit.Finding {
			s := parseSecretCostEntry(secret)
			if s.lastAccessedDays > t.GetInt("secrets", "unused_days", 90) {
				return audit.Finding{
					Service:    "secrets_manager",
					ResourceID: s.name,
					Tags:       s.tags,
					Check:      "unused_secret",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"last accessed %d days ago ($0.40/mo)",
						s.lastAccessedDays,
					),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: pricing.SecretMonthly(),
					Remediation: remediation.Recommend(
						"cost",
						"secrets_manager",
						"unused_secret",
						s.name,
						fmt.Sprintf("last accessed %d days ago", s.lastAccessedDays),
					),
				}
			}
			return audit.Finding{
				Service:              "secrets_manager",
				ResourceID:           s.name,
				Tags:                 s.tags,
				Check:                "unused_secret",
				Status:               "PASS",
				Detail:               fmt.Sprintf("last accessed %d days ago", s.lastAccessedDays),
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: pricing.SecretMonthly(),
			}
		},
	), nil
}

func parseSecretCostEntry(secret smtypes.SecretListEntry) secretCostEntry {
	s := secretCostEntry{
		name:             aws.ToString(secret.Name),
		lastAccessedDays: -1,
	}
	if secret.LastAccessedDate != nil {
		s.lastAccessedDays = int(time.Since(*secret.LastAccessedDate).Hours() / 24)
	}
	s.tags = make(map[string]string, len(secret.Tags))
	for _, t := range secret.Tags {
		s.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return s
}
