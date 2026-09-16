package security

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

func init() {
	awsreg.Register(Module, "secrets", AuditSecrets)
}

type secretEntry struct {
	name             string
	rotationEnabled  bool
	daysSinceRotated int
	tags             map[string]string
}

func parseSecretEntry(secret smtypes.SecretListEntry) secretEntry {
	s := secretEntry{
		name:             aws.ToString(secret.Name),
		rotationEnabled:  aws.ToBool(secret.RotationEnabled),
		daysSinceRotated: -1,
	}
	if secret.LastRotatedDate != nil {
		s.daysSinceRotated = int(time.Since(*secret.LastRotatedDate).Hours() / 24)
	}
	s.tags = make(map[string]string, len(secret.Tags))
	for _, t := range secret.Tags {
		s.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return s
}

func AuditSecrets(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
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

	results := audit.ProcessAll(
		ctx,
		allSecrets,
		"Auditing secrets",
		func(_ context.Context, secret smtypes.SecretListEntry) audit.Finding {
			s := parseSecretEntry(secret)

			rotationOverdue := s.daysSinceRotated > t.GetInt(
				"secrets",
				"rotation_max_days",
				90,
			)
			risk := secretsRisk(s.rotationEnabled, rotationOverdue, s.daysSinceRotated)

			detail := fmt.Sprintf("rotation_enabled=%t", s.rotationEnabled)
			if s.daysSinceRotated >= 0 {
				detail += fmt.Sprintf(", days_since_rotated=%d", s.daysSinceRotated)
			} else {
				detail += ", never_rotated=true"
			}

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend(
					"security",
					"secrets_manager",
					"secret_rotation",
					s.name,
					detail,
				)
			}

			return audit.Finding{
				Service:     "secrets_manager",
				ResourceID:  s.name,
				Tags:        s.tags,
				Check:       "secret_rotation",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	)
	return results, nil
}

func secretsRisk(rotationEnabled, rotationOverdue bool, daysSinceRotated int) string {
	switch {
	case !rotationEnabled && daysSinceRotated == -1:
		return "HIGH"
	case !rotationEnabled:
		return "MEDIUM"
	case rotationOverdue:
		return "MEDIUM"
	default:
		return "MINIMAL"
	}
}
