package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func init() {
	awsreg.Register(Module, "kms", AuditKMS)
}

func AuditKMS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := kms.NewFromConfig(cfg)

	var keys []kmstypes.KeyListEntry
	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}
		keys = append(keys, page.Keys...)
	}

	return audit.ProcessAllMulti(
		ctx,
		keys,
		"Auditing KMS security",
		func(ctx context.Context, key kmstypes.KeyListEntry) []audit.Finding {
			keyID := aws.ToString(key.KeyId)

			desc, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
			if err != nil {
				return []audit.Finding{audit.ErrorFinding("kms", keyID, "describe_key", err)}
			}
			if desc.KeyMetadata.KeyManager == kmstypes.KeyManagerTypeAws {
				return nil
			}
			if desc.KeyMetadata.KeyState != kmstypes.KeyStateEnabled {
				return nil
			}

			rotResp, _ := client.GetKeyRotationStatus(
				ctx,
				&kms.GetKeyRotationStatusInput{KeyId: &keyID},
			)
			rotationEnabled := rotResp != nil && rotResp.KeyRotationEnabled

			policyResp, _ := client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
				KeyId:      &keyID,
				PolicyName: aws.String("default"),
			})
			wildcardPrincipal := false
			if policyResp != nil && policyResp.Policy != nil {
				wildcardPrincipal = strings.Contains(*policyResp.Policy, `"Principal":"*"`) ||
					strings.Contains(*policyResp.Policy, `"Principal": "*"`)
			}

			var results []audit.Finding

			if wildcardPrincipal {
				detail := "key policy allows wildcard principal"
				risk := "HIGH"
				if !rotationEnabled {
					risk = "CRITICAL"
				}
				results = append(results, audit.Finding{
					Service:    "kms",
					ResourceID: keyID,
					Check:      "wildcard_principal",
					Status:     statusFromRisk(risk),
					Detail:     detail,
					RiskLevel:  risk,
					Remediation: remediation.Recommend(
						"security",
						"kms",
						"wildcard_principal",
						keyID,
						detail,
					),
				})
			}

			if !rotationEnabled {
				detail := "automatic key rotation disabled"
				results = append(results, audit.Finding{
					Service:    "kms",
					ResourceID: keyID,
					Check:      "no_rotation",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"security",
						"kms",
						"no_rotation",
						keyID,
						detail,
					),
				})
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "kms",
					ResourceID: keyID,
					Check:      "kms_posture",
					Status:     "PASS",
					Detail:     "rotation=true, no wildcard principal",
					RiskLevel:  "MINIMAL",
				})
			}

			return results
		},
	), nil
}
