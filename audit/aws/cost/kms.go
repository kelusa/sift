package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func init() {
	awsreg.Register(Module, "kms", AuditKMSCost)
}

func AuditKMSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := kms.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)
	unusedDays := t.GetInt("kms", "unused_days", 90)

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
		"Auditing KMS cost",
		func(ctx context.Context, key kmstypes.KeyListEntry) []audit.Finding {
			keyID := aws.ToString(key.KeyId)

			desc, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
			if err != nil {
				return nil
			}
			meta := desc.KeyMetadata

			// Skip AWS-managed keys and disabled/pending-deletion keys
			if meta.KeyManager == kmstypes.KeyManagerTypeAws {
				return nil
			}
			if meta.KeyState != kmstypes.KeyStateEnabled {
				return nil
			}

			// Check last used
			if meta.CreationDate != nil &&
				time.Since(*meta.CreationDate).Hours() < 24*float64(unusedDays) {
				return nil // too new to judge
			}

			// DescribeKey doesn't give last-used; we need GetKeyRotationStatus or just check creation age
			// KMS doesn't expose "last used" directly, but we can check if it was used recently via CloudTrail
			// For simplicity, flag customer-managed keys older than threshold with no rotation
			rotResp, _ := client.GetKeyRotationStatus(
				ctx,
				&kms.GetKeyRotationStatusInput{KeyId: &keyID},
			)
			rotationEnabled := rotResp != nil && rotResp.KeyRotationEnabled

			// Get tags
			var tags map[string]string
			tagResp, tagErr := client.ListResourceTags(
				ctx,
				&kms.ListResourceTagsInput{KeyId: &keyID},
			)
			if tagErr == nil {
				tags = make(map[string]string, len(tagResp.Tags))
				for _, t := range tagResp.Tags {
					tags[aws.ToString(t.TagKey)] = aws.ToString(t.TagValue)
				}
			}

			if !rotationEnabled {
				detail := "customer-managed key, rotation disabled, $1/mo"
				return []audit.Finding{{
					Service:              "kms",
					ResourceID:           keyID,
					Tags:                 tags,
					Check:                "unrotated_cmk",
					Status:               "WARN",
					Detail:               detail,
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: 1.0,
					Remediation: remediation.Recommend(
						"cost",
						"kms",
						"unrotated_cmk",
						keyID,
						detail,
					),
				}}
			}
			return nil
		},
	), nil
}
