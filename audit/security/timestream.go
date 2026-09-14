package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/timestreamwrite"
)

func init() {
	audit.RegisterAWS(Module, "timestream", AuditTimestream)
}

func AuditTimestream(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := timestreamwrite.NewFromConfig(cfg)

	var findings []audit.Finding
	dbInput := &timestreamwrite.ListDatabasesInput{}
	for {
		resp, err := client.ListDatabases(ctx, dbInput)
		if err != nil {
			return nil, fmt.Errorf("list databases: %w", err)
		}
		for _, db := range resp.Databases {
			name := aws.ToString(db.DatabaseName)
			arn := aws.ToString(db.Arn)
			kmsKey := aws.ToString(db.KmsKeyId)

			// AWS-managed key means no customer-managed encryption
			isCustomerKey := kmsKey != "" && !isAWSManagedKey(kmsKey)

			if !isCustomerKey {
				detail := fmt.Sprintf("database=%s encryption=aws_managed", name)
				findings = append(findings, audit.Finding{
					Service:    "timestream",
					ResourceID: arn,
					Check:      "no_cmk_encryption",
					Status:     "WARN",
					Detail:     detail,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"security",
						"timestream",
						"no_cmk_encryption",
						name,
						detail,
					),
				})
			} else {
				findings = append(findings, audit.Finding{
					Service:    "timestream",
					ResourceID: arn,
					Check:      "timestream_posture",
					Status:     "PASS",
					Detail:     fmt.Sprintf("database=%s encryption=cmk", name),
					RiskLevel:  "MINIMAL",
				})
			}
		}
		if resp.NextToken == nil {
			break
		}
		dbInput.NextToken = resp.NextToken
	}
	return findings, nil
}

func isAWSManagedKey(keyID string) bool {
	// AWS managed keys contain "alias/aws" or are the default service key
	return len(keyID) > 0 && (keyID == "alias/aws/timestream" || keyID[:4] != "arn:")
}
