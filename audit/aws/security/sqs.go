package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func init() {
	awsreg.Register(Module, "sqs", AuditSQS)
}

func AuditSQS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := sqs.NewFromConfig(cfg)

	resp, err := client.ListQueues(ctx, &sqs.ListQueuesInput{})
	if err != nil {
		return nil, fmt.Errorf("list queues: %w", err)
	}

	return audit.ProcessAllMulti(ctx, resp.QueueUrls, "Auditing SQS security",
		func(ctx context.Context, url string) []audit.Finding {
			name := url[strings.LastIndex(url, "/")+1:]

			attrs, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl: &url,
				AttributeNames: []sqstypes.QueueAttributeName{
					sqstypes.QueueAttributeNamePolicy,
					sqstypes.QueueAttributeNameKmsMasterKeyId,
					sqstypes.QueueAttributeNameSqsManagedSseEnabled,
				},
			})
			if err != nil {
				return []audit.Finding{audit.ErrorFinding("sqs", name, "get_attributes", err)}
			}

			var results []audit.Finding

			policy := attrs.Attributes["Policy"]
			if policy != "" &&
				(strings.Contains(policy, `"Principal":"*"`) || strings.Contains(policy, `"Principal": "*"`)) {
				d := "queue policy allows wildcard principal"
				results = append(results, audit.Finding{
					Service:     "sqs",
					ResourceID:  name,
					Check:       "public_access",
					Status:      "FAIL",
					Detail:      d,
					RiskLevel:   "CRITICAL",
					Remediation: remediation.Recommend("security", "sqs", "public_access", name, d),
				})
			}

			kmsKey := attrs.Attributes["KmsMasterKeyId"]
			sseManagedStr := attrs.Attributes["SqsManagedSseEnabled"]
			if kmsKey == "" && sseManagedStr != "true" {
				d := "server-side encryption disabled"
				results = append(results, audit.Finding{
					Service:     "sqs",
					ResourceID:  name,
					Check:       "no_encryption",
					Status:      "FAIL",
					Detail:      d,
					RiskLevel:   "HIGH",
					Remediation: remediation.Recommend("security", "sqs", "no_encryption", name, d),
				})
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "sqs",
					ResourceID: name,
					Check:      "sqs_posture",
					Status:     "PASS",
					Detail:     "encrypted=true, no public access",
					RiskLevel:  "MINIMAL",
				})
			}
			return results
		},
	), nil
}
