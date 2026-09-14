package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

func init() {
	audit.RegisterAWS(Module, "sns", AuditSNS)
}

func AuditSNS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := sns.NewFromConfig(cfg)

	var topics []string
	input := &sns.ListTopicsInput{}
	for {
		resp, err := client.ListTopics(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list topics: %w", err)
		}
		for _, t := range resp.Topics {
			topics = append(topics, aws.ToString(t.TopicArn))
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	return audit.ProcessAllMulti(ctx, topics, "Auditing SNS security",
		func(ctx context.Context, arn string) []audit.Finding {
			name := arn[strings.LastIndex(arn, ":")+1:]

			attrs, err := client.GetTopicAttributes(
				ctx,
				&sns.GetTopicAttributesInput{TopicArn: &arn},
			)
			if err != nil {
				return []audit.Finding{audit.ErrorFinding("sns", name, "get_attributes", err)}
			}

			var results []audit.Finding

			policy := attrs.Attributes["Policy"]
			if policy != "" &&
				(strings.Contains(policy, `"Principal":"*"`) || strings.Contains(policy, `"Principal": "*"`)) {
				d := "topic policy allows wildcard principal"
				results = append(results, audit.Finding{
					Service:     "sns",
					ResourceID:  name,
					Check:       "public_access",
					Status:      "FAIL",
					Detail:      d,
					RiskLevel:   "CRITICAL",
					Remediation: remediation.Recommend("security", "sns", "public_access", name, d),
				})
			}

			kmsKey := attrs.Attributes["KmsMasterKeyId"]
			if kmsKey == "" {
				d := "server-side encryption disabled"
				results = append(results, audit.Finding{
					Service:     "sns",
					ResourceID:  name,
					Check:       "no_encryption",
					Status:      "FAIL",
					Detail:      d,
					RiskLevel:   "HIGH",
					Remediation: remediation.Recommend("security", "sns", "no_encryption", name, d),
				})
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "sns",
					ResourceID: name,
					Check:      "sns_posture",
					Status:     "PASS",
					Detail:     "encrypted=true, no public access",
					RiskLevel:  "MINIMAL",
				})
			}
			return results
		},
	), nil
}
