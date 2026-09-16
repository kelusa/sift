package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
)

func init() {
	awsreg.Register(Module, "msk", AuditMSK)
}

func AuditMSK(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := kafka.NewFromConfig(cfg)

	var clusters []kafkatypes.ClusterInfo
	input := &kafka.ListClustersInput{}
	for {
		resp, err := client.ListClusters(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list clusters: %w", err)
		}
		clusters = append(clusters, resp.ClusterInfoList...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	return audit.ProcessAll(ctx, clusters, "Auditing MSK security",
		func(ctx context.Context, c kafkatypes.ClusterInfo) audit.Finding {
			name := aws.ToString(c.ClusterName)
			arn := aws.ToString(c.ClusterArn)

			encInTransit := false
			encAtRest := false
			if c.EncryptionInfo != nil {
				if c.EncryptionInfo.EncryptionInTransit != nil {
					encInTransit = c.EncryptionInfo.EncryptionInTransit.ClientBroker == kafkatypes.ClientBrokerTls
				}
				if c.EncryptionInfo.EncryptionAtRest != nil {
					encAtRest = true
				}
			}

			hasAuth := false
			if c.ClientAuthentication != nil {
				if c.ClientAuthentication.Sasl != nil || c.ClientAuthentication.Tls != nil {
					hasAuth = true
				}
			}

			risk := "MINIMAL"
			status := "PASS"
			check := "msk_posture"

			if !encAtRest && !encInTransit && !hasAuth {
				risk = "CRITICAL"
				status = "FAIL"
				check = "no_encryption_no_auth"
			} else if !encInTransit && !hasAuth {
				risk = "HIGH"
				status = "FAIL"
				check = "no_transit_encryption"
			} else if !encAtRest {
				risk = "MEDIUM"
				status = "FAIL"
				check = "no_rest_encryption"
			} else if !hasAuth {
				risk = "LOW"
				status = "WARN"
				check = "no_atuh"
			}

			detail := fmt.Sprintf(
				"cluster=%s enc_at_rest=%t enc_in_transit=%t auth=%t",
				name,
				encAtRest,
				encInTransit,
				hasAuth,
			)

			f := audit.Finding{
				Service:    "msk",
				ResourceID: arn,
				Check:      check,
				Status:     status,
				Detail:     detail,
				RiskLevel:  risk,
			}
			if status != "PASS" {
				f.Remediation = remediation.Recommend("security", "msk", check, name, detail)
			}
			return f
		},
	), nil
}
