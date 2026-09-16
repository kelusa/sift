package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	ktypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
)

func init() {
	awsreg.Register(Module, "kinesis", AuditKinesis)
}

func AuditKinesis(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := kinesis.NewFromConfig(cfg)

	var streams []string
	input := &kinesis.ListStreamsInput{}
	for {
		resp, err := client.ListStreams(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list streams: %w", err)
		}
		for _, s := range resp.StreamSummaries {
			streams = append(streams, aws.ToString(s.StreamName))
		}
		if !aws.ToBool(resp.HasMoreStreams) {
			break
		}
		input.ExclusiveStartStreamName = &streams[len(streams)-1]
	}

	return audit.ProcessAll(ctx, streams, "Auditing Kinesis security",
		func(ctx context.Context, name string) audit.Finding {
			desc, err := client.DescribeStreamSummary(
				ctx,
				&kinesis.DescribeStreamSummaryInput{StreamName: &name},
			)
			if err != nil {
				return audit.ErrorFinding("kinesis", name, "describe_stream", err)
			}
			encType := desc.StreamDescriptionSummary.EncryptionType
			if encType == ktypes.EncryptionTypeNone || encType == "" {
				d := fmt.Sprintf("encryption_type=%s", encType)
				return audit.Finding{
					Service:    "kinesis",
					ResourceID: name,
					Check:      "no_encryption",
					Status:     "FAIL",
					Detail:     d,
					RiskLevel:  "HIGH",
					Remediation: remediation.Recommend(
						"security",
						"kinesis",
						"no_encryption",
						name,
						d,
					),
				}
			}
			return audit.Finding{
				Service:    "kinesis",
				ResourceID: name,
				Check:      "kinesis_posture",
				Status:     "PASS",
				Detail:     fmt.Sprintf("encryption_type=%s", encType),
				RiskLevel:  "MINIMAL",
			}
		},
	), nil
}
