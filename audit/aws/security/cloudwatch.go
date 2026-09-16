package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

func init() {
	awsreg.Register(Module, "cloudwatch", AuditCloudWatch)
}

func AuditCloudWatch(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := cloudwatchlogs.NewFromConfig(cfg)

	var groups []cwltypes.LogGroup

	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(
		client,
		&cloudwatchlogs.DescribeLogGroupsInput{},
	)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe log groups: %w", err)
		}
		groups = append(groups, page.LogGroups...)
	}

	return audit.ProcessAll(ctx, groups, "Auditing CloudWatch security",
		func(ctx context.Context, g cwltypes.LogGroup) audit.Finding {
			name := aws.ToString(g.LogGroupName)

			if g.KmsKeyId == nil || *g.KmsKeyId == "" {
				detail := fmt.Sprintf("log_group=%s encrypted=false", name)
				return audit.Finding{
					Service:    "cloudwatch",
					ResourceID: name,
					Check:      "no_encryption",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"security",
						"cloudwatch",
						"no_encryption",
						name,
						detail,
					),
				}
			}

			return audit.Finding{
				Service:    "cloudwatch",
				ResourceID: name,
				Check:      "cloudwatch_posture",
				Status:     "PASS",
				Detail:     fmt.Sprintf("log_group=%s encrypted=true", name),
				RiskLevel:  "MINIMAL",
			}
		},
	), nil
}
