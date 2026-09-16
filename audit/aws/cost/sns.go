package cost

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

func init() {
	awsreg.Register(Module, "sns", AuditSNSCost)
}

func AuditSNSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := sns.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

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

	end := time.Now()
	start := end.AddDate(0, 0, -30)

	return audit.ProcessAll(ctx, topics, "Auditing SNS cost",
		func(ctx context.Context, arn string) audit.Finding {
			name := arn[strings.LastIndex(arn, ":")+1:]

			// Get tags
			var tags map[string]string
			tagResp, tagErr := client.ListTagsForResource(
				ctx,
				&sns.ListTagsForResourceInput{ResourceArn: &arn},
			)
			if tagErr == nil {
				tags = make(map[string]string, len(tagResp.Tags))
				for _, t := range tagResp.Tags {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
			}

			resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/SNS"),
				MetricName: aws.String("NumberOfMessagesPublished"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("TopicName"),
					Value: &name,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})
			if err != nil {
				return audit.ErrorFinding("sns", name, "check_metrics", err)
			}

			var totalPublished float64
			for _, dp := range resp.Datapoints {
				totalPublished += aws.ToFloat64(dp.Sum)
			}

			if totalPublished == 0 {
				detail := "zero messages published in 30 days"
				return audit.Finding{
					Service:    "sns",
					ResourceID: name,
					Tags:       tags,
					Check:      "idle_topic",
					Status:     "WARN",
					Detail:     detail,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"cost", "sns", "idle_topic", name, detail,
					),
				}
			}

			return audit.Finding{
				Service:    "sns",
				ResourceID: name,
				Tags:       tags,
				Check:      "idle_topic",
				Status:     "PASS",
				Detail:     fmt.Sprintf("%.0f messages published in last 30 days", totalPublished),
				RiskLevel:  "MINIMAL",
			}
		},
	), nil
}
