package cost

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func init() {
	audit.RegisterAWS(Module, "sqs", AuditSQSCost)
}

func AuditSQSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := sqs.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	var urls []string
	input := &sqs.ListQueuesInput{}
	for {
		resp, err := client.ListQueues(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list queues: %w", err)
		}
		urls = append(urls, resp.QueueUrls...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	end := time.Now()
	start := end.AddDate(0, 0, -30)

	return audit.ProcessAll(ctx, urls, "Auditing SQS cost",
		func(ctx context.Context, url string) audit.Finding {
			name := url[strings.LastIndex(url, "/")+1:]

			// Get tags
			var tags map[string]string
			tagResp, err := client.ListQueueTags(ctx, &sqs.ListQueueTagsInput{QueueUrl: &url})
			if err == nil {
				tags = tagResp.Tags
			}

			// Get approximate messages to detect stuck DLQs
			attrs, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl: &url,
				AttributeNames: []sqstypes.QueueAttributeName{
					sqstypes.QueueAttributeNameApproximateNumberOfMessages,
				},
			})
			msgCount := ""
			if err == nil {
				msgCount = attrs.Attributes["ApproximateNumberOfMessages"]
			}

			// Check NumberOfMessagesSent over 30 days
			resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/SQS"),
				MetricName: aws.String("NumberOfMessagesSent"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("QueueName"),
					Value: &name,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})
			if err != nil {
				return audit.ErrorFinding("sqs", name, "check_metrics", err)
			}

			var totalSent float64
			for _, dp := range resp.Datapoints {
				totalSent += aws.ToFloat64(dp.Sum)
			}

			if totalSent == 0 {
				detail := "zero messages sent in 30 days"
				if msgCount != "" && msgCount != "0" {
					detail += fmt.Sprintf(", %s stuck messages", msgCount)
				}
				return audit.Finding{
					Service:    "sqs",
					ResourceID: name,
					Tags:       tags,
					Check:      "idle_queue",
					Status:     "WARN",
					Detail:     detail,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"cost", "sqs", "idle_queue", name, detail,
					),
				}
			}

			return audit.Finding{
				Service:    "sqs",
				ResourceID: name,
				Tags:       tags,
				Check:      "idle_queue",
				Status:     "PASS",
				Detail:     fmt.Sprintf("%.0f messages sent in last 30 days", totalSent),
				RiskLevel:  "MINIMAL",
			}
		},
	), nil
}
