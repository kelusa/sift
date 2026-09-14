package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

func init() {
	audit.RegisterAWS(Module, "eventbridge", AuditEventBridgeCost)
}

func AuditEventBridgeCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := eventbridge.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	resp, err := client.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{})
	if err != nil {
		return nil, fmt.Errorf("list event buses: %w", err)
	}

	end := time.Now()
	start := end.AddDate(0, 0, -30)

	return audit.ProcessAll(ctx, resp.EventBuses, "Auditing EventBridge cost",
		func(ctx context.Context, bus ebtypes.EventBus) audit.Finding {
			name := aws.ToString(bus.Name)

			// Get tags
			var tags map[string]string
			if bus.Arn != nil {
				tagResp, tagErr := client.ListTagsForResource(
					ctx,
					&eventbridge.ListTagsForResourceInput{ResourceARN: bus.Arn},
				)
				if tagErr == nil {
					tags = make(map[string]string, len(tagResp.Tags))
					for _, t := range tagResp.Tags {
						tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
					}
				}
			}

			resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/Events"),
				MetricName: aws.String("Invocations"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("EventBusName"),
					Value: &name,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})
			if err != nil {
				return audit.ErrorFinding("eventbridge", name, "check_metrics", err)
			}

			var totalInvocations float64
			for _, dp := range resp.Datapoints {
				totalInvocations += aws.ToFloat64(dp.Sum)
			}

			if totalInvocations == 0 && name != "default" {
				detail := "zero rule invocations in 30 days"
				return audit.Finding{
					Service:    "eventbridge",
					ResourceID: name,
					Tags:       tags,
					Check:      "idle_bus",
					Status:     "WARN",
					Detail:     detail,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"cost", "eventbridge", "idle_bus", name, detail,
					),
				}
			}

			return audit.Finding{
				Service:    "eventbridge",
				ResourceID: name,
				Tags:       tags,
				Check:      "idle_bus",
				Status:     "PASS",
				Detail:     fmt.Sprintf("%.0f invocations in last 30 days", totalInvocations),
				RiskLevel:  "MINIMAL",
			}
		},
	), nil
}
