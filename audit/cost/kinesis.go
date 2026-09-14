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
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
)

func init() {
	audit.RegisterAWS(Module, "kinesis", AuditKinesisCost)
}

func AuditKinesisCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := kinesis.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

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

	end := time.Now()
	start := end.AddDate(0, 0, -30)

	return audit.ProcessAll(
		ctx,
		streams,
		"Auditing Kinesis cost",
		func(ctx context.Context, name string) audit.Finding {
			desc, err := client.DescribeStreamSummary(
				ctx,
				&kinesis.DescribeStreamSummaryInput{StreamName: &name},
			)
			if err != nil {
				return audit.ErrorFinding("kinesis", name, "describe_stream", err)
			}

			// Get tags
			var tags map[string]string
			tagResp, tagErr := client.ListTagsForStream(
				ctx,
				&kinesis.ListTagsForStreamInput{StreamName: &name},
			)
			if tagErr == nil {
				tags = make(map[string]string, len(tagResp.Tags))
				for _, t := range tagResp.Tags {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
			}

			shards := aws.ToInt32(desc.StreamDescriptionSummary.OpenShardCount)
			monthlyCost := float64(shards) * 11.0 // ~$11/shard/mo

			// Check IncomingRecords
			resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/Kinesis"),
				MetricName: aws.String("IncomingRecords"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("StreamName"),
					Value: &name,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})
			if err != nil {
				return audit.ErrorFinding("kinesis", name, "check_metrics", err)
			}

			var totalRecords float64
			for _, dp := range resp.Datapoints {
				totalRecords += aws.ToFloat64(dp.Sum)
			}

			if totalRecords == 0 {
				return audit.Finding{
					Service:    "kinesis",
					ResourceID: name,
					Tags:       tags,
					Check:      "idle_stream",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"shards=%d, zero records in last 30 days, $%.0f/mo waste",
						shards,
						monthlyCost,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"kinesis",
						"idle_stream",
						name,
						"zero incoming records in 30 days",
					),
				}
			}

			return audit.Finding{
				Service:    "kinesis",
				ResourceID: name,
				Tags:       tags,
				Check:      "idle_stream",
				Status:     "PASS",
				Detail: fmt.Sprintf(
					"shards=%d, %.0f records in last 30 days",
					shards,
					totalRecords,
				),
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: monthlyCost,
			}
		},
	), nil
}
