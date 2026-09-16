package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

func init() {
	awsreg.Register(Module, "cloudfront", AuditCloudFrontCost)
}

func AuditCloudFrontCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := cloudfront.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg, func(o *cloudwatch.Options) {
		o.Region = "us-east-1" // CloudFront metrics are in us-east-1
	})

	var distributions []cftypes.DistributionSummary
	input := &cloudfront.ListDistributionsInput{}
	for {
		resp, err := client.ListDistributions(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list distributions: %w", err)
		}
		if resp.DistributionList != nil {
			distributions = append(distributions, resp.DistributionList.Items...)
			if aws.ToBool(resp.DistributionList.IsTruncated) {
				input.Marker = resp.DistributionList.NextMarker
				continue
			}
		}
		break
	}

	return audit.ProcessAll(ctx, distributions, "Auditing CloudFront cost",
		func(ctx context.Context, d cftypes.DistributionSummary) audit.Finding {
			id := aws.ToString(d.Id)
			domain := aws.ToString(d.DomainName)

			// Check requests over last 30 days
			end := time.Now()
			start := end.AddDate(0, 0, -30)
			metricsResp, _ := cwClient.GetMetricStatistics(
				ctx,
				&cloudwatch.GetMetricStatisticsInput{
					Namespace:  aws.String("AWS/CloudFront"),
					MetricName: aws.String("Requests"),
					Dimensions: []cwtypes.Dimension{
						{Name: aws.String("DistributionId"), Value: aws.String(id)},
						{Name: aws.String("Region"), Value: aws.String("Global")},
					},
					StartTime:  &start,
					EndTime:    &end,
					Period:     aws.Int32(86400 * 30),
					Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
				},
			)

			totalRequests := 0.0
			if metricsResp != nil {
				for _, dp := range metricsResp.Datapoints {
					totalRequests += aws.ToFloat64(dp.Sum)
				}
			}

			if totalRequests == 0 {
				detail := fmt.Sprintf("distribution=%s domain=%s requests=0 (30d)", id, domain)
				return audit.Finding{
					Service:    "cloudfront",
					ResourceID: id,
					Check:      "idle_distribution",
					Status:     "WARN",
					Detail:     detail,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"cost",
						"cloudfront",
						"idle_distribution",
						id,
						detail,
					),
				}
			}

			return audit.Finding{
				Service:    "cloudfront",
				ResourceID: id,
				Check:      "cloudfront_cost",
				Status:     "PASS",
				Detail:     fmt.Sprintf("distribution=%s requests=%.0f (30d)", id, totalRequests),
				RiskLevel:  "MINIMAL",
			}
		},
	), nil
}
