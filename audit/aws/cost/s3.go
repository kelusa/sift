package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/aws/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func init() {
	audit.RegisterAWS(Module, "s3", AuditS3Cost)
}

type s3CostBucket struct {
	name   string
	sizeGB float64
	tags   map[string]string
}

func parseS3CostBucket(
	ctx context.Context,
	client *s3.Client,
	cwClient *cloudwatch.Client,
	name string,
) s3CostBucket {
	b := s3CostBucket{name: name}
	tagResp, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &name})
	if err == nil {
		b.tags = make(map[string]string, len(tagResp.TagSet))
		for _, t := range tagResp.TagSet {
			b.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}

	// Fetch bucket size from Cloudwatch
	end := time.Now()
	start := end.AddDate(0, 0, -2)
	resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/S3"),
		MetricName: aws.String("BucketSizeBytes"),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("BucketName"), Value: &name},
			{Name: aws.String("StorageType"), Value: aws.String("StandardStorage")},
		},
		StartTime:  &start,
		EndTime:    &end,
		Period:     aws.Int32(86400),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err == nil && len(resp.Datapoints) > 0 {
		// Use most recent datapoint
		latest := resp.Datapoints[0]
		for _, dp := range resp.Datapoints[1:] {
			if dp.Timestamp.After(*latest.Timestamp) {
				latest = dp
			}
		}
		b.sizeGB = aws.ToFloat64(latest.Average) / (1024 * 1024 * 1024)
	}

	return b
}

func AuditS3Cost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := s3.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	resp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var names []string
	for _, b := range resp.Buckets {
		if b.Name != nil {
			names = append(names, *b.Name)
		}
	}
	return audit.ProcessAllMulti(
		ctx,
		names,
		"Auditing S3 cost",
		func(ctx context.Context, name string) []audit.Finding {
			bucket := parseS3CostBucket(ctx, client, cwClient, name)
			monthlyCost := pricing.S3Monthly(bucket.sizeGB)

			var results []audit.Finding

			_, err := client.GetBucketLifecycleConfiguration(
				ctx,
				&s3.GetBucketLifecycleConfigurationInput{Bucket: &name},
			)
			if err != nil {
				results = append(results, audit.Finding{
					Service:    "s3",
					ResourceID: bucket.name,
					Tags:       bucket.tags,
					Check:      "no_lifecycle_policy",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"size=%.2fGB, data may grow indefinitely without expiration rules",
						bucket.sizeGB,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"s3",
						"no_lifecycle_policy",
						bucket.name,
						"no lifecycle policy configured",
					),
				})
			} else {
				results = append(results, audit.Finding{
					Service:              "s3",
					ResourceID:           bucket.name,
					Tags:                 bucket.tags,
					Check:                "no_lifecycle_policy",
					Status:               "PASS",
					Detail:               fmt.Sprintf("size=%.2fGB, lifecycle policy configured", bucket.sizeGB),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: monthlyCost,
				})
			}

			// Check read activity via GetRequests metric
			end := time.Now()
			start := end.AddDate(0, 0, -30)
			metricsResp, err := cwClient.GetMetricStatistics(
				ctx,
				&cloudwatch.GetMetricStatisticsInput{
					Namespace:  aws.String("AWS/S3"),
					MetricName: aws.String("GetRequests"),
					Dimensions: []cwtypes.Dimension{
						{Name: aws.String("BucketName"), Value: &name},
						{Name: aws.String("FilterId"), Value: aws.String("EntireBucket")},
					},
					StartTime:  &start,
					EndTime:    &end,
					Period:     aws.Int32(86400),
					Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
				},
			)
			if err != nil || len(metricsResp.Datapoints) == 0 {
				results = append(results, audit.Finding{
					Service:              "s3",
					ResourceID:           bucket.name,
					Tags:                 bucket.tags,
					Check:                "read_activity",
					Status:               "WARN",
					Detail:               "request metrics not enabled - unable to determine read activity",
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"s3",
						"read_activity",
						bucket.name,
						"request metrics not enabled",
					),
				})
				// Check incomplete multipart uploads
				mpResp, err := client.ListMultipartUploads(
					ctx,
					&s3.ListMultipartUploadsInput{Bucket: &name},
				)
				if err == nil && len(mpResp.Uploads) > 0 {
					oldCount := 0
					for _, u := range mpResp.Uploads {
						if u.Initiated != nil && time.Since(*u.Initiated).Hours() > 24*7 {
							oldCount++
						}
					}
					if oldCount > 0 {
						results = append(results, audit.Finding{
							Service:    "s3",
							ResourceID: bucket.name,
							Tags:       bucket.tags,
							Check:      "incomplete_multipart_uploads",
							Status:     "WARN",
							Detail: fmt.Sprintf(
								"%d incomplete multipart uploads older than 7 days",
								oldCount,
							),
							RiskLevel: "LOW",
							Remediation: remediation.Recommend(
								"cost",
								"s3",
								"incomplete_multipart_uploads",
								bucket.name,
								fmt.Sprintf("%d stale uploads", oldCount),
							),
						})
					}
				}
				return results
			}

			var totalGets float64
			for _, dp := range metricsResp.Datapoints {
				totalGets += aws.ToFloat64(dp.Sum)
			}
			if totalGets == 0 {
				results = append(results, audit.Finding{
					Service:    "s3",
					ResourceID: bucket.name,
					Tags:       bucket.tags,
					Check:      "read_activity",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"size=%.2fGB, zero GetRequests in last 30 days - no consumers",
						bucket.sizeGB,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: monthlyCost,
				})
			} else {
				results = append(results, audit.Finding{
					Service:              "s3",
					ResourceID:           bucket.name,
					Tags:                 bucket.tags,
					Check:                "read_activity",
					Status:               "PASS",
					Detail:               fmt.Sprintf("%.0f GetRequests in last 30 days", totalGets),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: monthlyCost,
				})
			}

			return results
		},
	), nil
}
