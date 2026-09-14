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
	"github.com/aws/aws-sdk-go-v2/service/timestreamwrite"
)

func init() {
	audit.RegisterAWS(Module, "timestream", AuditTimestreamCost)
}

func AuditTimestreamCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := timestreamwrite.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	var databases []string
	dbInput := &timestreamwrite.ListDatabasesInput{}
	for {
		resp, err := client.ListDatabases(ctx, dbInput)
		if err != nil {
			return nil, fmt.Errorf("list databases: %w", err)
		}
		for _, db := range resp.Databases {
			databases = append(databases, aws.ToString(db.DatabaseName))
		}
		if resp.NextToken == nil {
			break
		}
		dbInput.NextToken = resp.NextToken
	}

	type tsTable struct {
		database         string
		table            string
		arn              string
		memRetentionHrs  int64
		magRetentionDays int64
	}

	var tables []tsTable
	for _, db := range databases {
		tblInput := &timestreamwrite.ListTablesInput{DatabaseName: &db}
		for {
			resp, err := client.ListTables(ctx, tblInput)
			if err != nil {
				break
			}
			for _, t := range resp.Tables {
				var memHrs, magDays int64
				if t.RetentionProperties != nil {
					memHrs = aws.ToInt64(t.RetentionProperties.MemoryStoreRetentionPeriodInHours)
					magDays = aws.ToInt64(t.RetentionProperties.MagneticStoreRetentionPeriodInDays)
				}
				tables = append(tables, tsTable{
					database:         db,
					table:            aws.ToString(t.TableName),
					arn:              *t.Arn,
					memRetentionHrs:  memHrs,
					magRetentionDays: magDays,
				})
			}
			if resp.NextToken == nil {
				break
			}
			tblInput.NextToken = resp.NextToken
		}
	}

	end := time.Now()
	start := end.AddDate(0, 0, -30)

	return audit.ProcessAll(
		ctx,
		tables,
		"Auditing Timestream cost",
		func(ctx context.Context, t tsTable) audit.Finding {
			resourceID := fmt.Sprintf("%s/%s", t.database, t.table)

			// Get tags
			var tags map[string]string
			if t.arn != "" {
				tagResp, tagErr := client.ListTagsForResource(
					ctx,
					&timestreamwrite.ListTagsForResourceInput{ResourceARN: &t.arn},
				)
				if tagErr == nil {
					tags = make(map[string]string, len(tagResp.Tags))
					for _, tag := range tagResp.Tags {
						tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
					}
				}
			}

			// Check write records
			writeResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/Timestream"),
				MetricName: aws.String("SuccessfulRequestLatency"),
				Dimensions: []cwtypes.Dimension{
					{Name: aws.String("DatabaseName"), Value: &t.database},
					{Name: aws.String("TableName"), Value: &t.table},
					{Name: aws.String("Operation"), Value: aws.String("WriteRecords")},
				},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSampleCount},
			})

			var totalWrites float64
			if writeResp != nil {
				for _, dp := range writeResp.Datapoints {
					totalWrites += aws.ToFloat64(dp.SampleCount)
				}
			}

			if totalWrites == 0 {
				detail := fmt.Sprintf(
					"memory_retention=%dh, magnetic_retention=%dd, zero writes in 30 days",
					t.memRetentionHrs,
					t.magRetentionDays,
				)
				return audit.Finding{
					Service:    "timestream",
					ResourceID: resourceID,
					Tags:       tags,
					Check:      "idle_table",
					Status:     "WARN",
					Detail:     detail,
					RiskLevel:  "HIGH",
					Remediation: remediation.Recommend(
						"cost",
						"timestream",
						"idle_table",
						resourceID,
						"zero writes in 30 days",
					),
				}
			}

			// Flag long memory retention (>24h is expensive)
			if t.memRetentionHrs > 24 {
				detail := fmt.Sprintf(
					"memory_retention=%dh (expensive at $0.50/GB/hr), consider reducing",
					t.memRetentionHrs,
				)
				return audit.Finding{
					Service:    "timestream",
					ResourceID: resourceID,
					Tags:       tags,
					Check:      "high_memory_retention",
					Status:     "WARN",
					Detail:     detail,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"cost",
						"timestream",
						"high_memory_retention",
						resourceID,
						fmt.Sprintf("memory retention %dh", t.memRetentionHrs),
					),
				}
			}

			return audit.Finding{
				Service:    "timestream",
				ResourceID: resourceID,
				Tags:       tags,
				Check:      "timestream_cost",
				Status:     "PASS",
				Detail:     fmt.Sprintf("memory_retention=%dh, active writes", t.memRetentionHrs),
				RiskLevel:  "MINIMAL",
			}
		},
	), nil
}
