package cost

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/aws/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func init() {
	audit.RegisterAWS(Module, "docdb", AuditDocDBCost)
}

func AuditDocDBCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	rdsClient := rds.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	var instances []rdstypes.DBInstance
	paginator := rds.NewDescribeDBInstancesPaginator(rdsClient, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe db instances: %w", err)
		}
		for _, db := range page.DBInstances {
			if strings.HasPrefix(aws.ToString(db.Engine), "docdb") {
				instances = append(instances, db)
			}
		}
	}

	lookback := t.GetInt("docdb", "cpu_lookback_days", 7)
	cpuThreshold := t.GetFloat("docdb", "cpu_idle_percent", 10)
	end := time.Now()
	start := end.AddDate(0, 0, -lookback)

	return audit.ProcessAllMulti(
		ctx,
		instances,
		"Auditing DocumentDB cost",
		func(ctx context.Context, db rdstypes.DBInstance) []audit.Finding {
			r := parseRDSCostInstance(db)
			var results []audit.Finding

			if r.status == "stopped" {
				return []audit.Finding{{
					Service:    "docdb",
					ResourceID: r.id,
					Tags:       r.tags,
					Check:      "stopped_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"class=%s, storage still incurring cost",
						r.class,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: pricing.RDSMonthly(r.class),
					Remediation: remediation.Recommend(
						"cost",
						"docdb",
						"stopped_instance",
						r.id,
						"instance in stopped state",
					),
				}}
			}

			if r.status != "available" {
				return nil
			}

			// Check connections
			connResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/DocDB"),
				MetricName: aws.String("DatabaseConnections"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("DBInstanceIdentifier"),
					Value: &r.id,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})

			var avgConns float64
			if connResp != nil && len(connResp.Datapoints) > 0 {
				var total float64
				for _, dp := range connResp.Datapoints {
					total += aws.ToFloat64(dp.Average)
				}
				avgConns = total / float64(len(connResp.Datapoints))
			}

			if avgConns == 0 {
				results = append(results, audit.Finding{
					Service:    "docdb",
					ResourceID: r.id,
					Tags:       r.tags,
					Check:      "idle_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"class=%s, zero connections over %d days",
						r.class,
						lookback,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: pricing.RDSMonthly(r.class),
					Remediation: remediation.Recommend(
						"cost",
						"docdb",
						"idle_instance",
						r.id,
						"zero database connections",
					),
				})
				return results
			}

			// Check CPU
			cpuResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/DocDB"),
				MetricName: aws.String("CPUUtilization"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("DBInstanceIdentifier"),
					Value: &r.id,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})

			if cpuResp != nil && len(cpuResp.Datapoints) > 0 {
				var total float64
				for _, dp := range cpuResp.Datapoints {
					total += aws.ToFloat64(dp.Average)
				}
				avgCPU := total / float64(len(cpuResp.Datapoints))
				if avgCPU < cpuThreshold {
					results = append(results, audit.Finding{
						Service:    "docdb",
						ResourceID: r.id,
						Tags:       r.tags,
						Check:      "oversized_instance",
						Status:     "WARN",
						Detail: fmt.Sprintf(
							"class=%s, avg CPU=%.1f%% over %d days, consider downsizing",
							r.class,
							avgCPU,
							lookback,
						),
						RiskLevel:            "HIGH",
						EstimatedMonthlyCost: pricing.RDSMonthly(r.class),
						Remediation: remediation.Recommend(
							"cost",
							"docdb",
							"oversized_instance",
							r.id,
							fmt.Sprintf("avg CPU %.1f%%", avgCPU),
						),
					})
				}
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "docdb",
					ResourceID: r.id,
					Tags:       r.tags,
					Check:      "docdb_cost",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"class=%s, avg_conns=%.0f, active",
						r.class,
						avgConns,
					),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: pricing.RDSMonthly(r.class),
				})
			}

			return results
		},
	), nil
}
