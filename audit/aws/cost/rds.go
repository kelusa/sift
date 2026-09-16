package cost

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/aws/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func init() {
	awsreg.Register(Module, "rds", AuditRDSCost)
}

type rdsCostInstance struct {
	id     string
	engine string
	class  string
	status string
	tags   map[string]string
}

func parseRDSCostInstance(db rdstypes.DBInstance) rdsCostInstance {
	tags := make(map[string]string, len(db.TagList))
	for _, t := range db.TagList {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return rdsCostInstance{
		id:     aws.ToString(db.DBInstanceIdentifier),
		engine: aws.ToString(db.Engine),
		class:  aws.ToString(db.DBInstanceClass),
		status: aws.ToString(db.DBInstanceStatus),
		tags:   tags,
	}
}

func AuditRDSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	rdsClient := rds.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	var allDBs []rdstypes.DBInstance
	paginator := rds.NewDescribeDBInstancesPaginator(rdsClient, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe db instances: %w", err)
		}
		for _, db := range page.DBInstances {
			if !strings.HasPrefix(aws.ToString(db.Engine), "docdb") {
				allDBs = append(allDBs, db)
			}
		}
	}

	return audit.ProcessAllMulti(
		ctx,
		allDBs,
		"Auditing RDS cost",
		func(ctx context.Context, db rdstypes.DBInstance) []audit.Finding {
			r := parseRDSCostInstance(db)
			if r.status == "stopped" {
				return []audit.Finding{{
					Service:    "rds",
					ResourceID: r.id,
					Tags:       r.tags,
					Check:      "stopped_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"engine=%s, storage still incurring cost",
						r.engine,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: pricing.RDSMonthly(r.class),
					Remediation: remediation.Recommend(
						"cost",
						"rds",
						"stopped_instance",
						r.id,
						"instance in stopped state",
					),
				}}
			}
			if r.status != "available" {
				return nil
			}
			var findings []audit.Finding

			// Graviton opportunity
			gravitonType, _, _, savings := pricing.RDSGravitonSavings(r.class)
			if gravitonType != "" && savings > 0 {
				findings = append(findings, audit.Finding{
					Service:    "rds",
					ResourceID: r.id,
					Tags:       r.tags,
					Check:      "graviton_opportunity",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"class=%s, switch to %s, save $%.0f/mo",
						r.class,
						gravitonType,
						savings,
					),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: savings,
					Remediation: remediation.Recommend(
						"cost",
						"rds",
						"graviton_opportunity",
						r.id,
						fmt.Sprintf("switch %s to %s", r.class, gravitonType),
					),
				})
			}

			avgCPU, err := getAvgCPU(ctx, cwClient, r.id, r.engine)
			if err != nil {
				findings = append(findings, audit.ErrorFinding("rds", r.id, "check_cpu", err))
				return findings
			}
			t := audit.GetThresholds(ctx)
			if avgCPU < t.GetFloat("rds", "cpu_idle_percent", 10) {
				findings = append(findings, audit.Finding{
					Service:    "rds",
					ResourceID: r.id,
					Tags:       r.tags,
					Check:      "oversized_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"class=%s, avg CPU=%.1f%% over %d days, consider downsizing",
						r.class,
						avgCPU,
						t.GetInt("rds", "cpu_lookback_days", 7),
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: pricing.RDSMonthly(r.class),
					Remediation: remediation.Recommend(
						"cost",
						"rds",
						"oversized_instance",
						r.id,
						fmt.Sprintf("avg CPU %.1f%%", avgCPU),
					),
				})
				return findings
			}
			findings = append(findings, audit.Finding{
				Service:    "rds",
				ResourceID: r.id,
				Tags:       r.tags,
				Check:      "oversized_instance",
				Status:     "PASS",
				Detail: fmt.Sprintf(
					"class=%s, avg CPU=%.1f%% over %d days",
					r.class,
					avgCPU,
					t.GetInt("rds", "cpu_lookback_days", 7),
				),
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: pricing.RDSMonthly(r.class),
			})
			return findings
		},
	), nil
}

func getAvgCPU(
	ctx context.Context,
	client *cloudwatch.Client,
	dbID, engine string,
) (float64, error) {
	end := time.Now()
	lookbackDays := audit.GetThresholds(ctx).GetInt("rds", "cpu_lookback_days", 7)
	start := end.AddDate(0, 0, -lookbackDays)

	namespace := "AWS/RDS"
	if strings.HasPrefix(engine, "docdb") {
		namespace = "AWS/DocDB"
	}

	resp, err := client.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String(namespace),
		MetricName: aws.String("CPUUtilization"),
		Dimensions: []cwtypes.Dimension{{
			Name:  aws.String("DBInstanceIdentifier"),
			Value: &dbID,
		}},
		StartTime:  &start,
		EndTime:    &end,
		Period:     aws.Int32(86400),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err != nil {
		return 0, err
	}

	if len(resp.Datapoints) == 0 {
		return 0, fmt.Errorf("no datapoints")
	}

	var total float64
	for _, dp := range resp.Datapoints {
		total += aws.ToFloat64(dp.Average)
	}
	return total / float64(len(resp.Datapoints)), nil
}
