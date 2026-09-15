package cost

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/aws/pricing"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func init() {
	audit.RegisterAWS(Module, "ec2", AuditEC2Cost)
}

type ec2CostInstance struct {
	id           string
	instanceType string
	tags         map[string]string
}

func parseEC2CostInstance(inst ec2types.Instance) ec2CostInstance {
	tags := make(map[string]string, len(inst.Tags))
	for _, t := range inst.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return ec2CostInstance{
		id:           aws.ToString(inst.InstanceId),
		instanceType: string(inst.InstanceType),
		tags:         tags,
	}
}

func AuditEC2Cost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := ec2.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)
	var findings []audit.Finding

	spinner := progress.NewSpinner(ctx, "Auditing EC2 cost")

	// Stopped instances
	stoppedPaginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{{
			Name:   aws.String("instance-state-name"),
			Values: []string{"stopped"},
		}},
	})
	for stoppedPaginator.HasMorePages() {
		page, err := stoppedPaginator.NextPage(ctx)
		if err != nil {
			spinner.Finish()
			return nil, fmt.Errorf("describe stopped instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				i := parseEC2CostInstance(inst)
				findings = append(findings, audit.Finding{
					Service:    "ec2",
					ResourceID: i.id,
					Tags:       i.tags,
					Check:      "stopped_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, EBS volumes still incurring cost",
						i.instanceType,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: pricing.EC2Monthly(i.instanceType),
					Remediation: remediation.Recommend(
						"cost",
						"ec2",
						"stopped_instance",
						i.id,
						"instance in stopped state",
					),
				})
			}
		}
	}

	// Collect running instances for type and util checks
	var running []ec2CostInstance
	runningPaginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{{
			Name:   aws.String("instance-state-name"),
			Values: []string{"running"},
		}},
	})
	for runningPaginator.HasMorePages() {
		page, err := runningPaginator.NextPage(ctx)
		if err != nil {
			spinner.Finish()
			return nil, fmt.Errorf("describe running instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				running = append(running, parseEC2CostInstance(inst))
			}
		}
	}

	spinner.Finish()

	// Previous gen check
	for _, i := range running {
		isPrevGen := false
		for _, prefix := range PrevGenPrefixes {
			if strings.HasPrefix(i.instanceType, prefix) {
				isPrevGen = true
				findings = append(findings, audit.Finding{
					Service:    "ec2",
					ResourceID: i.id,
					Tags:       i.tags,
					Check:      "previous_gen_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, consider upgrading",
						i.instanceType,
					),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: pricing.EC2Monthly(i.instanceType),
					Remediation: remediation.Recommend(
						"cost", "ec2", "previous_gen_instance", i.id, "previous-gen instance type",
					),
				})
				break
			}
		}
		if !isPrevGen {
			findings = append(findings, audit.Finding{
				Service:              "ec2",
				ResourceID:           i.id,
				Tags:                 i.tags,
				Check:                "previous_gen_instance",
				Status:               "PASS",
				Detail:               fmt.Sprintf("type=%s, current generation", i.instanceType),
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: pricing.EC2Monthly(i.instanceType),
			})
		}
	}

	// Graviton opportunity
	for _, i := range running {
		gravitonType, _, _, savings := pricing.GravitonSavings(i.instanceType)
		if gravitonType != "" && savings > 0 {
			findings = append(findings, audit.Finding{
				Service:    "ec2",
				ResourceID: i.id,
				Tags:       i.tags,
				Check:      "graviton_opportunity",
				Status:     "WARN",
				Detail: fmt.Sprintf(
					"type=%s, switch to %s, save $%.0f/mo",
					i.instanceType,
					gravitonType,
					savings,
				),
				RiskLevel:            "LOW",
				EstimatedMonthlyCost: savings,
				Remediation: remediation.Recommend(
					"cost",
					"ec2",
					"graviton_opportunity",
					i.id,
					fmt.Sprintf("switch %s to %s", i.instanceType, gravitonType),
				),
			})
		}
	}

	// Oversized instances (low CPU)
	cpuThreshold := t.GetFloat("ec2", "cpu_idle_percent", 10)
	lookback := t.GetInt("ec2", "cpu_lookback_days", 7)
	end := time.Now()
	start := end.AddDate(0, 0, -lookback)

	cpuFindings := audit.ProcessAllMulti(
		ctx,
		running,
		"Checking EC2 CPU utilization",
		func(ctx context.Context, i ec2CostInstance) []audit.Finding {
			resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/EC2"),
				MetricName: aws.String("CPUUtilization"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("InstanceId"),
					Value: aws.String(i.id),
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})
			if err != nil || len(resp.Datapoints) == 0 {
				return nil
			}
			var total float64
			for _, dp := range resp.Datapoints {
				total += aws.ToFloat64(dp.Average)
			}
			avgCPU := total / float64(len(resp.Datapoints))
			if avgCPU < cpuThreshold {
				detail := fmt.Sprintf(
					"type=%s, avg_cpu=%.1f%% over %d days",
					i.instanceType,
					avgCPU,
					lookback,
				)
				return []audit.Finding{{
					Service:              "ec2",
					ResourceID:           i.id,
					Tags:                 i.tags,
					Check:                "oversized_instance",
					Status:               "WARN",
					Detail:               detail,
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: pricing.EC2Monthly(i.instanceType),
					Remediation: remediation.Recommend(
						"cost",
						"ec2",
						"oversized_instance",
						i.id,
						fmt.Sprintf("avg CPU %.1f%%", avgCPU),
					),
				}}
			}
			return nil
		},
	)
	findings = append(findings, cpuFindings...)

	// Unused Elastic IPs
	addrs, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err == nil {
		for _, addr := range addrs.Addresses {
			if addr.AssociationId == nil {
				tags := make(map[string]string, len(addr.Tags))
				for _, t := range addr.Tags {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
				findings = append(findings, audit.Finding{
					Service:              "eip",
					ResourceID:           aws.ToString(addr.AllocationId),
					Tags:                 tags,
					Check:                "unused_elastic_ip",
					Status:               "WARN",
					Detail:               fmt.Sprintf("ip=%s", aws.ToString(addr.PublicIp)),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: pricing.ElasticIPMonthly(),
					Remediation: remediation.Recommend(
						"cost",
						"eip",
						"unused_elastic_ip",
						aws.ToString(addr.AllocationId),
						"EIP not associated",
					),
				})
			}
		}
	}

	return findings, nil
}
