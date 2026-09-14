package cost

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

func init() {
	audit.RegisterAWS(Module, "elb", AuditELBCost)
}

type elbCostEntry struct {
	name   string
	arn    string
	lbType string
	tags   map[string]string
}

func parseELBCostEntry(
	ctx context.Context,
	client *elbv2.Client,
	lb elbtypes.LoadBalancer,
) elbCostEntry {
	e := elbCostEntry{
		name:   aws.ToString(lb.LoadBalancerName),
		arn:    aws.ToString(lb.LoadBalancerArn),
		lbType: string(lb.Type),
	}
	tagResp, err := client.DescribeTags(
		ctx,
		&elbv2.DescribeTagsInput{ResourceArns: []string{e.arn}},
	)
	if err == nil {
		for _, desc := range tagResp.TagDescriptions {
			e.tags = make(map[string]string, len(desc.Tags))
			for _, t := range desc.Tags {
				e.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
		}
	}
	return e
}

// extractLBDimension extracts the ALB/NLB dimension value from the ARN.
// e.g "arn:aws:elasticloadbalancing:...:loadbalancer/app/my-lb/abc123" -> "app/my-lb/abc123"
func extractLBDimension(arn string) string {
	parts := strings.SplitN(arn, ":loadbalancer/", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func AuditELBCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	elbClient := elbv2.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	var allLBs []elbtypes.LoadBalancer
	paginator := elbv2.NewDescribeLoadBalancersPaginator(
		elbClient,
		&elbv2.DescribeLoadBalancersInput{},
	)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe load balancers: %w", err)
		}
		allLBs = append(allLBs, page.LoadBalancers...)
	}

	end := time.Now()
	start := end.AddDate(0, 0, -30)

	return audit.ProcessAllMulti(
		ctx,
		allLBs,
		"Auditing ELB cost",
		func(ctx context.Context, lb elbtypes.LoadBalancer) []audit.Finding {
			e := parseELBCostEntry(ctx, elbClient, lb)
			dim := extractLBDimension(e.arn)
			if dim == "" {
				return []audit.Finding{{
					Service:    "elb",
					ResourceID: e.name,
					Tags:       e.tags,
					Check:      "idle_lb",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"type=%s, unable to extract dimension",
						e.lbType,
					),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: pricing.ELBMonthly(e.lbType),
				}}
			}
			// Check for no targets
			tgResp, err := elbClient.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
				LoadBalancerArn: &e.arn,
			})
			if err == nil && len(tgResp.TargetGroups) == 0 {
				return []audit.Finding{{
					Service:    "elb",
					ResourceID: e.name,
					Tags:       e.tags,
					Check:      "no_targets",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, no target groups attached",
						e.lbType,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: pricing.ELBMonthly(e.lbType),
					Remediation: remediation.Recommend(
						"cost",
						"elb",
						"no_targets",
						e.arn,
						"no target groups attached",
					),
				}}
			}
			// Check traffic
			metricName := "RequestCount"
			namespace := "AWS/ApplicationELB"
			dimName := "LoadBalancer"
			if e.lbType == "network" {
				metricName = "ActiveFlowCount"
				namespace = "AWS/NetworkELB"
			}
			resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  &namespace,
				MetricName: &metricName,
				Dimensions: []cwtypes.Dimension{{
					Name:  &dimName,
					Value: &dim,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})
			if err != nil {
				return []audit.Finding{{
					Service:              "elb",
					ResourceID:           e.name,
					Tags:                 e.tags,
					Check:                "idle_lb",
					Status:               "PASS",
					Detail:               fmt.Sprintf("type=%s, unable to fetch metrics", e.lbType),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: pricing.ELBMonthly(e.lbType),
				}}
			}
			total := 0.0
			for _, dp := range resp.Datapoints {
				total += aws.ToFloat64(dp.Sum)
			}
			if total == 0 {
				return []audit.Finding{{
					Service:    "elb",
					ResourceID: e.name,
					Tags:       e.tags,
					Check:      "idle_lb",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, zero traffic in last 30 days (~$16-22/mo waste)",
						e.lbType,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: pricing.ELBMonthly(e.lbType),
					Remediation: remediation.Recommend(
						"cost",
						"elb",
						"idle_lb",
						e.name,
						"zero traffic over 30 days",
					),
				}}
			}
			return []audit.Finding{{
				Service:              "elb",
				ResourceID:           e.name,
				Tags:                 e.tags,
				Check:                "idle_lb",
				Status:               "PASS",
				Detail:               fmt.Sprintf("type=%s, active traffic", e.lbType),
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: pricing.ELBMonthly(e.lbType),
			}}
		},
	), nil
}
