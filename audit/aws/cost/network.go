package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/aws/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func init() {
	awsreg.Register(Module, "network", AuditNetworkCost)
}

type natGatewayEntry struct {
	id   string
	tags map[string]string
}

func parseNATGateway(nat ec2types.NatGateway) natGatewayEntry {
	tags := make(map[string]string, len(nat.Tags))
	for _, t := range nat.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return natGatewayEntry{
		id:   aws.ToString(nat.NatGatewayId),
		tags: tags,
	}
}

func AuditNetworkCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	var findings []audit.Finding

	nat, err := findIdleNATGateways(ctx, cfg)
	if err == nil {
		findings = append(findings, nat...)
	}

	vpce, err := findIdleVPCEndpoints(ctx, cfg)
	if err == nil {
		findings = append(findings, vpce...)
	}

	return findings, nil
}

func findIdleNATGateways(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	ec2Client := ec2.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	var allNATs []ec2types.NatGateway
	natPaginator := ec2.NewDescribeNatGatewaysPaginator(ec2Client, &ec2.DescribeNatGatewaysInput{})
	for natPaginator.HasMorePages() {
		page, err := natPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe nat gateways: %w", err)
		}
		allNATs = append(allNATs, page.NatGateways...)
	}

	var available []natGatewayEntry
	for _, nat := range allNATs {
		if string(nat.State) != "available" {
			available = append(available, parseNATGateway(nat))
		}
	}

	end := time.Now()
	start := end.AddDate(0, 0, -7)

	results := audit.ProcessAll(
		ctx,
		available,
		"Auditing NAT Gateways",
		func(ctx context.Context, n natGatewayEntry) audit.Finding {
			metricResp, err := cwClient.GetMetricStatistics(
				ctx,
				&cloudwatch.GetMetricStatisticsInput{
					Namespace:  aws.String("AWS/NATGateway"),
					MetricName: aws.String("BytesOutToDestination"),
					Dimensions: []cwtypes.Dimension{{
						Name:  aws.String("NatGatewayId"),
						Value: &n.id,
					}},
					StartTime:  &start,
					EndTime:    &end,
					Period:     aws.Int32(86400),
					Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
				},
			)
			if err != nil {
				return audit.ErrorFinding("nat_gateway", n.id, "check_traffic", err)
			}
			totalBytes := 0.0

			for _, dp := range metricResp.Datapoints {
				totalBytes += aws.ToFloat64(dp.Sum)
			}

			if totalBytes == 0 {
				return audit.Finding{
					Service:              "nat_gateway",
					ResourceID:           n.id,
					Tags:                 n.tags,
					Check:                "idle_nat_gateway",
					Status:               "WARN",
					Detail:               "zero bytes processed in last 7 days (~$32/mo waste)",
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: pricing.NATGatewayMonthly(),
					Remediation: remediation.Recommend(
						"cost",
						"nat_gateway",
						"idle_nat_gateway",
						n.id,
						"zero bytes over 7 days",
					),
				}
			}
			return audit.Finding{
				Service:    "nat_gateway",
				ResourceID: n.id,
				Tags:       n.tags,
				Check:      "idle_nat_gateway",
				Status:     "PASS",
				Detail: fmt.Sprintf(
					"%.2f GB processed in last 7 days",
					totalBytes/(1024*1024*1024),
				),
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: pricing.NATGatewayMonthly(),
			}
		},
	)

	return results, nil
}

func findIdleVPCEndpoints(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	ec2Client := ec2.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	var endpoints []ec2types.VpcEndpoint
	input := &ec2.DescribeVpcEndpointsInput{}
	for {
		resp, err := ec2Client.DescribeVpcEndpoints(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe vpc endpoints: %w", err)
		}
		endpoints = append(endpoints, resp.VpcEndpoints...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	// Filter to interface endpoints only (gateway endpoints are free)
	var ifaceEndpoints []ec2types.VpcEndpoint
	for _, ep := range endpoints {
		if ep.VpcEndpointType == ec2types.VpcEndpointTypeInterface {
			ifaceEndpoints = append(ifaceEndpoints, ep)
		}
	}

	end := time.Now()
	start := end.AddDate(0, 0, -30)

	return audit.ProcessAll(
		ctx,
		ifaceEndpoints,
		"Auditing VPC endpoints",
		func(ctx context.Context, ep ec2types.VpcEndpoint) audit.Finding {
			id := aws.ToString(ep.ServiceName)
			svcName := aws.ToString(ep.ServiceName)
			azCount := len(ep.SubnetIds)
			monthlyCost := float64(azCount) * 7.30

			tags := make(map[string]string, len(ep.Tags))
			for _, t := range ep.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}

			resp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/PrivateLinkEndpoints"),
				MetricName: aws.String("BytesProcessed"),
				Dimensions: []cwtypes.Dimension{
					{Name: aws.String("VPC Endpoint Id"), Value: &id},
					{Name: aws.String("Endpoint Type"), Value: aws.String("Interface")},
				},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})

			var totalBytes float64
			if resp != nil {
				for _, dp := range resp.Datapoints {
					totalBytes += aws.ToFloat64(dp.Sum)
				}
			}

			if totalBytes == 0 {
				return audit.Finding{
					Service:    "vpc_endpoint",
					ResourceID: id,
					Tags:       tags,
					Check:      "idle_vpc_endpoint",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"service=%s, azs=%d, zero bytes in 30 days, $%.0f/mo waste",
						svcName,
						azCount,
						monthlyCost,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"vpc_endpoint",
						"idle_vpc_endpoint",
						id,
						"zero bytes processed in 30 days",
					),
				}
			}
			return audit.Finding{
				Service:    "vpc_endpoint",
				ResourceID: id,
				Tags:       tags,
				Check:      "idle_vpc_endpoint",
				Status:     "PASS",
				Detail: fmt.Sprintf(
					"service=%s, azs=%d, %.2f GB in 30 days",
					svcName,
					azCount,
					totalBytes/(1024*1024*1024),
				),
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: monthlyCost,
			}
		},
	), nil
}
