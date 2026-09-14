package list

import (
	"context"
	"fmt"
	"strconv"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

func init() {
	Register(Lister{
		Service: "elb",
		Columns: map[string][]Column{
			"loadbalancer": {
				{Key: "type", Header: "TYPE"},
				{Key: "scheme", Header: "SCHEME"},
				{Key: "state", Header: "STATE"},
				{Key: "targets", Header: "TARGETS"},
				{Key: "dns", Header: "DNS"},
				{Key: "created", Header: "CREATED"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, _ string) ([]audit.Resource, error) {
			return ListELBs(ctx, cfg)
		},
	})
}

func ListELBs(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := elbv2.NewFromConfig(cfg)

	var resources []audit.Resource
	paginator := elbv2.NewDescribeLoadBalancersPaginator(
		client,
		&elbv2.DescribeLoadBalancersInput{},
	)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe load balancers: %w", err)
		}
		for _, lb := range page.LoadBalancers {
			// Count target groups
			tgResp, _ := client.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
				LoadBalancerArn: lb.LoadBalancerArn,
			})
			tgCount := 0
			if tgResp != nil {
				tgCount = len(tgResp.TargetGroups)
			}

			state := ""
			if lb.State != nil {
				state = string(lb.State.Code)
			}

			props := map[string]string{
				"type":    string(lb.Type),
				"scheme":  string(lb.Scheme),
				"state":   state,
				"targets": strconv.Itoa(tgCount),
				"dns":     aws.ToString(lb.DNSName),
			}
			if lb.CreatedTime != nil {
				props["created"] = lb.CreatedTime.Format("2006-01-02")
			}

			resources = append(resources, audit.Resource{
				Service:    "elb",
				ResourceID: aws.ToString(lb.LoadBalancerName),
				Type:       "loadbalancer",
				Properties: props,
			})
		}
	}
	return resources, nil
}
