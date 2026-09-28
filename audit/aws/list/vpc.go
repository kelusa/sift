package list

import (
	"context"
	"fmt"
	"math"
	"strconv"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() {
	Register(Lister{
		Service:  "vpc",
		SubTypes: []string{"subnets"},
		Columns: map[string][]Column{
			"subnet": {
				{Key: "vpc_id", Header: "VPC"},
				{Key: "az", Header: "AZ"},
				{Key: "cidr", Header: "CIDR"},
				{Key: "available_ips", Header: "AVAILABLE"},
				{Key: "total_ips", Header: "TOTAL"},
				{Key: "usage_pct", Header: "USAGE%"},
				{Key: "name", Header: "NAME"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, _ string) ([]audit.Resource, error) {
			return ListVPCSubnets(ctx, cfg)
		},
	})
}

func ListVPCSubnets(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := ec2.NewFromConfig(cfg)
	spinner := progress.NewSpinner(ctx, "Listing VPC subnets")

	var resources []audit.Resource
	input := &ec2.DescribeSubnetsInput{}
	for {
		resp, err := client.DescribeSubnets(ctx, input)
		if err != nil {
			spinner.Finish()
			return nil, fmt.Errorf("describe subnets: %w", err)
		}
		for _, s := range resp.Subnets {
			total := cidrUsable(aws.ToString(s.CidrBlock))
			avail := int(aws.ToInt32(s.AvailableIpAddressCount))
			usage := 0.0
			if total > 0 {
				usage = float64(total-avail) / float64(total) * 100
			}

			name := ""
			tags := make(map[string]string, len(s.Tags))
			for _, t := range s.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				if aws.ToString(t.Key) == "Name" {
					name = aws.ToString(t.Value)
				}
			}

			props := map[string]string{
				"vpc_id":        aws.ToString(s.VpcId),
				"az":            aws.ToString(s.AvailabilityZone),
				"cidr":          aws.ToString(s.CidrBlock),
				"available_ips": strconv.Itoa(avail),
				"total_ips":     strconv.Itoa(total),
				"usage_pct":     fmt.Sprintf("%.0f", usage),
				"name":          name,
			}

			resources = append(resources, audit.Resource{
				Service:    "vpc",
				ResourceID: aws.ToString(s.SubnetId),
				Type:       "subnet",
				Properties: props,
				Tags:       tags,
			})
		}
		spinner.Add(len(resp.Subnets))
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	spinner.Finish()
	return resources, nil
}

// cidrUsable returns usable IPs (total - 5 AWS reserved).
func cidrUsable(cidr string) int {
	for i := len(cidr) - 1; i >= 0; i-- {
		if cidr[i] == '/' {
			prefix, _ := strconv.Atoi(cidr[i+1:])
			total := int(math.Pow(2, float64(32-prefix))) - 5
			if total < 0 {
				return 0
			}
			return total
		}
	}
	return 0
}
