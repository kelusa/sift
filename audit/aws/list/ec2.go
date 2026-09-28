package list

import (
	"context"
	"fmt"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func init() {
	Register(Lister{
		Service: "ec2",
		Columns: map[string][]Column{
			"instance": {
				{Key: "name", Header: "NAME"},
				{Key: "type", Header: "TYPE"},
				{Key: "state", Header: "STATE"},
				{Key: "public_ip", Header: "PUBLIC IP"},
				{Key: "private_ip", Header: "PRIVATE IP"},
				{Key: "vpc_id", Header: "VPC"},
				{Key: "iam_role", Header: "IAM ROLE"},
				{Key: "launched", Header: "LAUNCHED"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, _ string) ([]audit.Resource, error) {
			return ListEC2Instances(ctx, cfg)
		},
	})
}

func ListEC2Instances(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := ec2.NewFromConfig(cfg)

	var instances []ec2types.Instance
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, r := range page.Reservations {
			instances = append(instances, r.Instances...)
		}
	}

	resources := make([]audit.Resource, 0, len(instances))
	for _, inst := range instances {
		name := ""
		tags := make(map[string]string, len(inst.Tags))
		for _, t := range inst.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			if aws.ToString(t.Key) == "Name" {
				name = aws.ToString(t.Value)
			}
		}

		role := ""
		if inst.IamInstanceProfile != nil {
			arn := aws.ToString(inst.IamInstanceProfile.Arn)
			// Extract role name from arn:aws:iam::123:instance-profile/role-name
			for i := len(arn) - 1; i >= 0; i-- {
				if arn[i] == '/' {
					role = arn[i+1:]
					break
				}
			}
		}

		props := map[string]string{
			"name":       name,
			"type":       string(inst.InstanceType),
			"state":      string(inst.State.Name),
			"public_ip":  aws.ToString(inst.PublicIpAddress),
			"private_ip": aws.ToString(inst.PrivateIpAddress),
			"vpc_id":     aws.ToString(inst.VpcId),
			"iam_role":   role,
		}
		if inst.LaunchTime != nil {
			props["launched"] = inst.LaunchTime.Format("2006-01-02")
		}

		resources = append(resources, audit.Resource{
			Service:    "ec2",
			ResourceID: aws.ToString(inst.InstanceId),
			Type:       "instance",
			Properties: props,
			Tags:       tags,
		})
	}
	return resources, nil
}
