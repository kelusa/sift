package list

import (
	"context"
	"fmt"
	"strconv"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() {
	Register(Lister{
		Service: "ebs",
		Columns: map[string][]Column{
			"volume": {
				{Key: "type", Header: "TYPE"},
				{Key: "size_gb", Header: "SIZE(GB)"},
				{Key: "state", Header: "STATE"},
				{Key: "iops", Header: "IOPS"},
				{Key: "encrypted", Header: "ENCRYPTED"},
				{Key: "attached_to", Header: "ATTACHED TO"},
				{Key: "created", Header: "CREATED"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, _ string) ([]audit.Resource, error) {
			return ListEBSVolumes(ctx, cfg)
		},
	})
}

func ListEBSVolumes(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := ec2.NewFromConfig(cfg)

	var resources []audit.Resource
	paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe volumes: %w", err)
		}
		for _, v := range page.Volumes {
			tags := make(map[string]string, len(v.Tags))
			for _, t := range v.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}

			attached := ""
			if len(v.Attachments) > 0 {
				attached = aws.ToString(v.Attachments[0].InstanceId)
			}

			props := map[string]string{
				"type":        string(v.VolumeType),
				"size_gb":     strconv.Itoa(int(aws.ToInt32(v.Size))),
				"state":       string(v.State),
				"iops":        strconv.Itoa(int(aws.ToInt32(v.Iops))),
				"encrypted":   strconv.FormatBool(aws.ToBool(v.Encrypted)),
				"attached_to": attached,
			}
			if v.CreateTime != nil {
				props["created"] = v.CreateTime.Format("2006-01-02")
			}

			resources = append(resources, audit.Resource{
				Service:    "ebs",
				ResourceID: aws.ToString(v.VolumeId),
				Type:       "volume",
				Properties: props,
				Tags:       tags,
			})
		}
	}
	return resources, nil
}
