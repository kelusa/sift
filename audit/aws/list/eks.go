package list

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

func init() {
	Register(Lister{
		Service: "eks",
		Columns: map[string][]Column{
			"cluster": {
				{Key: "version", Header: "VERSION"},
				{Key: "status", Header: "STATUS"},
				{Key: "endpoint_public", Header: "PUBLIC"},
				{Key: "endpoint_private", Header: "PRIVATE"},
				{Key: "nodegroups", Header: "NGS"},
				{Key: "total_nodes", Header: "NODES"},
				{Key: "instance_types", Header: "INSTANCE TYPES"},
				{Key: "created", Header: "CREATED"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, _ string) ([]audit.Resource, error) {
			return ListEKSClusters(ctx, cfg)
		},
	})
}

func ListEKSClusters(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := eks.NewFromConfig(cfg)
	spinner := progress.NewSpinner(ctx, "Listing EKS clusters")

	var names []string
	input := &eks.ListClustersInput{}
	for {
		resp, err := client.ListClusters(ctx, input)
		if err != nil {
			spinner.Finish()
			return nil, fmt.Errorf("list clusters: %w", err)
		}
		names = append(names, resp.Clusters...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	var resources []audit.Resource
	for _, name := range names {
		desc, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
		if err != nil {
			spinner.Add(1)
			continue
		}
		c := desc.Cluster

		props := map[string]string{
			"version": aws.ToString(c.Version),
			"status":  string(c.Status),
		}
		if c.ResourcesVpcConfig != nil {
			props["endpoint_public"] = strconv.FormatBool(c.ResourcesVpcConfig.EndpointPublicAccess)
			props["endpoint_private"] = strconv.FormatBool(
				c.ResourcesVpcConfig.EndpointPrivateAccess,
			)
		}
		if c.CreatedAt != nil {
			props["created"] = c.CreatedAt.Format("2006-01-02")
		}

		// Count nodegroups and total nodes
		var ngNames []string
		ngInput := &eks.ListNodegroupsInput{ClusterName: &name}
		for {
			ngResp, err := client.ListNodegroups(ctx, ngInput)
			if err != nil {
				break
			}
			ngNames = append(ngNames, ngResp.Nodegroups...)
			if ngResp.NextToken == nil {
				break
			}
			ngInput.NextToken = ngResp.NextToken
		}
		props["nodegroups"] = strconv.Itoa(len(ngNames))

		var totalNodes int32
		var instanceTypes []string
		for _, ngName := range ngNames {
			ngDesc, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
				ClusterName:   &name,
				NodegroupName: &ngName,
			})
			if err != nil {
				continue
			}
			ng := ngDesc.Nodegroup
			if ng.ScalingConfig != nil {
				totalNodes += aws.ToInt32(ng.ScalingConfig.DesiredSize)
			}
			if len(ng.InstanceTypes) > 0 {
				instanceTypes = append(instanceTypes, ng.InstanceTypes...)
			} else if ng.LaunchTemplate != nil {
				lt := ng.LaunchTemplate
				ltInput := &ec2svc.DescribeLaunchTemplateVersionsInput{}
				if lt.Id != nil {
					ltInput.LaunchTemplateId = lt.Id
				} else if lt.Name != nil {
					ltInput.LaunchTemplateName = lt.Name
				}
				if ltInput.LaunchTemplateId != nil || ltInput.LaunchTemplateName != nil {
					if lt.Version != nil {
						ltInput.Versions = []string{*lt.Version}
					} else {
						ltInput.Versions = []string{"$Default"}
					}
					ec2Client := ec2svc.NewFromConfig(cfg)
					ltResp, ltErr := ec2Client.DescribeLaunchTemplateVersions(ctx, ltInput)
					if ltErr == nil && len(ltResp.LaunchTemplateVersions) > 0 {
						if data := ltResp.LaunchTemplateVersions[0].LaunchTemplateData; data != nil && data.InstanceType != "" {
							instanceTypes = append(instanceTypes, string(data.InstanceType))
						}
					}
				}
			}
		}
		props["total_nodes"] = strconv.Itoa(int(totalNodes))
		if len(instanceTypes) > 0 {
			props["instance_types"] = strings.Join(unique(instanceTypes), ",")
		}

		resources = append(resources, audit.Resource{
			Service:    "eks",
			ResourceID: name,
			Type:       "cluster",
			Properties: props,
			Tags:       c.Tags,
		})
		spinner.Add(1)
	}
	spinner.Finish()
	return resources, nil
}

func unique(s []string) []string {
	seen := make(map[string]bool, len(s))
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
