package security

import (
	"context"
	"fmt"
	"strings"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
)

func init() {
	awsreg.Register(Module, "sagemaker", AuditSagemaker)
}

type sageMakerNotebook struct {
	name                 string
	status               string
	directInternetAccess bool
	subnetID             *string
	securityGroupIDs     []string
	roleARN              *string
}

func sagemakerRisk(directInternet, publicSubnet, sgOpen bool) string {
	switch {
	case directInternet:
		return "HIGH"
	case publicSubnet && sgOpen:
		return "HIGH"
	case publicSubnet:
		return "MEDIUM"
	case sgOpen:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

func AuditSagemaker(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	notebooks, err := listNotebooks(ctx, cfg)
	if err != nil {
		return nil, err
	}

	ec2Client := ec2.NewFromConfig(cfg)

	// Batch-fetch all SGs and deduplicate
	sgSet := make(map[string]bool)
	for _, nb := range notebooks {
		for _, id := range nb.securityGroupIDs {
			sgSet[id] = true
		}
	}
	var sgIDs []string
	for id := range sgSet {
		sgIDs = append(sgIDs, id)
	}
	openSGs := FindOpenSGs(ctx, ec2Client, sgIDs)

	// Batch-fetch route tables for all unique subnets
	subnetSet := make(map[string]bool)
	for _, nb := range notebooks {
		if nb.subnetID != nil {
			subnetSet[*nb.subnetID] = true
		}
	}
	publicSubnets := make(map[string]bool)
	if len(subnetSet) > 0 {
		var subnetIDs []string
		for id := range subnetSet {
			subnetIDs = append(subnetIDs, id)
		}
		rtResp, err := ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
			Filters: []ec2types.Filter{{
				Name:   aws.String("association.subnet-id"),
				Values: subnetIDs,
			}},
		})
		if err == nil {
			for _, rt := range rtResp.RouteTables {
				hasIGW := false
				for _, route := range rt.Routes {
					if route.GatewayId != nil && strings.HasPrefix(*route.GatewayId, "igw-") {
						hasIGW = true
						break
					}
				}
				if hasIGW {
					for _, assoc := range rt.Associations {
						if assoc.SubnetId != nil {
							publicSubnets[*assoc.SubnetId] = true
						}
					}
				}
			}
		}
	}

	return audit.ProcessAll(
		ctx,
		notebooks,
		"Auditing SageMaker exposure",
		func(_ context.Context, nb sageMakerNotebook) audit.Finding {
			sgOpen := false
			for _, id := range nb.securityGroupIDs {
				if openSGs[id] {
					sgOpen = true
					break
				}
			}
			publicSubnet := nb.subnetID != nil && publicSubnets[*nb.subnetID]
			risk := sagemakerRisk(nb.directInternetAccess, publicSubnet, sgOpen)
			detail := fmt.Sprintf(
				"status=%s, direct_internet=%t, public_subnet=%t, sg_open=%t",
				nb.status,
				nb.directInternetAccess,
				publicSubnet,
				sgOpen,
			)
			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend(
					"security",
					"sagemaker",
					"notebook_exposure",
					nb.name,
					detail,
				)
			}
			return audit.Finding{
				Service:     "sagemaker",
				ResourceID:  nb.name,
				Check:       "notebook_exposure",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	), nil
}

func listNotebooks(ctx context.Context, cfg aws.Config) ([]sageMakerNotebook, error) {
	client := sagemaker.NewFromConfig(cfg)

	var names []string
	input := &sagemaker.ListNotebookInstancesInput{}
	for {
		resp, err := client.ListNotebookInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list notebook instances: %w", err)
		}
		for _, nb := range resp.NotebookInstances {
			if nb.NotebookInstanceName != nil {
				names = append(names, *nb.NotebookInstanceName)
			}
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	results := audit.FetchAll(
		ctx,
		names,
		"Describing SageMaker notebooks",
		func(ctx context.Context, name string) sageMakerNotebook {
			desc, err := client.DescribeNotebookInstance(
				ctx,
				&sagemaker.DescribeNotebookInstanceInput{
					NotebookInstanceName: &name,
				},
			)
			if err != nil {
				return sageMakerNotebook{}
			}
			return sageMakerNotebook{
				name:                 name,
				status:               string(desc.NotebookInstanceStatus),
				directInternetAccess: string(desc.DirectInternetAccess) == "enabled",
				subnetID:             desc.SubnetId,
				securityGroupIDs:     desc.SecurityGroups,
				roleARN:              desc.RoleArn,
			}
		},
	)

	var filtered []sageMakerNotebook
	for _, nb := range results {
		if nb.name != "" {
			filtered = append(filtered, nb)
		}
	}
	return filtered, nil
}
