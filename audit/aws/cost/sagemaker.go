package cost

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/aws/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	smtypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
)

func init() {
	audit.RegisterAWS(Module, "sagemaker", AuditSagemakerCost)
}

type sagemakerCostEntry struct {
	name         string
	status       string
	instanceType string
}

func parseSagemakerCostEntry(
	desc *sagemaker.DescribeNotebookInstanceOutput,
	name string,
) sagemakerCostEntry {
	return sagemakerCostEntry{
		name:         name,
		status:       string(desc.NotebookInstanceStatus),
		instanceType: string(desc.InstanceType),
	}
}

func AuditSagemakerCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
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

	return audit.ProcessAll(
		ctx,
		names,
		"Auditing SageMaker cost",
		func(ctx context.Context, name string) audit.Finding {
			desc, err := client.DescribeNotebookInstance(
				ctx,
				&sagemaker.DescribeNotebookInstanceInput{
					NotebookInstanceName: &name,
				},
			)
			if err != nil {
				return audit.ErrorFinding("sagemaker", name, "describe", err)
			}
			e := parseSagemakerCostEntry(desc, name)

			// Get tags
			var tags map[string]string
			if desc.NotebookInstanceArn != nil {
				tagResp, tagErr := client.ListTags(
					ctx,
					&sagemaker.ListTagsInput{ResourceArn: desc.NotebookInstanceArn},
				)
				if tagErr == nil {
					tags = make(map[string]string, len(tagResp.Tags))
					for _, t := range tagResp.Tags {
						tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
					}
				}
			}

			monthlyCost := pricing.SageMakerMonthly(e.instanceType)

			switch smtypes.NotebookInstanceStatus(e.status) {
			case smtypes.NotebookInstanceStatusStopped:
				return audit.Finding{
					Service:    "sagemaker",
					ResourceID: e.name,
					Tags:       tags,
					Check:      "stopped_notebook",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, stopped but EBS storage still incurring cost",
						e.instanceType,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: monthlyCost * 0.1,
					Remediation: remediation.Recommend(
						"cost",
						"sagemaker",
						"stopped_notebook",
						e.name,
						"notebook stopped but EBS still billed",
					),
				}
			case smtypes.NotebookInstanceStatusInService:
				return audit.Finding{
					Service:              "sagemaker",
					ResourceID:           e.name,
					Tags:                 tags,
					Check:                "running_notebook",
					Status:               "PASS",
					Detail:               fmt.Sprintf("type=%s in service", e.instanceType),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: monthlyCost,
				}
			default:
				return audit.Finding{
					Service:    "sagemaker",
					ResourceID: e.name,
					Tags:       tags,
					Check:      "notebook_status",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"type=%s, status=%s",
						e.instanceType,
						e.status,
					),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: monthlyCost,
				}
			}
		},
	), nil
}
