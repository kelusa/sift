package cost

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/aws/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
	dstypes "github.com/aws/aws-sdk-go-v2/service/directoryservice/types"
)

func init() {
	audit.RegisterAWS(Module, "directory", AuditDirectoryCost)
}

func AuditDirectoryCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := directoryservice.NewFromConfig(cfg)

	var directories []dstypes.DirectoryDescription
	input := &directoryservice.DescribeDirectoriesInput{}
	for {
		resp, err := client.DescribeDirectories(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe directories: %w", err)
		}
		directories = append(directories, resp.DirectoryDescriptions...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	return audit.ProcessAll(
		ctx,
		directories,
		"Auditing Directory Service cost",
		func(ctx context.Context, d dstypes.DirectoryDescription) audit.Finding {
			id := aws.ToString(d.DirectoryId)
			name := aws.ToString(d.Name)
			dirType := string(d.Type)
			size := string(d.Size)
			monthlyCost := pricing.DirectoryMonthly(dirType, size)
			resourceID := fmt.Sprintf("%s (%s)", name, id)

			// Get tags
			var tags map[string]string
			tagResp, tagErr := client.ListTagsForResource(
				ctx,
				&directoryservice.ListTagsForResourceInput{ResourceId: &id},
			)
			if tagErr == nil {
				tags = make(map[string]string, len(tagResp.Tags))
				for _, t := range tagResp.Tags {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
			}

			if d.Stage == dstypes.DirectoryStageActive && len(d.DnsIpAddrs) == 0 {
				return audit.Finding{
					Service:    "directory",
					ResourceID: resourceID,
					Tags:       tags,
					Check:      "idle_directory",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, size=%s, no DNS IPs - likely unused",
						dirType,
						size,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"directory",
						"idle_directory",
						id,
						"no DNS IPs configured",
					),
				}
			}

			return audit.Finding{
				Service:              "directory",
				ResourceID:           resourceID,
				Tags:                 tags,
				Check:                "idle_directory",
				Status:               "PASS",
				Detail:               fmt.Sprintf("type-%s, size=%s, active", dirType, size),
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: monthlyCost,
			}
		},
	), nil
}
