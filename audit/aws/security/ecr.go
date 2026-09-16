package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func init() {
	awsreg.Register(Module, "ecr", AuditECR)
}

func AuditECR(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := ecr.NewFromConfig(cfg)

	var allRepos []ecrtypes.Repository
	paginator := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe repositories: %w", err)
		}
		allRepos = append(allRepos, page.Repositories...)
	}

	return audit.ProcessAllMulti(
		ctx,
		allRepos,
		"Auditing ECR security",
		func(ctx context.Context, repo ecrtypes.Repository) []audit.Finding {
			name := aws.ToString(repo.RepositoryName)
			arn := aws.ToString(repo.RepositoryArn)
			scanOnPush := repo.ImageScanningConfiguration != nil &&
				repo.ImageScanningConfiguration.ScanOnPush
			imageTagMutable := repo.ImageTagMutability == ecrtypes.ImageTagMutabilityMutable

			var tags map[string]string
			tagResp, err := client.ListTagsForResource(
				ctx,
				&ecr.ListTagsForResourceInput{ResourceArn: &arn},
			)
			if err == nil {
				tags = make(map[string]string, len(tagResp.Tags))
				for _, t := range tagResp.Tags {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
			}

			var results []audit.Finding

			if !scanOnPush {
				detail := "image scanning on push disabled"
				results = append(results, audit.Finding{
					Service:    "ecr",
					ResourceID: name,
					Tags:       tags,
					Check:      "no_scan_on_push",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"security",
						"ecr",
						"no_scan_on_push",
						name,
						detail,
					),
				})
			}

			if imageTagMutable {
				risk := "LOW"
				if !scanOnPush {
					risk = "HIGH"
				}
				detail := "image tags are mutable"
				results = append(results, audit.Finding{
					Service:    "ecr",
					ResourceID: name,
					Tags:       tags,
					Check:      "mutable_tags",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  risk,
					Remediation: remediation.Recommend(
						"security",
						"ecr",
						"mutable_tags",
						name,
						detail,
					),
				})
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "ecr",
					ResourceID: name,
					Tags:       tags,
					Check:      "ecr_posture",
					Status:     "PASS",
					Detail:     "scan_on_push=true, immutable_tags=true",
					RiskLevel:  "MINIMAL",
				})
			}

			return results
		},
	), nil
}
