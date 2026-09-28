package cost

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/aws/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func init() {
	awsreg.Register(Module, "ecr", AuditECRCost)
}

type ecrRepo struct {
	name string
	arn  string
	tags map[string]string
}

func AuditECRCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
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

	return audit.ProcessAll(
		ctx,
		allRepos,
		"Auditing ECR cost",
		func(ctx context.Context, repo ecrtypes.Repository) audit.Finding {
			r := parseECRRepo(ctx, client, repo)
			_, err := client.GetLifecyclePolicy(
				ctx,
				&ecr.GetLifecyclePolicyInput{RepositoryName: &r.name},
			)
			if err != nil {
				imgResp, _ := client.DescribeImages(
					ctx,
					&ecr.DescribeImagesInput{RepositoryName: &r.name},
				)
				imgCount := 0
				var totalSizeGB float64
				if imgResp != nil {
					imgCount = len(imgResp.ImageDetails)
					for _, img := range imgResp.ImageDetails {
						if img.ImageSizeInBytes != nil {
							totalSizeGB += float64(*img.ImageSizeInBytes) / (1024 * 1024 * 1024)
						}
					}
				}
				return audit.Finding{
					Service:    "ecr",
					ResourceID: r.name,
					Tags:       r.tags,
					Check:      "no_lifecycle_policy",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"images=%d, size=%.2fGB, old images never cleaned up",
						imgCount,
						totalSizeGB,
					),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: pricing.ECRMonthly(totalSizeGB),
					Remediation: remediation.Recommend(
						"cost",
						"ecr",
						"no_lifecycle_policy",
						r.name,
						"no lifecycle policy",
					),
				}
			}
			return audit.Finding{
				Service:    "ecr",
				ResourceID: r.name,
				Tags:       r.tags,
				Check:      "no_lifecycle_policy",
				Status:     "PASS",
				Detail:     "lifecycle policy configured",
				RiskLevel:  "MINIMAL",
			}
		},
	), nil
}

func parseECRRepo(ctx context.Context, client *ecr.Client, repo ecrtypes.Repository) ecrRepo {
	r := ecrRepo{
		name: aws.ToString(repo.RepositoryName),
		arn:  aws.ToString(repo.RepositoryArn),
	}
	tagResp, err := client.ListTagsForResource(
		ctx,
		&ecr.ListTagsForResourceInput{ResourceArn: &r.arn},
	)
	if err == nil {
		r.tags = make(map[string]string, len(tagResp.Tags))
		for _, t := range tagResp.Tags {
			r.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	return r
}
