package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

func init() {
	audit.RegisterAWS(Module, "lambda", AuditLambdaCost)
}

type lambdaCostFunction struct {
	name     string
	arn      string
	memoryMB int32
	tags     map[string]string
}

func AuditLambdaCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := lambda.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	var allFunctions []lambdatypes.FunctionConfiguration
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list functions: %w", err)
		}
		allFunctions = append(allFunctions, page.Functions...)
	}

	end := time.Now()
	start := end.AddDate(0, 0, -30)

	return audit.ProcessAllMulti(
		ctx,
		allFunctions,
		"Auditing Lambda cost",
		func(ctx context.Context, fn lambdatypes.FunctionConfiguration) []audit.Finding {
			f := parseLambdaCostFunction(ctx, client, fn)

			invResp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/Lambda"),
				MetricName: aws.String("Invocations"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("FunctionName"),
					Value: &f.name,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(2592000),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})
			if err != nil {
				return []audit.Finding{
					audit.ErrorFinding("lambda", f.name, "check_invocations", err),
				}
			}

			totalInvocations := 0.0
			for _, dp := range invResp.Datapoints {
				totalInvocations += aws.ToFloat64(dp.Sum)
			}

			var results []audit.Finding

			if totalInvocations == 0 {
				results = append(results, audit.Finding{
					Service:    "lambda",
					ResourceID: f.name,
					Tags:       f.tags,
					Check:      "unused_function",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"memory=%dMB, zero invocations in last 30 days",
						f.memoryMB,
					),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: 0,
					Remediation: remediation.Recommend(
						"cost",
						"lambda",
						"unused_function",
						f.name,
						"zero invocations in last 30 days",
					),
				})
			}
			pcResp, err := client.ListProvisionedConcurrencyConfigs(
				ctx,
				&lambda.ListProvisionedConcurrencyConfigsInput{FunctionName: &f.name},
			)
			if err == nil {
				for _, pc := range pcResp.ProvisionedConcurrencyConfigs {
					allocated := aws.ToInt32(pc.AllocatedProvisionedConcurrentExecutions)
					if allocated > 0 && totalInvocations == 0 {
						results = append(results, audit.Finding{
							Service:    "lambda",
							ResourceID: f.name,
							Tags:       f.tags,
							Check:      "unused_provisioned_concurrency",
							Status:     "WARN",
							Detail: fmt.Sprintf(
								"allocated=%d, zero invocations in last 30 days",
								allocated,
							),
							RiskLevel: "HIGH",
							EstimatedMonthlyCost: pricing.LambdaProvisionedMonthly(
								f.memoryMB,
								allocated,
							),
							Remediation: remediation.Recommend(
								"cost",
								"lambda",
								"unused_provisioned_concurrency",
								f.name,
								"zero invocations with provisioned concurrency",
							),
						})
					}
				}
			}
			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "lambda",
					ResourceID: f.name,
					Tags:       f.tags,
					Check:      "unused_function",
					Status:     "PASS",
					Detail:     fmt.Sprintf("memory=%dMB, active in last 30 days", f.memoryMB),
					RiskLevel:  "MINIMAL",
				})
			}
			return results
		},
	), nil
}

func parseLambdaCostFunction(
	ctx context.Context,
	client *lambda.Client,
	fn lambdatypes.FunctionConfiguration,
) lambdaCostFunction {
	f := lambdaCostFunction{
		name:     aws.ToString(fn.FunctionName),
		arn:      aws.ToString(fn.FunctionArn),
		memoryMB: aws.ToInt32(fn.MemorySize),
	}
	tagResp, err := client.ListTags(ctx, &lambda.ListTagsInput{Resource: fn.FunctionArn})
	if err == nil {
		f.tags = tagResp.Tags
	}
	return f
}
