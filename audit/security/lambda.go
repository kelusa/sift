package security

import (
	"context"
	"fmt"
	"strings"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

func init() {
	audit.RegisterAWS(Module, "lambda", AuditLambda)
}

var deprecatedRuntimes = map[string]bool{
	"python2.7":     true,
	"python3.6":     true,
	"python3.7":     true,
	"nodejs10.x":    true,
	"nodejs12.x":    true,
	"nodejs14.x":    true,
	"dotnetcore2.1": true,
	"dotnetcore3.1": true,
	"ruby2.5":       true,
	"ruby2.7":       true,
	"java8":         true,
	"go1.x":         true,
	"provided":      true,
}

func AuditLambda(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := lambda.NewFromConfig(cfg)

	var allFunctions []lambdatypes.FunctionConfiguration
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list functions: %w", err)
		}
		allFunctions = append(allFunctions, page.Functions...)
	}

	return audit.ProcessAllMulti(
		ctx,
		allFunctions,
		"Auditing Lambda functions",
		func(ctx context.Context, fn lambdatypes.FunctionConfiguration) []audit.Finding {
			name := aws.ToString(fn.FunctionName)
			runtime := string(fn.Runtime)

			var tags map[string]string
			tagResp, err := client.ListTags(ctx, &lambda.ListTagsInput{Resource: fn.FunctionArn})
			if err == nil {
				tags = tagResp.Tags
			}

			hasPublicURL := false
			authType := ""
			urlResp, err := client.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{
				FunctionName: &name,
			})
			if err == nil && urlResp.FunctionUrl != nil {
				hasPublicURL = true
				authType = string(urlResp.AuthType)
			}
			deprecated := deprecatedRuntimes[runtime]

			var results []audit.Finding

			if hasPublicURL {
				risk := "MEDIUM"
				if strings.ToUpper(authType) == "NONE" {
					risk = "CRITICAL"
				}
				detail := fmt.Sprintf(
					"url=%s, auth=%s",
					aws.ToString(urlResp.FunctionUrl),
					authType,
				)
				results = append(results, audit.Finding{
					Service:    "lambda",
					ResourceID: name,
					Tags:       tags,
					Check:      "public_function_url",
					Status:     statusFromRisk(risk),
					Detail:     detail,
					RiskLevel:  risk,
					Remediation: remediation.Recommend(
						"security",
						"lambda",
						"public_function_url",
						name,
						detail,
					),
				})
			}
			if deprecated {
				detail := fmt.Sprintf("runtime=%s, no longer receives security patches", runtime)
				results = append(results, audit.Finding{
					Service:    "lambda",
					ResourceID: name,
					Tags:       tags,
					Check:      "deprecated_runtime",
					Status:     statusFromRisk("HIGH"),
					Detail:     detail,
					RiskLevel:  "HIGH",
					Remediation: remediation.Recommend(
						"security",
						"lambda",
						"deprecated_runtime",
						name,
						detail,
					),
				})
			}
			if !hasPublicURL && !deprecated {
				results = append(results, audit.Finding{
					Service:    "lambda",
					ResourceID: name,
					Tags:       tags,
					Check:      "deprecated_runtime",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"runtime=%s, no public URL, supported runtime",
						runtime,
					),
					RiskLevel: "MINIMAL",
				})
			}
			return results
		},
	), nil
}
