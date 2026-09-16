package cost

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

func init() {
	awsreg.Register(Module, "waf", AuditWAFCost)
}

func AuditWAFCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := wafv2.NewFromConfig(cfg)

	var acls []waftypes.WebACLSummary
	for _, scope := range []waftypes.Scope{waftypes.ScopeRegional} {
		input := &wafv2.ListWebACLsInput{Scope: scope}
		for {
			resp, err := client.ListWebACLs(ctx, input)
			if err != nil {
				return nil, fmt.Errorf("list web acls: %w", err)
			}
			acls = append(acls, resp.WebACLs...)
			if resp.NextMarker == nil {
				break
			}
			input.NextMarker = resp.NextMarker
		}
	}

	return audit.ProcessAll(
		ctx,
		acls,
		"Auditing WAF cost",
		func(ctx context.Context, acl waftypes.WebACLSummary) audit.Finding {
			aclARN := aws.ToString(acl.ARN)
			name := aws.ToString(acl.Name)

			// Get tags
			var tags map[string]string
			tagResp, tagErr := client.ListTagsForResource(
				ctx,
				&wafv2.ListTagsForResourceInput{ResourceARN: &aclARN},
			)
			if tagErr == nil && tagResp.TagInfoForResource != nil {
				tags = make(map[string]string, len(tagResp.TagInfoForResource.TagList))
				for _, t := range tagResp.TagInfoForResource.TagList {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
			}

			resp, err := client.GetWebACL(ctx, &wafv2.GetWebACLInput{
				Name:  &name,
				Id:    acl.Id,
				Scope: waftypes.ScopeRegional,
			})
			if err != nil {
				return audit.ErrorFinding("waf", name, "get_web_acl", err)
			}

			ruleCount := len(resp.WebACL.Rules)

			// Check associations
			resResp, err := client.ListResourcesForWebACL(ctx, &wafv2.ListResourcesForWebACLInput{
				WebACLArn: &aclARN,
			})
			associated := 0
			if err == nil {
				associated = len(resResp.ResourceArns)
			}

			// $5/mo per ACL + $1/mo per rule
			monthlyCost := 5.0 + float64(ruleCount)

			if associated == 0 {
				detail := fmt.Sprintf(
					"rules=%d, no associated resources, $%.0f/mo waste",
					ruleCount,
					monthlyCost,
				)
				return audit.Finding{
					Service:              "waf",
					ResourceID:           name,
					Tags:                 tags,
					Check:                "unused_web_acl",
					Status:               "WARN",
					Detail:               detail,
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"waf",
						"unused_web_acl",
						name,
						"no associated resources",
					),
				}
			}
			return audit.Finding{
				Service:    "waf",
				ResourceID: name,
				Tags:       tags,
				Check:      "unused_web_acl",
				Status:     "PASS",
				Detail: fmt.Sprintf(
					"rules=%d, associated_resources=%d",
					ruleCount,
					associated,
				),
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: monthlyCost,
			}
		},
	), nil
}
