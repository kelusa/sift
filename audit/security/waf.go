package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

func init() {
	audit.RegisterAWS(Module, "waf", AuditWAF)
}

func AuditWAF(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := wafv2.NewFromConfig(cfg)

	var acls []waftypes.WebACLSummary
	input := &wafv2.ListWebACLsInput{Scope: waftypes.ScopeRegional}
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

	return audit.ProcessAllMulti(ctx, acls, "Auditing WAF security",
		func(ctx context.Context, acl waftypes.WebACLSummary) []audit.Finding {
			name := aws.ToString(acl.Name)
			resp, err := client.GetWebACL(
				ctx,
				&wafv2.GetWebACLInput{Name: &name, Id: acl.Id, Scope: waftypes.ScopeRegional},
			)
			if err != nil {
				return []audit.Finding{audit.ErrorFinding("waf", name, "get_web_acl", err)}
			}

			webACL := resp.WebACL
			defaultAllow := webACL.DefaultAction != nil && webACL.DefaultAction.Allow != nil
			ruleCount := len(webACL.Rules)
			hasRateLimit := false
			for _, r := range webACL.Rules {
				if r.Statement != nil && r.Statement.RateBasedStatement != nil {
					hasRateLimit = true
					break
				}
			}

			var results []audit.Finding
			if defaultAllow && ruleCount == 0 {
				d := "default action is ALLOW with no rules"
				results = append(
					results,
					audit.Finding{
						Service:     "waf",
						ResourceID:  name,
						Check:       "no_rules",
						Status:      "FAIL",
						Detail:      d,
						RiskLevel:   "CRITICAL",
						Remediation: remediation.Recommend("security", "waf", "no_rules", name, d),
					},
				)
			} else if defaultAllow && !hasRateLimit {
				d := fmt.Sprintf("default action is ALLOW, rules=%d, no rate-based rule", ruleCount)
				results = append(results, audit.Finding{Service: "waf", ResourceID: name, Check: "no_rate_limit", Status: "FAIL", Detail: d, RiskLevel: "HIGH", Remediation: remediation.Recommend("security", "waf", "no_rate_limit", name, d)})
			}
			if len(results) == 0 {
				results = append(
					results,
					audit.Finding{
						Service:    "waf",
						ResourceID: name,
						Check:      "waf_posture",
						Status:     "PASS",
						Detail: fmt.Sprintf(
							"rules=%d, has_rate_limit=%t",
							ruleCount,
							hasRateLimit,
						),
						RiskLevel: "MINIMAL",
					},
				)
			}
			return results
		},
	), nil
}
