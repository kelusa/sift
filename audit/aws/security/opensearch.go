package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
)

func init() {
	awsreg.Register(Module, "opensearch", AuditOpenSearch)
}

func AuditOpenSearch(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := opensearch.NewFromConfig(cfg)

	resp, err := client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("list domain names: %w", err)
	}

	var names []string
	for _, d := range resp.DomainNames {
		names = append(names, aws.ToString(d.DomainName))
	}

	return audit.ProcessAllMulti(
		ctx,
		names,
		"Auditing OpenSearch security",
		func(ctx context.Context, name string) []audit.Finding {
			desc, err := client.DescribeDomain(
				ctx,
				&opensearch.DescribeDomainInput{DomainName: &name},
			)
			if err != nil {
				return []audit.Finding{
					audit.ErrorFinding("opensearch", name, "describe_domain", err),
				}
			}

			domain := desc.DomainStatus
			encryptAtRest := domain.EncryptionAtRestOptions != nil &&
				aws.ToBool(domain.EncryptionAtRestOptions.Enabled)
			nodeToNode := domain.NodeToNodeEncryptionOptions != nil &&
				aws.ToBool(domain.NodeToNodeEncryptionOptions.Enabled)
			fineGrained := domain.AdvancedSecurityOptions != nil &&
				aws.ToBool(domain.AdvancedSecurityOptions.Enabled)
			vpcEnabled := domain.VPCOptions != nil && aws.ToString(domain.VPCOptions.VPCId) != ""
			publicAccess := !vpcEnabled

			var results []audit.Finding
			if publicAccess {
				risk := "HIGH"
				if !fineGrained {
					risk = "CRITICAL"
				}
				d := "domain is publicly accessible (not in VPC)"
				results = append(
					results,
					audit.Finding{
						Service:    "opensearch",
						ResourceID: name,
						Check:      "public_access",
						Status:     statusFromRisk(risk),
						Detail:     d,
						RiskLevel:  risk,
						Remediation: remediation.Recommend(
							"security",
							"opensearch",
							"public_access",
							name,
							d,
						),
					},
				)
			}

			if !encryptAtRest {
				d := "encryption at rest disabled"
				results = append(
					results,
					audit.Finding{
						Service:    "opensearch",
						ResourceID: name,
						Check:      "no_encryption",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "MEDIUM",
						Remediation: remediation.Recommend(
							"security",
							"opensearch",
							"no_encryption",
							name,
							d,
						),
					},
				)
			}
			if !nodeToNode {
				d := "node-to-node encryption disabled"
				results = append(
					results,
					audit.Finding{
						Service:    "opensearch",
						ResourceID: name,
						Check:      "no_node_to_node",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "MEDIUM",
						Remediation: remediation.Recommend(
							"security",
							"opensearch",
							"no_node_to_node",
							name,
							d,
						),
					},
				)
			}
			if !fineGrained {
				d := "fine-grained access control not enabled"
				results = append(
					results,
					audit.Finding{
						Service:    "opensearch",
						ResourceID: name,
						Check:      "no_fine_grained_access",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "LOW",
						Remediation: remediation.Recommend(
							"security",
							"opensearch",
							"no_fine_grained_access",
							name,
							d,
						),
					},
				)
			}
			if len(results) == 0 {
				results = append(
					results,
					audit.Finding{
						Service:    "opensearch",
						ResourceID: name,
						Check:      "opensearch_posture",
						Status:     "PASS",
						Detail:     "vpc=true, encrypt_at_rest=true, node_to_node=true, fine_grained_access=true",
						RiskLevel:  "MINIMAL",
					},
				)
			}
			return results
		},
	), nil
}
