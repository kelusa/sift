package security

import (
	"context"
	"fmt"
	"strings"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

func init() {
	awsreg.Register(Module, "eks", AuditEKS)
}

func AuditEKS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := eks.NewFromConfig(cfg)

	var allClusters []string
	input := &eks.ListClustersInput{}
	for {
		resp, err := client.ListClusters(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list clusters: %w", err)
		}
		allClusters = append(allClusters, resp.Clusters...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	return audit.ProcessAllMulti(
		ctx,
		allClusters,
		"Auditing EKS clusters",
		func(ctx context.Context, name string) []audit.Finding {
			desc, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
			if err != nil {
				return []audit.Finding{audit.ErrorFinding("eks", name, "describe_cluster", err)}
			}

			cluster := desc.Cluster
			tags := cluster.Tags

			publicEP := false
			privateEP := false
			if cluster.ResourcesVpcConfig != nil {
				publicEP = cluster.ResourcesVpcConfig.EndpointPublicAccess
				privateEP = cluster.ResourcesVpcConfig.EndpointPrivateAccess
			}

			secretsEnc := false
			for _, enc := range cluster.EncryptionConfig {
				for _, res := range enc.Resources {
					if res == "secrets" {
						secretsEnc = true
					}
				}
			}

			var disabledLogs []string
			if cluster.Logging != nil {
				for _, ls := range cluster.Logging.ClusterLogging {
					if !aws.ToBool(ls.Enabled) {
						for _, lt := range ls.Types {
							disabledLogs = append(disabledLogs, string(lt))
						}
					}
				}
			}

			var results []audit.Finding

			if publicEP {
				risk := "MEDIUM"
				if !privateEP && !secretsEnc {
					risk = "CRITICAL"
				} else if !privateEP {
					risk = "HIGH"
				}
				detail := fmt.Sprintf("public_endpoint=true, private_endpoint=%t", privateEP)
				results = append(results, audit.Finding{
					Service:    "eks",
					ResourceID: name,
					Tags:       tags,
					Check:      "public_endpoint",
					Status:     statusFromRisk(risk),
					Detail:     detail,
					RiskLevel:  risk,
					Remediation: remediation.Recommend(
						"security",
						"eks",
						"public_endpoint",
						name,
						detail,
					),
				})
			}

			if !secretsEnc {
				detail := "Kubernetes secrets not encrypted at rest"
				results = append(results, audit.Finding{
					Service:    "eks",
					ResourceID: name,
					Tags:       tags,
					Check:      "no_secrets_encryption",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"security",
						"eks",
						"no_secrets_encryption",
						name,
						detail,
					),
				})
			}

			if len(disabledLogs) > 0 {
				detail := fmt.Sprintf("disabled_log_types=%s", strings.Join(disabledLogs, ","))
				results = append(results, audit.Finding{
					Service:    "eks",
					ResourceID: name,
					Tags:       tags,
					Check:      "logging_disabled",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"security",
						"eks",
						"logging_disabled",
						name,
						detail,
					),
				})
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "eks",
					ResourceID: name,
					Tags:       tags,
					Check:      "eks_posture",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"version=%s, private_only=true, secrets_encrypted=true, all_logging_enabled=true",
						aws.ToString(cluster.Version),
					),
					RiskLevel: "MINIMAL",
				})
			}
			return results
		},
	), nil
}

func eksRisk(publicEP, privateEP, secretsEnc, hasDisabledLogs bool) string {
	switch {
	case publicEP && !privateEP && !secretsEnc:
		return "CRITICAL"
	case publicEP && !privateEP:
		return "HIGH"
	case publicEP:
		return "MEDIUM"
	case !secretsEnc || hasDisabledLogs:
		return "LOW"
	default:
		return "MINIMAL"
	}
}
