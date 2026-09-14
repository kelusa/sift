package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

func init() {
	audit.RegisterAWS(Module, "redshift", AuditRedshift)
}

func AuditRedshift(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := redshift.NewFromConfig(cfg)

	var findings []audit.Finding
	paginator := redshift.NewDescribeClustersPaginator(client, &redshift.DescribeClustersInput{})

	bar := progress.NewSpinner(ctx, "Auditing Redshift security")
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			bar.Finish()
			return nil, fmt.Errorf("describe clusters: %w", err)
		}
		for _, c := range page.Clusters {
			id := aws.ToString(c.ClusterIdentifier)
			pub := aws.ToBool(c.PubliclyAccessible)
			enc := aws.ToBool(c.Encrypted)
			tags := make(map[string]string, len(c.Tags))
			for _, t := range c.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			loggingResp, _ := client.DescribeLoggingStatus(
				ctx,
				&redshift.DescribeLoggingStatusInput{ClusterIdentifier: c.ClusterIdentifier},
			)
			logging := loggingResp != nil && aws.ToBool(loggingResp.LoggingEnabled)

			var results []audit.Finding
			if pub {
				risk := "HIGH"
				if !enc {
					risk = "CRITICAL"
				}
				d := fmt.Sprintf("publicly_accessible=true, encrypted=%t", enc)
				results = append(
					results,
					audit.Finding{
						Service:    "redshift",
						ResourceID: id,
						Tags:       tags,
						Check:      "public_access",
						Status:     statusFromRisk(risk),
						Detail:     d,
						RiskLevel:  risk,
						Remediation: remediation.Recommend(
							"security",
							"redshift",
							"public_access",
							id,
							d,
						),
					},
				)
			}
			if !enc {
				d := "cluster encryption disabled"
				results = append(
					results,
					audit.Finding{
						Service:    "redshift",
						ResourceID: id,
						Tags:       tags,
						Check:      "no_encryption",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "HIGH",
						Remediation: remediation.Recommend(
							"security",
							"redshift",
							"no_encryption",
							id,
							d,
						),
					},
				)
			}
			if !logging {
				d := "audit logging disabled"
				results = append(
					results,
					audit.Finding{
						Service:    "redshift",
						ResourceID: id,
						Tags:       tags,
						Check:      "no_logging",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "MEDIUM",
						Remediation: remediation.Recommend(
							"security",
							"redshift",
							"no_logging",
							id,
							d,
						),
					},
				)
			}
			if len(results) == 0 {
				results = append(
					results,
					audit.Finding{
						Service:    "redshift",
						ResourceID: id,
						Tags:       tags,
						Check:      "redshift_posture",
						Status:     "PASS",
						Detail:     "private=true, encrypted=true, logging=true",
						RiskLevel:  "MINIMAL",
					},
				)
			}
			findings = append(findings, results...)
		}
		bar.Add(len(page.Clusters))
	}
	bar.Finish()

	return findings, nil
}
