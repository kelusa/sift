package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
)

func init() {
	audit.RegisterAWS(Module, "acm", AuditACM)
}

func AuditACM(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := acm.NewFromConfig(cfg)

	var certs []acmtypes.CertificateSummary
	input := &acm.ListCertificatesInput{}
	for {
		resp, err := client.ListCertificates(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list certificates: %w", err)
		}
		certs = append(certs, resp.CertificateSummaryList...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	return audit.ProcessAllMulti(ctx, certs, "Auditing ACM certificates",
		func(ctx context.Context, cert acmtypes.CertificateSummary) []audit.Finding {
			arn := aws.ToString(cert.CertificateArn)
			domain := aws.ToString(cert.DomainName)

			desc, err := client.DescribeCertificate(
				ctx,
				&acm.DescribeCertificateInput{CertificateArn: &arn},
			)
			if err != nil {
				return []audit.Finding{audit.ErrorFinding("acm", domain, "describe_cert", err)}
			}
			detail := desc.Certificate

			var results []audit.Finding

			if detail.NotAfter != nil {
				daysLeft := int(time.Until(*detail.NotAfter).Hours() / 24)
				if daysLeft < 0 {
					d := fmt.Sprintf("certificate expired %d days ago", -daysLeft)
					results = append(results, audit.Finding{
						Service:     "acm",
						ResourceID:  domain,
						Check:       "expired",
						Status:      "FAIL",
						Detail:      d,
						RiskLevel:   "CRITICAL",
						Remediation: remediation.Recommend("security", "acm", "expired", domain, d),
					})
				} else if daysLeft <= 30 {
					d := fmt.Sprintf("certificate expires in %d days", daysLeft)
					results = append(results, audit.Finding{
						Service:     "acm",
						ResourceID:  domain,
						Check:       "expiring_soon",
						Status:      "FAIL",
						Detail:      d,
						RiskLevel:   "HIGH",
						Remediation: remediation.Recommend("security", "acm", "expiring_soon", domain, d),
					})
				}
			}

			if detail.Type == acmtypes.CertificateTypeAmazonIssued &&
				detail.RenewalEligibility == acmtypes.RenewalEligibilityIneligible {
				d := "certificate not eligible for auto-renewal"
				results = append(results, audit.Finding{
					Service:    "acm",
					ResourceID: domain,
					Check:      "no_auto_renewal",
					Status:     "FAIL",
					Detail:     d,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"security",
						"acm",
						"no_auto_renewal",
						domain,
						d,
					),
				})
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "acm",
					ResourceID: domain,
					Check:      "acm_posture",
					Status:     "PASS",
					Detail:     "certificate valid, auto-renewal eligible",
					RiskLevel:  "MINIMAL",
				})
			}

			return results
		},
	), nil
}
