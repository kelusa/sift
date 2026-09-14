package security

import (
	"context"
	"fmt"
	"net"
	"sift/audit"
	"sift/audit/remediation"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

func init() {
	audit.RegisterAWS(Module, "route53", AuditRoute53)
}

var danglingCNAMESuffixes = []string{
	".elb.amazonaws.com",
	".s3.amazonaws.com",
	".s3-website",
	".cloudfront.net",
	".elasticbeanstalk.com",
	".herokuapp.com",
	".azurewebsites.net",
}

func AuditRoute53(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := route53.NewFromConfig(cfg)

	zonesResp, err := client.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
	if err != nil {
		return nil, fmt.Errorf("list hosted zones: %w", err)
	}

	var findings []audit.Finding

	for _, zone := range zonesResp.HostedZones {
		zoneID := aws.ToString(zone.Id)
		zoneName := aws.ToString(zone.Name)

		// Check DNSSEC
		if !zone.Config.PrivateZone {
			dnssecResp, err := client.GetDNSSEC(ctx, &route53.GetDNSSECInput{HostedZoneId: &zoneID})
			if err == nil &&
				(dnssecResp.Status == nil || dnssecResp.Status.ServeSignature == nil || *dnssecResp.Status.ServeSignature != "SIGNING") {
				d := fmt.Sprintf("zone=%s, DNSSEC not enabled", zoneName)
				findings = append(findings, audit.Finding{
					Service:    "route53",
					ResourceID: zoneName,
					Check:      "no_dnssec",
					Status:     "FAIL",
					Detail:     d,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"security",
						"route53",
						"no_dnssec",
						zoneID,
						d,
					),
				})
			}
		}

		// Check for dangling CNAMEs
		recordInput := &route53.ListResourceRecordSetsInput{HostedZoneId: &zoneID}
		for {
			records, err := client.ListResourceRecordSets(ctx, recordInput)
			if err != nil {
				break
			}
			for _, rr := range records.ResourceRecordSets {
				if rr.Type != r53types.RRTypeCname {
					continue
				}
				for _, val := range rr.ResourceRecords {
					target := aws.ToString(val.Value)
					if isDanglingCandidate(target) && !resolvesSuccessfully(target) {
						name := aws.ToString(rr.Name)
						d := fmt.Sprintf(
							"CNAME %s -> %s (unresolvable, subdomain takeover risk)",
							name,
							target,
						)
						findings = append(findings, audit.Finding{
							Service:    "route53",
							ResourceID: name,
							Check:      "dangling_cname",
							Status:     "FAIL",
							Detail:     d,
							RiskLevel:  "CRITICAL",
							Remediation: remediation.Recommend(
								"security",
								"route53",
								"dangling_cname",
								zoneID+"/"+name,
								d,
							),
						})
					}
				}
			}
			if !records.IsTruncated {
				break
			}
			recordInput.StartRecordName = records.NextRecordName
			recordInput.StartRecordType = records.NextRecordType
		}
	}

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			Service:    "route53",
			ResourceID: "all_zones",
			Check:      "route53_posture",
			Status:     "PASS",
			Detail:     "no dangling records found",
			RiskLevel:  "MINIMAL",
		})
	}

	return findings, nil
}

func isDanglingCandidate(target string) bool {
	lower := strings.ToLower(target)
	for _, suffix := range danglingCNAMESuffixes {
		if strings.Contains(lower, suffix) {
			return true
		}
	}
	return false
}

func resolvesSuccessfully(target string) bool {
	target = strings.TrimSuffix(target, ".")
	_, err := net.LookupHost(target)
	return err == nil
}
