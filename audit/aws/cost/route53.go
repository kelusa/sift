package cost

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

func init() {
	awsreg.Register(Module, "route53", AuditRoute53Cost)
}

func AuditRoute53Cost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := route53.NewFromConfig(cfg)

	var zones []r53types.HostedZone
	input := &route53.ListHostedZonesInput{}
	for {
		resp, err := client.ListHostedZones(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list hosted zones: %w", err)
		}
		zones = append(zones, resp.HostedZones...)
		if !resp.IsTruncated {
			break
		}
		input.Marker = resp.NextMarker
	}

	var findings []audit.Finding

	for _, z := range zones {
		id := aws.ToString(z.Id)
		name := aws.ToString(z.Name)
		count := aws.ToInt64(z.ResourceRecordSetCount)

		// A zone with only SOA + NS (count <= 2) is effectively empty
		if count <= 2 {
			detail := fmt.Sprintf("zone=%s records=%d (empty)", name, count)
			findings = append(findings, audit.Finding{
				Service:              "route53",
				ResourceID:           id,
				Check:                "empty_hosted_zone",
				Status:               "WARN",
				Detail:               detail,
				RiskLevel:            "LOW",
				EstimatedMonthlyCost: 0.50,
				Remediation: remediation.Recommend(
					"cost",
					"route53",
					"empty_hosted_zone",
					id,
					detail,
				),
			})
		}
	}

	// Check unused health checks
	hcInput := &route53.ListHealthChecksInput{}
	for {
		resp, err := client.ListHealthChecks(ctx, hcInput)
		if err != nil {
			break
		}
		for _, hc := range resp.HealthChecks {
			hcID := aws.ToString(hc.Id)
			// Check if health check is referenced by any record
			// A health check costs $0.50 - $1/mo; flag all for awareness
			detail := fmt.Sprintf("health_check=%s type=%s", hcID, hc.HealthCheckConfig.Type)
			findings = append(findings, audit.Finding{
				Service:              "route53",
				ResourceID:           hcID,
				Check:                "health_check_cost",
				Status:               "PASS",
				Detail:               detail,
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: 0.75,
			})
		}
		if !resp.IsTruncated {
			break
		}
		hcInput.Marker = resp.NextMarker
	}

	return findings, nil
}
