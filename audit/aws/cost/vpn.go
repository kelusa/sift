package cost

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func init() {
	awsreg.Register(Module, "vpn", AuditVPNCost)
}

func AuditVPNCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := ec2.NewFromConfig(cfg)

	resp, err := client.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe vpn connections: %w", err)
	}

	return audit.ProcessAll(
		ctx,
		resp.VpnConnections,
		"Auditing VPN cost",
		func(_ context.Context, vpn ec2types.VpnConnection) audit.Finding {
			id := aws.ToString(vpn.VpnConnectionId)
			tags := make(map[string]string, len(vpn.Tags))
			for _, t := range vpn.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}

			allDown := true
			for _, tun := range vpn.VgwTelemetry {
				if tun.Status == ec2types.TelemetryStatusUp {
					allDown = false
					break
				}
			}

			if allDown && string(vpn.State) == "available" {
				detail := "all tunnels down, $36/mo waste"
				return audit.Finding{
					Service:              "vpn",
					ResourceID:           id,
					Tags:                 tags,
					Check:                "idle_vpn",
					Status:               "WARN",
					Detail:               detail,
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: 36.0,
					Remediation: remediation.Recommend(
						"cost",
						"vpn",
						"idle_vpn",
						id,
						"all tunnels down",
					),
				}
			}
			return audit.Finding{
				Service:              "vpn",
				ResourceID:           id,
				Tags:                 tags,
				Check:                "idle_vpn",
				Status:               "PASS",
				Detail:               "at least one tunnel up",
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: 36.0,
			}
		},
	), nil
}
