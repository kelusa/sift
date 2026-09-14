package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
)

func init() {
	audit.RegisterAWS(Module, "dms", AuditDMS)
}

func AuditDMS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := databasemigrationservice.NewFromConfig(cfg)

	var instances []dmstypes.ReplicationInstance
	input := &databasemigrationservice.DescribeReplicationInstancesInput{}
	for {
		resp, err := client.DescribeReplicationInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe replication instances: %w", err)
		}
		instances = append(instances, resp.ReplicationInstances...)
		if resp.Marker == nil {
			break
		}
		input.Marker = resp.Marker
	}

	return audit.ProcessAllMulti(
		ctx,
		instances,
		"Auditing DMS security",
		func(_ context.Context, inst dmstypes.ReplicationInstance) []audit.Finding {
			id := aws.ToString(inst.ReplicationInstanceIdentifier)
			publiclyAccessible := aws.ToBool(&inst.PubliclyAccessible)
			encrypted := inst.KmsKeyId != nil && *inst.KmsKeyId != ""

			var results []audit.Finding

			if publiclyAccessible {
				risk := "HIGH"
				if !encrypted {
					risk = "CRITICAL"
				}
				detail := fmt.Sprintf("publicly_accessible=true, encrypted=%t", encrypted)
				results = append(results, audit.Finding{
					Service:    "dms",
					ResourceID: id,
					Check:      "public_access",
					Status:     statusFromRisk(risk),
					Detail:     detail,
					RiskLevel:  risk,
					Remediation: remediation.Recommend(
						"security",
						"dms",
						"public_access",
						id,
						detail,
					),
				})
			}

			if !encrypted {
				detail := "storage encryption disabled"
				results = append(results, audit.Finding{
					Service:    "dms",
					ResourceID: id,
					Check:      "no_encryption",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "HIGH",
					Remediation: remediation.Recommend(
						"security",
						"dms",
						"no_encryption",
						id,
						detail,
					),
				})
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "dms",
					ResourceID: id,
					Check:      "dms_posture",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"publicly_accessible=%t, encrypted=%t",
						publiclyAccessible,
						encrypted,
					),
					RiskLevel: "MINIMAL",
				})
			}

			return results
		},
	), nil
}
