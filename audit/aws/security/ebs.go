package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func init() {
	audit.RegisterAWS(Module, "ebs", AuditEBS)
}

func AuditEBS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := ec2.NewFromConfig(cfg)

	var volumes []ec2types.Volume
	paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe volumes: %w", err)
		}
		volumes = append(volumes, page.Volumes...)
	}

	results := audit.ProcessAll(ctx, volumes, "Auditing EBS security",
		func(_ context.Context, vol ec2types.Volume) audit.Finding {
			volID := aws.ToString(vol.VolumeId)
			if !aws.ToBool(vol.Encrypted) {
				d := "volume encryption disabled"
				return audit.Finding{
					Service:    "ebs",
					ResourceID: volID,
					Check:      "no_encryption",
					Status:     "FAIL",
					Detail:     d,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"security",
						"ebs",
						"no_encryption",
						volID,
						d,
					),
				}
			}
			return audit.Finding{
				Service:    "ebs",
				ResourceID: volID,
				Check:      "ebs_posture",
				Status:     "PASS",
				Detail:     "encrypted=true",
				RiskLevel:  "MINIMAL",
			}
		},
	)

	snapResp, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
		Filters:  []ec2types.Filter{{Name: aws.String("status"), Values: []string{"completed"}}},
	})
	if err == nil && len(snapResp.Snapshots) > 0 {
		snapFindings := audit.ProcessAll(ctx, snapResp.Snapshots, "Auditing EBS snapshot sharing",
			func(ctx context.Context, snap ec2types.Snapshot) audit.Finding {
				snapID := aws.ToString(snap.SnapshotId)
				encrypted := aws.ToBool(snap.Encrypted)
				attrResp, err := client.DescribeSnapshotAttribute(
					ctx,
					&ec2.DescribeSnapshotAttributeInput{
						SnapshotId: &snapID, Attribute: ec2types.SnapshotAttributeNameCreateVolumePermission,
					},
				)
				public := false
				if err == nil {
					for _, perm := range attrResp.CreateVolumePermissions {
						if perm.Group == ec2types.PermissionGroupAll {
							public = true
							break
						}
					}
				}
				if public {
					risk := "HIGH"
					if !encrypted {
						risk = "CRITICAL"
					}
					d := fmt.Sprintf("snapshot is public, encrypted=%t", encrypted)
					return audit.Finding{
						Service:    "ebs",
						ResourceID: snapID,
						Check:      "public_snapshot",
						Status:     statusFromRisk(risk),
						Detail:     d,
						RiskLevel:  risk,
						Remediation: remediation.Recommend(
							"security",
							"ebs",
							"public_snapshot",
							snapID,
							d,
						),
					}
				}
				return audit.Finding{
					Service:    "ebs",
					ResourceID: snapID,
					Check:      "snapshot_posture",
					Status:     "PASS",
					Detail:     fmt.Sprintf("public=false, encrypted=%t", encrypted),
					RiskLevel:  "MINIMAL",
				}
			},
		)
		results = append(results, snapFindings...)
	}
	return results, nil
}
