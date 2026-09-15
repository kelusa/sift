package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/aws/pricing"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func init() {
	audit.RegisterAWS(Module, "ebs", AuditEBSCost)
}

type ebsVolume struct {
	id         string
	size       int32
	volumeType string
	status     string
	tags       map[string]string
}

type ebsSnapshot struct {
	id        string
	size      int32
	startTime *time.Time
	tags      map[string]string
}

func ec2TagsToMap(tags []ec2types.Tag) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return m
}

func parseEBSVolume(vol ec2types.Volume) ebsVolume {
	return ebsVolume{
		id:         aws.ToString(vol.VolumeId),
		size:       aws.ToInt32(vol.Size),
		volumeType: string(vol.VolumeType),
		status:     string(vol.State),
		tags:       ec2TagsToMap(vol.Tags),
	}
}

func parseEBSSnapshot(snap ec2types.Snapshot) ebsSnapshot {
	return ebsSnapshot{
		id:        aws.ToString(snap.SnapshotId),
		size:      aws.ToInt32(snap.VolumeSize),
		startTime: snap.StartTime,
		tags:      ec2TagsToMap(snap.Tags),
	}
}

func AuditEBSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := ec2.NewFromConfig(cfg)
	var findings []audit.Finding

	spinner := progress.NewSpinner(ctx, "Auditing EBS cost")

	// All volumes
	volPaginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for volPaginator.HasMorePages() {
		page, err := volPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe volumes: %w", err)
		}
		for _, vol := range page.Volumes {
			v := parseEBSVolume(vol)
			var volFindings []audit.Finding

			if v.status == "available" {
				volFindings = append(volFindings, audit.Finding{
					Service:              "ebs",
					ResourceID:           v.id,
					Tags:                 v.tags,
					Check:                "unattached_volume",
					Status:               "WARN",
					Detail:               fmt.Sprintf("size=%dGB, type=%s", v.size, v.volumeType),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: pricing.EBSMonthly(v.volumeType, v.size),
					Remediation: remediation.Recommend(
						"cost",
						"ebs",
						"unattached_volume",
						v.id,
						"volume status=available",
					),
				})
			}

			if v.volumeType == "gp2" {
				volFindings = append(volFindings, audit.Finding{
					Service:    "ebs",
					ResourceID: v.id,
					Tags:       v.tags,
					Check:      "gp2_volume",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"size=%dGB, GP3 is ~20%% cheaper with better baseline IOPS",
						v.size,
					),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: pricing.EBSMonthly(v.volumeType, v.size),
					Remediation: remediation.Recommend(
						"cost",
						"ebs",
						"gp2_volume",
						v.id,
						"gp2 volume type",
					),
				})
			}

			if len(volFindings) > 0 {
				findings = append(findings, volFindings...)
			} else {
				findings = append(findings, audit.Finding{
					Service:              "ebs",
					ResourceID:           v.id,
					Tags:                 v.tags,
					Check:                "ebs_cost",
					Status:               "PASS",
					Detail:               fmt.Sprintf("size=%dGB, type=%s, attached", v.size, v.volumeType),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: pricing.EBSMonthly(v.volumeType, v.size),
					Remediation:          nil,
				})
			}
		}
	}

	// Snapshots
	t := audit.GetThresholds(ctx)
	cutoff := time.Now().AddDate(0, 0, -t.GetInt("ebs", "snapshot_age_days", 90))
	snapPaginator := ec2.NewDescribeSnapshotsPaginator(client, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})
	for snapPaginator.HasMorePages() {
		page, err := snapPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe snapshots: %w", err)
		}
		for _, snap := range page.Snapshots {
			s := parseEBSSnapshot(snap)
			if s.startTime != nil && s.startTime.Before(cutoff) {
				findings = append(findings, audit.Finding{
					Service:    "ebs_snapshot",
					ResourceID: s.id,
					Tags:       s.tags,
					Check:      "old_snapshot",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"age=%dd, size=%dGB",
						int(time.Since(*s.startTime).Hours()/24),
						s.size,
					),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: pricing.SnapshotMonthly(s.size),
					Remediation: remediation.Recommend(
						"cost",
						"ebs_snapshot",
						"old_snapshot",
						s.id,
						fmt.Sprintf(
							"snapshot age %d days",
							int(time.Since(*s.startTime).Hours()/24),
						),
					),
				})
			} else {
				findings = append(findings, audit.Finding{
					Service:              "ebs_snapshot",
					ResourceID:           s.id,
					Tags:                 s.tags,
					Check:                "old_snapshot",
					Status:               "PASS",
					Detail:               fmt.Sprintf("size=%dGB, within retention period", s.size),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: pricing.SnapshotMonthly(s.size),
					Remediation:          nil,
				})
			}
		}
	}

	spinner.Finish()
	return findings, nil
}
