package security

import (
	"context"
	"fmt"
	"strings"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func init() {
	audit.RegisterAWS(Module, "docdb", AuditDocDB)
}

func AuditDocDB(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := rds.NewFromConfig(cfg)

	var clusters []rdstypes.DBCluster
	input := &rds.DescribeDBClustersInput{}
	for {
		resp, err := client.DescribeDBClusters(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe db clusters: %w", err)
		}
		for _, c := range resp.DBClusters {
			if strings.HasPrefix(aws.ToString(c.Engine), "docdb") {
				clusters = append(clusters, c)
			}
		}
		if resp.Marker == nil {
			break
		}
		input.Marker = resp.Marker
	}

	return audit.ProcessAll(ctx, clusters, "Auditing DocDB security",
		func(ctx context.Context, c rdstypes.DBCluster) audit.Finding {
			id := aws.ToString(c.DBClusterIdentifier)
			encrypted := aws.ToBool(c.StorageEncrypted)
			public := false
			for _, m := range c.DBClusterMembers {
				if m.DBInstanceIdentifier != nil {
					inst, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
						DBInstanceIdentifier: m.DBInstanceIdentifier,
					})
					if err == nil && len(inst.DBInstances) > 0 {
						if aws.ToBool(inst.DBInstances[0].PubliclyAccessible) {
							public = true
						}
					}
				}
			}

			risk := "MINIMAL"
			status := "PASS"
			var issues []string

			if public && !encrypted {
				risk = "CRITICAL"
				status = "FAIL"
				issues = append(issues, "public", "unencrypted")
			} else if public {
				risk = "HIGH"
				status = "FAIL"
				issues = append(issues, "public")
			} else if !encrypted {
				risk = "HIGH"
				status = "FAIL"
				issues = append(issues, "unencrypted")
			}

			deletionProtection := aws.ToBool(c.DeletionProtection)
			if !deletionProtection && risk == "MINIMAL" {
				risk = "LOW"
				status = "WARN"
				issues = append(issues, "no_deletion_protection")
			}

			detail := fmt.Sprintf(
				"cluster=%s encrypted=%t public=%t deletion_protection=%t",
				id,
				encrypted,
				public,
				deletionProtection,
			)
			check := "docdb_posture"
			if status != "PASS" {
				check = issues[0]
			}

			f := audit.Finding{
				Service:    "docdb",
				ResourceID: id,
				Check:      check,
				Status:     status,
				Detail:     detail,
				RiskLevel:  risk,
			}
			if status != "PASS" {
				f.Remediation = remediation.Recommend("security", "docdb", check, id, detail)
			}
			return f
		},
	), nil
}
