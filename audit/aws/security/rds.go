package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func init() {
	awsreg.Register(Module, "rds", AuditRDS)
}

func AuditRDS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := rds.NewFromConfig(cfg)

	var instances []rdstypes.DBInstance
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe db instances: %w", err)
		}
		instances = append(instances, page.DBInstances...)
	}

	return audit.ProcessAllMulti(
		ctx,
		instances,
		"Auditing RDS instances",
		func(_ context.Context, db rdstypes.DBInstance) []audit.Finding {
			id := aws.ToString(db.DBInstanceIdentifier)
			engine := aws.ToString(db.Engine)
			public := aws.ToBool(db.PubliclyAccessible)
			encrypted := aws.ToBool(db.StorageEncrypted)
			backup := aws.ToInt32(db.BackupRetentionPeriod)
			delProtect := aws.ToBool(db.DeletionProtection)

			tags := make(map[string]string, len(db.TagList))
			for _, t := range db.TagList {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}

			var results []audit.Finding

			if public {
				risk := "HIGH"
				if !encrypted {
					risk = "CRITICAL"
				}
				detail := fmt.Sprintf("engine=%s, publicly_accessible=true", engine)
				results = append(results, audit.Finding{
					Service:    "rds",
					ResourceID: id,
					Tags:       tags,
					Check:      "public_access",
					Status:     statusFromRisk(risk),
					Detail:     detail,
					RiskLevel:  risk,
					Remediation: remediation.Recommend(
						"security",
						"rds",
						"public_access",
						id,
						detail,
					),
				})
			}

			if !encrypted {
				detail := fmt.Sprintf("engine=%s, storage encryption disabled", engine)
				results = append(results, audit.Finding{
					Service:    "rds",
					ResourceID: id,
					Tags:       tags,
					Check:      "no_encryption",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "HIGH",
					Remediation: remediation.Recommend(
						"security",
						"rds",
						"no_encryption",
						id,
						detail,
					),
				})
			}

			if backup < 7 {
				detail := fmt.Sprintf("engine=%s, backup_retention=%d days", engine, backup)
				results = append(results, audit.Finding{
					Service:    "rds",
					ResourceID: id,
					Tags:       tags,
					Check:      "weak_backup",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"security",
						"rds",
						"weak_backup",
						id,
						detail,
					),
				})
			}

			if !delProtect {
				detail := fmt.Sprintf("engine=%s, deletion protection disabled", engine)
				results = append(results, audit.Finding{
					Service:    "rds",
					ResourceID: id,
					Tags:       tags,
					Check:      "no_delete_protection",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"security",
						"rds",
						"no_delete_protection",
						id,
						detail,
					),
				})
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "rds",
					ResourceID: id,
					Tags:       tags,
					Check:      "rds_posture",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"engine=%s, encrypted, backup=%dd, delete_protection=true",
						engine,
						backup,
					),
					RiskLevel: "MINIMAL",
				})
			}

			return results
		},
	), nil
}

func rdsRisk(
	public, encrypted bool,
	backup int32,
	delProtect, multiAZ, autoUpgrade bool,
	minBackupDays int,
) string {
	switch {
	case public && !encrypted:
		return "CRITICAL"
	case public:
		return "HIGH"
	case !encrypted:
		return "HIGH"
	case backup < int32(minBackupDays) || !delProtect:
		return "MEDIUM"
	case !multiAZ || !autoUpgrade:
		return "LOW"
	default:
		return "MINIMAL"
	}
}
