package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
)

func init() {
	audit.RegisterAWS(Module, "backup", AuditBackupCost)
}

func AuditBackupCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := backup.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	retentionDays := t.GetInt("backup", "retention_days", 90)
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	// Collect all vaults first
	var vaults []backuptypes.BackupVaultListMember
	vaultInput := &backup.ListBackupVaultsInput{}
	for {
		vaultResp, err := client.ListBackupVaults(ctx, vaultInput)
		if err != nil {
			return nil, fmt.Errorf("list backup vaults: %w", err)
		}
		vaults = append(vaults, vaultResp.BackupVaultList...)
		if vaultResp.NextToken == nil {
			break
		}
		vaultInput.NextToken = vaultResp.NextToken
	}

	costPerGB := t.GetFloat("backup", "storage_per_gb", 0.05)

	return audit.ProcessAll(
		ctx,
		vaults,
		"Auditing Backup cost",
		func(ctx context.Context, v backuptypes.BackupVaultListMember) audit.Finding {
			vaultName := aws.ToString(v.BackupVaultName)

			// Get tags
			var tags map[string]string
			if v.BackupVaultArn != nil {
				tagResp, tagErr := client.ListTags(
					ctx,
					&backup.ListTagsInput{ResourceArn: v.BackupVaultArn},
				)
				if tagErr == nil {
					tags = tagResp.Tags
				}
			}

			rpInput := &backup.ListRecoveryPointsByBackupVaultInput{BackupVaultName: &vaultName}
			var oldCount, totalCount int
			var oldBytes int64
			for {
				rpResp, err := client.ListRecoveryPointsByBackupVault(ctx, rpInput)
				if err != nil {
					break
				}
				for _, rp := range rpResp.RecoveryPoints {
					totalCount++
					if rp.CreationDate != nil && rp.CreationDate.Before(cutoff) {
						oldCount++
						if rp.BackupSizeInBytes != nil {
							oldBytes += *rp.BackupSizeInBytes
						}
					}
				}
				if rpResp.NextToken == nil {
					break
				}
				rpInput.NextToken = rpResp.NextToken
			}
			oldGB := float64(oldBytes) / (1024 * 1024 * 1024)
			if oldCount > 0 {
				detail := fmt.Sprintf(
					"total=%d, older_than_%dd=%d, old_size=%.1fGB",
					totalCount,
					retentionDays,
					oldCount,
					oldGB,
				)
				return audit.Finding{
					Service:              "backup",
					ResourceID:           vaultName,
					Tags:                 tags,
					Check:                "old_recovery_points",
					Status:               "WARN",
					Detail:               detail,
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: oldGB * costPerGB,
					Remediation: remediation.Recommend(
						"cost",
						"backup",
						"old_recovery_points",
						vaultName,
						fmt.Sprintf("old_recovery_points=%d, size=%.1fGB", oldCount, oldGB),
					),
				}
			}
			return audit.Finding{
				Service:    "backup",
				ResourceID: vaultName,
				Tags:       tags,
				Check:      "old_recovery_points",
				Status:     "PASS",
				Detail: fmt.Sprintf(
					"total=%d, all within %d day retention",
					totalCount,
					retentionDays,
				),
				RiskLevel: "MINIMAL",
			}
		},
	), nil
}
