package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
)

func init() {
	awsreg.Register(Module, "backup", AuditBackup)
}

type backupVaultEntry struct {
	name           string
	encrypted      bool
	recoveryPoints int64
}

func parseBackupVaultEntry(v backuptypes.BackupVaultListMember) backupVaultEntry {
	return backupVaultEntry{
		name:           aws.ToString(v.BackupVaultName),
		encrypted:      v.EncryptionKeyArn != nil && *v.EncryptionKeyArn != "",
		recoveryPoints: v.NumberOfRecoveryPoints,
	}
}

func backupRisk(encrypted bool) string {
	if !encrypted {
		return "HIGH"
	}
	return "MINIMAL"
}

func AuditBackup(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := backup.NewFromConfig(cfg)

	var vaults []backuptypes.BackupVaultListMember
	input := &backup.ListBackupVaultsInput{}
	for {
		resp, err := client.ListBackupVaults(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list backup vaults: %w", err)
		}
		vaults = append(vaults, resp.BackupVaultList...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	// Check vaults
	return audit.ProcessAll(
		ctx,
		vaults,
		"Auditing Backup vaults",
		func(_ context.Context, v backuptypes.BackupVaultListMember) audit.Finding {
			entry := parseBackupVaultEntry(v)
			risk := backupRisk(entry.encrypted)
			detail := fmt.Sprintf(
				"encrypted=%t, recovery_points=%d",
				entry.encrypted,
				entry.recoveryPoints,
			)

			var rem *audit.Remediation
			if risk != "MINIMAL" {
				rem = remediation.Recommend(
					"security",
					"backup",
					"no_encryption",
					entry.name,
					detail,
				)
			}

			return audit.Finding{
				Service:     "backup",
				ResourceID:  entry.name,
				Check:       "no_encryption",
				Status:      statusFromRisk(risk),
				Detail:      detail,
				RiskLevel:   risk,
				Remediation: rem,
			}
		},
	), nil
}
