package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
)

func init() {
	audit.RegisterAWS(Module, "efs", AuditEFS)
}

func AuditEFS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := efs.NewFromConfig(cfg)

	resp, err := client.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe file systems: %w", err)
	}

	return audit.ProcessAll(ctx, resp.FileSystems, "Auditing EFS security",
		func(ctx context.Context, fs efstypes.FileSystemDescription) audit.Finding {
			id := aws.ToString(fs.FileSystemId)
			name := aws.ToString(fs.Name)
			label := id
			if name != "" {
				label = name
			}

			encrypted := aws.ToBool(fs.Encrypted)
			if !encrypted {
				d := fmt.Sprintf("fs=%s encrypted=false", label)
				return audit.Finding{
					Service:     "efs",
					ResourceID:  id,
					Check:       "no_encryption",
					Status:      "FAIL",
					Detail:      d,
					RiskLevel:   "HIGH",
					Remediation: remediation.Recommend("security", "efs", "no_encryption", id, d),
				}
			}

			return audit.Finding{
				Service:    "efs",
				ResourceID: id,
				Check:      "efs_posture",
				Status:     "PASS",
				Detail:     fmt.Sprintf("fs=%s encrypted=true", label),
				RiskLevel:  "MINIMAL",
			}
		},
	), nil
}
