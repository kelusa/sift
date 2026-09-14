package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
	dstypes "github.com/aws/aws-sdk-go-v2/service/directoryservice/types"
)

func init() {
	audit.RegisterAWS(Module, "directory", AuditDirectory)
}

func AuditDirectory(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := directoryservice.NewFromConfig(cfg)

	var directories []dstypes.DirectoryDescription
	input := &directoryservice.DescribeDirectoriesInput{}
	for {
		resp, err := client.DescribeDirectories(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe directories: %w", err)
		}
		directories = append(directories, resp.DirectoryDescriptions...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	return audit.ProcessAll(ctx, directories, "Auditing Directory Service security",
		func(ctx context.Context, d dstypes.DirectoryDescription) audit.Finding {
			id := aws.ToString(d.DirectoryId)
			name := aws.ToString(d.Name)

			// Check LDAPS status
			ldapsResp, _ := client.DescribeLDAPSSettings(
				ctx,
				&directoryservice.DescribeLDAPSSettingsInput{
					DirectoryId: d.DirectoryId,
				},
			)
			ldapsEnabled := false
			if ldapsResp != nil {
				for _, s := range ldapsResp.LDAPSSettingsInfo {
					if s.LDAPSStatus == dstypes.LDAPSStatusEnabled {
						ldapsEnabled = true
					}
				}
			}

			//Check VPC settings
			hasVPC := d.VpcSettings != nil || d.ConnectSettings != nil

			risk := "MINIMAL"
			status := "PASS"
			check := "directory_posture"
			var issues []string

			if !ldapsEnabled && !hasVPC {
				risk = "HIGH"
				status = "FAIL"
				check = "no_ldaps"
				issues = append(issues, "no_ldaps", "no_vpc")
			} else if !ldapsEnabled {
				risk = "MEDIUM"
				status = "FAIL"
				check = "no_ldaps"
				issues = append(issues, "no_ldaps")
			} else if !hasVPC {
				risk = "MEDIUM"
				status = "FAIL"
				check = "no_vpc"
				issues = append(issues, "no_vpc")
			}

			detail := fmt.Sprintf(
				"directory=%s type=%s ldaps=%t vpc=%t",
				name,
				d.Type,
				ldapsEnabled,
				hasVPC,
			)

			f := audit.Finding{
				Service:    "directory",
				ResourceID: id,
				Check:      check,
				Status:     status,
				Detail:     detail,
				RiskLevel:  risk,
			}
			if status != "PASS" {
				f.Remediation = remediation.Recommend("security", "directory", check, id, detail)
			}
			return f
		},
	), nil
}
