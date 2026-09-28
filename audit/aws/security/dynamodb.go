package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func init() {
	awsreg.Register(Module, "dynamodb", AuditDynamoDB)
}

func AuditDynamoDB(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := dynamodb.NewFromConfig(cfg)

	var tableNames []string
	paginator := dynamodb.NewListTablesPaginator(client, &dynamodb.ListTablesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list tables: %w", err)
		}
		tableNames = append(tableNames, page.TableNames...)
	}

	return audit.ProcessAllMulti(
		ctx,
		tableNames,
		"Auditing DynamoDB tables",
		func(ctx context.Context, name string) []audit.Finding {
			desc, err := client.DescribeTable(
				ctx,
				&dynamodb.DescribeTableInput{TableName: aws.String(name)},
			)
			if err != nil {
				return []audit.Finding{audit.ErrorFinding("dynamodb", name, "describe_table", err)}
			}
			table := desc.Table
			encrypted := true
			if table.SSEDescription != nil &&
				table.SSEDescription.Status == dbtypes.SSEStatusDisabled {
				encrypted = false
			}
			pitr := false
			cb, err := client.DescribeContinuousBackups(
				ctx,
				&dynamodb.DescribeContinuousBackupsInput{TableName: aws.String(name)},
			)
			if err == nil && cb.ContinuousBackupsDescription != nil &&
				cb.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
				pitr = cb.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dbtypes.PointInTimeRecoveryStatusEnabled
			}
			delProtect := aws.ToBool(table.DeletionProtectionEnabled)

			var tags map[string]string
			tagResp, err := client.ListTagsOfResource(
				ctx,
				&dynamodb.ListTagsOfResourceInput{ResourceArn: table.TableArn},
			)
			if err == nil {
				tags = make(map[string]string, len(tagResp.Tags))
				for _, tag := range tagResp.Tags {
					tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
				}
			}

			var results []audit.Finding
			if !encrypted {
				d := "service-side encryption disabled"
				results = append(
					results,
					audit.Finding{
						Service:    "dynamodb",
						ResourceID: name,
						Tags:       tags,
						Check:      "no_encryption",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "HIGH",
						Remediation: remediation.Recommend(
							"security",
							"dynamodb",
							"no_encryption",
							name,
							d,
						),
					},
				)
			}
			if !pitr {
				d := "point-in-time recovery disabled"
				results = append(
					results,
					audit.Finding{
						Service:    "dynamodb",
						ResourceID: name,
						Tags:       tags,
						Check:      "no_pitr",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "MEDIUM",
						Remediation: remediation.Recommend(
							"security",
							"dynamodb",
							"no_pitr",
							name,
							d,
						),
					},
				)
			}
			if !delProtect {
				d := "deletion protection disabled"
				results = append(
					results,
					audit.Finding{
						Service:    "dynamodb",
						ResourceID: name,
						Tags:       tags,
						Check:      "no_delete_protection",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "MEDIUM",
						Remediation: remediation.Recommend(
							"security",
							"dynamodb",
							"no_delete_protection",
							name,
							d,
						),
					},
				)
			}
			if len(results) == 0 {
				results = append(
					results,
					audit.Finding{
						Service:    "dynamodb",
						ResourceID: name,
						Tags:       tags,
						Check:      "dynamodb_posture",
						Status:     "PASS",
						Detail:     "encrypted=true, pitr=true, deletion_protection=true",
						RiskLevel:  "MINIMAL",
					},
				)
			}
			return results
		},
	), nil
}
