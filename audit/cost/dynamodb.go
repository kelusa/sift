package cost

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func init() {
	audit.RegisterAWS(Module, "dynamodb", AuditDynamoDBCost)
}

type dynamoDBCostTable struct {
	name        string
	readCap     int64
	writeCap    int64
	provisioned bool
	gsis        []dbtypes.GlobalSecondaryIndexDescription
	tags        map[string]string
}

func parseDynamodDBCostTable(
	ctx context.Context,
	client *dynamodb.Client,
	name string,
) (*dynamoDBCostTable, error) {
	desc, err := client.DescribeTable(
		ctx,
		&dynamodb.DescribeTableInput{TableName: aws.String(name)},
	)
	if err != nil {
		return nil, err
	}
	table := desc.Table

	t := &dynamoDBCostTable{
		name: name,
		gsis: table.GlobalSecondaryIndexes,
	}

	if table.BillingModeSummary == nil ||
		table.BillingModeSummary.BillingMode == dbtypes.BillingModeProvisioned {
		t.provisioned = true
		if table.ProvisionedThroughput != nil {
			t.readCap = aws.ToInt64(table.ProvisionedThroughput.ReadCapacityUnits)
			t.writeCap = aws.ToInt64(table.ProvisionedThroughput.WriteCapacityUnits)
		}
	}

	tagResp, err := client.ListTagsOfResource(
		ctx,
		&dynamodb.ListTagsOfResourceInput{ResourceArn: table.TableArn},
	)
	if err == nil {
		t.tags = make(map[string]string, len(tagResp.Tags))
		for _, tag := range tagResp.Tags {
			t.tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
	}

	return t, nil
}

func AuditDynamoDBCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
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
		"Auditing DynamoDB cost",
		func(ctx context.Context, name string) []audit.Finding {
			t, err := parseDynamodDBCostTable(ctx, client, name)
			if err != nil {
				return []audit.Finding{audit.ErrorFinding("dynamodb", name, "cost_audit", err)}
			}

			var findings []audit.Finding
			if t.provisioned && (t.readCap > 0 || t.writeCap > 0) {
				findings = append(findings, audit.Finding{
					Service:    "dynamodb",
					ResourceID: t.name,
					Tags:       t.tags,
					Check:      "provisioned_mode",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"provisioned mode (RCU=%d, WCU=%d) - consider on-demand if traffic is unpredictable",
						t.readCap,
						t.writeCap,
					),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: pricing.DynamoDBProvisionedMonthly(t.readCap, t.writeCap),
					Remediation: remediation.Recommend(
						"cost",
						"dynamodb",
						"provisioned_mode",
						t.name,
						fmt.Sprintf("RCU=%d, WCU=%d", t.readCap, t.writeCap),
					),
				})
			}

			for _, gsi := range t.gsis {
				if gsi.ItemCount != nil && aws.ToInt64(gsi.ItemCount) == 0 {
					findings = append(findings, audit.Finding{
						Service: "dynamodb",
						ResourceID: fmt.Sprintf(
							"%s/%s",
							t.name,
							aws.ToString(gsi.IndexName),
						),
						Tags:                 t.tags,
						Check:                "unused_gsi",
						Status:               "WARN",
						Detail:               "GSI has zero items - wasting provisioned capacity",
						RiskLevel:            "MEDIUM",
						EstimatedMonthlyCost: 0,
						Remediation: remediation.Recommend(
							"cost",
							"dynamodb",
							"unused_gsi",
							fmt.Sprintf("%s/%s", t.name, aws.ToString(gsi.IndexName)),
							"GSI has zero items",
						),
					})
				}
			}
			if len(findings) == 0 {
				findings = append(findings, audit.Finding{
					Service:    "dynamodb",
					ResourceID: t.name,
					Tags:       t.tags,
					Check:      "dynamodb_cost",
					Status:     "PASS",
					Detail:     "no cost issues detected",
					RiskLevel:  "MINIMAL",
				})
			}
			return findings
		},
	), nil
}
