package list

import (
	"context"
	"fmt"
	"strconv"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func init() {
	Register(Lister{
		Service: "dynamodb",
		Columns: map[string][]Column{
			"table": {
				{Key: "mode", Header: "MODE"},
				{Key: "items", Header: "ITEMS"},
				{Key: "size_mb", Header: "SIZE(MB)"},
				{Key: "pitr", Header: "PITR"},
				{Key: "encrypted", Header: "ENCRYPTED"},
				{Key: "status", Header: "STATUS"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, _ string) ([]audit.Resource, error) {
			return ListDynamoDBTables(ctx, cfg)
		},
	})
}

func ListDynamoDBTables(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := dynamodb.NewFromConfig(cfg)

	var names []string
	input := &dynamodb.ListTablesInput{}
	for {
		resp, err := client.ListTables(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list tables: %w", err)
		}
		names = append(names, resp.TableNames...)
		if resp.LastEvaluatedTableName == nil {
			break
		}
		input.ExclusiveStartTableName = resp.LastEvaluatedTableName
	}

	resources := audit.FetchAll(ctx, names, "Listing DynamoDB tables",
		func(ctx context.Context, name string) audit.Resource {
			desc, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &name})
			if err != nil {
				return audit.Resource{
					Service:    "dynamodb",
					ResourceID: name,
					Type:       "table",
					Properties: map[string]string{},
				}
			}
			t := desc.Table

			mode := "PROVISIONED"
			if t.BillingModeSummary != nil {
				mode = string(t.BillingModeSummary.BillingMode)
			}

			encrypted := "true"
			if t.SSEDescription != nil && t.SSEDescription.Status != "ENABLED" {
				encrypted = "false"
			}

			props := map[string]string{
				"mode":      mode,
				"items":     strconv.FormatInt(aws.ToInt64(t.ItemCount), 10),
				"size_mb":   strconv.FormatInt(aws.ToInt64(t.TableSizeBytes)/(1024*1024), 10),
				"encrypted": encrypted,
				"status":    string(t.TableStatus),
			}

			// PITR
			pitrResp, err := client.DescribeContinuousBackups(
				ctx,
				&dynamodb.DescribeContinuousBackupsInput{TableName: &name},
			)
			if err == nil && pitrResp.ContinuousBackupsDescription != nil &&
				pitrResp.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
				props["pitr"] = string(
					pitrResp.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus,
				)
			}

			return audit.Resource{
				Service:    "dynamodb",
				ResourceID: name,
				Type:       "table",
				Properties: props,
			}
		},
	)
	return resources, nil
}
