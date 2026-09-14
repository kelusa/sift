package list

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/timestreamwrite"
	tstypes "github.com/aws/aws-sdk-go-v2/service/timestreamwrite/types"
)

func init() {
	Register(Lister{
		Service:  "timestream",
		SubTypes: []string{"databases", "tables"},
		Columns: map[string][]Column{
			"database": {
				{Key: "tables", Header: "TABLES"},
				{Key: "kms_key", Header: "KMS_KEY"},
				{Key: "status", Header: "STATUS"},
			},
			"tables": {
				{Key: "database", Header: "DATABASE"},
				{Key: "status", Header: "STATUS"},
				{Key: "mem_retention_hrs", Header: "MEM_RET(h)"},
				{Key: "mag_retention_days", Header: "MAG_RET(d)"},
				{Key: "writes_30d", Header: "WRITES(30d)"},
				{Key: "queries_30d", Header: "QUERIES(30d)"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, subType string) ([]audit.Resource, error) {
			switch subType {
			case "databases", "":
				return listTimestreamDatabases(ctx, cfg)
			case "tables":
				return listTimestreamTables(ctx, cfg)
			default:
				return nil, fmt.Errorf("unknown sub-type %q (use databases or tables)", subType)
			}
		},
	})
}

func listTimestreamDatabases(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := timestreamwrite.NewFromConfig(cfg)

	var resources []audit.Resource
	input := &timestreamwrite.ListDatabasesInput{}
	for {
		resp, err := client.ListDatabases(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list databases: %w", err)
		}
		for _, db := range resp.Databases {
			name := aws.ToString(db.DatabaseName)
			tableCount := countTables(ctx, client, name)

			tags := fetchTimestreamTags(ctx, client, aws.ToString(db.Arn))

			kmsKey := aws.ToString(db.KmsKeyId)
			if kmsKey == "" {
				kmsKey = "aws-managed"
			}

			resources = append(resources, audit.Resource{
				Service:    "timestream",
				ResourceID: name,
				Type:       "database",
				Properties: map[string]string{
					"tables":  strconv.Itoa(tableCount),
					"kms_key": truncateARN(kmsKey),
					"status":  "ACTIVE",
				},
				Tags: tags,
			})
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	return resources, nil
}

func listTimestreamTables(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := timestreamwrite.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	var databases []string
	dbInput := &timestreamwrite.ListDatabasesInput{}
	for {
		resp, err := client.ListDatabases(ctx, dbInput)
		if err != nil {
			return nil, fmt.Errorf("list databases: %w", err)
		}
		for _, db := range resp.Databases {
			databases = append(databases, aws.ToString(db.DatabaseName))
		}
		if resp.NextToken == nil {
			break
		}
		dbInput.NextToken = resp.NextToken
	}

	var resources []audit.Resource
	for _, dbName := range databases {
		tblInput := &timestreamwrite.ListTablesInput{DatabaseName: &dbName}
		for {
			resp, err := client.ListTables(ctx, tblInput)
			if err != nil {
				break
			}
			for _, t := range resp.Tables {
				resources = append(resources, buildTableResource(ctx, client, cwClient, dbName, t))
			}
			if resp.NextToken == nil {
				break
			}
			tblInput.NextToken = resp.NextToken
		}
	}
	return resources, nil
}

func buildTableResource(
	ctx context.Context,
	client *timestreamwrite.Client,
	cwClient *cloudwatch.Client,
	dbName string,
	t tstypes.Table,
) audit.Resource {
	tableName := aws.ToString(t.TableName)
	resourceID := fmt.Sprintf("%s/%s", dbName, tableName)

	var memHrs, magDays int64
	if t.RetentionProperties != nil {
		memHrs = aws.ToInt64(t.RetentionProperties.MemoryStoreRetentionPeriodInHours)
		magDays = aws.ToInt64(t.RetentionProperties.MagneticStoreRetentionPeriodInDays)
	}

	writes := getOperationCount(ctx, cwClient, dbName, tableName, "WriteRecords")
	queries := getOperationCount(ctx, cwClient, dbName, tableName, "Query")
	tags := fetchTimestreamTags(ctx, client, aws.ToString(t.Arn))

	status := "ACTIVE"
	if t.TableStatus != "" {
		status = string(t.TableStatus)
	}

	return audit.Resource{
		Service:    "timestream",
		ResourceID: resourceID,
		Type:       "table",
		Properties: map[string]string{
			"database":           dbName,
			"status":             status,
			"mem_retention_hrs":  strconv.FormatInt(memHrs, 10),
			"mag_retention_days": strconv.FormatInt(magDays, 10),
			"writes_30d":         writes,
			"queries_30d":        queries,
		},
		Tags: tags,
	}
}

func countTables(ctx context.Context, client *timestreamwrite.Client, database string) int {
	count := 0
	input := &timestreamwrite.ListTablesInput{DatabaseName: &database}
	for {
		resp, err := client.ListTables(ctx, input)
		if err != nil {
			break
		}
		count += len(resp.Tables)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	return count
}

func getOperationCount(
	ctx context.Context,
	cwClient *cloudwatch.Client,
	database, table string,
	operation string,
) string {
	end := time.Now()
	start := end.AddDate(0, 0, -30)

	resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/Timestream"),
		MetricName: aws.String("SuccessfulRequestLatency"),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("DatabaseName"), Value: &database},
			{Name: aws.String("TableName"), Value: &table},
			{Name: aws.String("Operation"), Value: aws.String(operation)},
		},
		StartTime:  &start,
		EndTime:    &end,
		Period:     aws.Int32(2592000), // 30 days
		Statistics: []cwtypes.Statistic{cwtypes.StatisticSampleCount},
	})
	if err != nil || len(resp.Datapoints) == 0 {
		return "0"
	}
	total := 0.0
	for _, dp := range resp.Datapoints {
		total += aws.ToFloat64(dp.SampleCount)
	}
	return strconv.Itoa(int(total))
}

func fetchTimestreamTags(
	ctx context.Context,
	client *timestreamwrite.Client,
	arn string,
) map[string]string {
	if arn == "" {
		return nil
	}
	resp, err := client.ListTagsForResource(ctx, &timestreamwrite.ListTagsForResourceInput{
		ResourceARN: &arn,
	})
	if err != nil {
		return nil
	}
	tags := make(map[string]string, len(resp.Tags))
	for _, t := range resp.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return tags
}

func truncateARN(s string) string {
	if len(s) > 40 {
		return "..." + s[len(s)-37:]
	}
	return s
}
