package list

import (
	"context"
	"fmt"
	"strconv"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func init() {
	Register(Lister{
		Service: "rds",
		Columns: map[string][]Column{
			"instance": {
				{Key: "engine", Header: "ENGINE"},
				{Key: "version", Header: "VERSION"},
				{Key: "class", Header: "CLASS"},
				{Key: "storage_gb", Header: "STORAGE(GB)"},
				{Key: "multi_az", Header: "MULTI-AZ"},
				{Key: "public", Header: "PUBLIC"},
				{Key: "status", Header: "STATUS"},
				{Key: "backup_days", Header: "BACKUP(d)"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, _ string) ([]audit.Resource, error) {
			return ListRDSInstances(ctx, cfg)
		},
	})
}

func ListRDSInstances(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := rds.NewFromConfig(cfg)

	var resources []audit.Resource
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe db instances: %w", err)
		}
		for _, db := range page.DBInstances {
			tags := make(map[string]string, len(db.TagList))
			for _, t := range db.TagList {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}

			props := map[string]string{
				"engine":      aws.ToString(db.Engine),
				"version":     aws.ToString(db.EngineVersion),
				"class":       aws.ToString(db.DBInstanceClass),
				"storage_gb":  strconv.Itoa(int(aws.ToInt32(db.AllocatedStorage))),
				"multi_az":    strconv.FormatBool(aws.ToBool(db.MultiAZ)),
				"public":      strconv.FormatBool(aws.ToBool(db.PubliclyAccessible)),
				"status":      aws.ToString(db.DBInstanceStatus),
				"backup_days": strconv.Itoa(int(aws.ToInt32(db.BackupRetentionPeriod))),
			}

			resources = append(resources, audit.Resource{
				Service:    "rds",
				ResourceID: aws.ToString(db.DBInstanceIdentifier),
				Type:       "instance",
				Properties: props,
				Tags:       tags,
			})
		}
	}
	return resources, nil
}
