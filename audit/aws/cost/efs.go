package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
)

func init() {
	awsreg.Register(Module, "efs", AuditEFSCost)
}

func AuditEFSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := efs.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	var fileSystems []struct {
		id     string
		sizeGB float64
		tags   map[string]string
	}

	input := &efs.DescribeFileSystemsInput{}
	for {
		resp, err := client.DescribeFileSystems(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe file systems: %w", err)
		}
		for _, fs := range resp.FileSystems {
			tags := make(map[string]string, len(fs.Tags))
			for _, t := range fs.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			var sizeGB float64
			if fs.SizeInBytes != nil {
				sizeGB = float64(fs.SizeInBytes.Value) / (1024 * 1024 * 1024)
			}
			fileSystems = append(fileSystems, struct {
				id     string
				sizeGB float64
				tags   map[string]string
			}{
				id:     aws.ToString(fs.FileSystemId),
				sizeGB: sizeGB,
				tags:   tags,
			})
		}
		if resp.NextMarker == nil {
			break
		}
		input.Marker = resp.NextMarker
	}

	end := time.Now()
	start := end.AddDate(0, 0, -30)

	return audit.ProcessAllMulti(
		ctx,
		fileSystems,
		"Auditing EFS cost",
		func(ctx context.Context, fs struct {
			id     string
			sizeGB float64
			tags   map[string]string
		}) []audit.Finding {
			var results []audit.Finding
			monthlyCost := fs.sizeGB * 0.30

			// Check mount targets
			mtResp, err := client.DescribeMountTargets(
				ctx,
				&efs.DescribeMountTargetsInput{FileSystemId: &fs.id},
			)
			if err != nil || len(mtResp.MountTargets) == 0 {
				results = append(results, audit.Finding{
					Service:    "efs",
					ResourceID: fs.id,
					Tags:       fs.tags,
					Check:      "no_mount_targets",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"size=%.2fGB, no mount targets - no consumers",
						fs.sizeGB,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"efs",
						"no_mount_targets",
						fs.id,
						"no mount targets",
					),
				})
				return results
			}

			// Check client connections
			connResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/EFS"),
				MetricName: aws.String("ClientConnections"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("FileSystemId"),
					Value: &fs.id,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})

			var totalConns float64
			if connResp != nil {
				for _, dp := range connResp.Datapoints {
					totalConns += aws.ToFloat64(dp.Sum)
				}
			}
			if totalConns == 0 {
				results = append(results, audit.Finding{
					Service:    "efs",
					ResourceID: fs.id,
					Tags:       fs.tags,
					Check:      "no_connections",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"size=%.2fGB, zero client connections in 30 days",
						fs.sizeGB,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"efs",
						"no_connections",
						fs.id,
						"zero connections in 30 days",
					),
				})
			}

			// Check lifecycle policy
			lcResp, err := client.DescribeLifecycleConfiguration(
				ctx,
				&efs.DescribeLifecycleConfigurationInput{FileSystemId: &fs.id},
			)
			if err != nil || len(lcResp.LifecyclePolicies) == 0 {
				results = append(results, audit.Finding{
					Service:    "efs",
					ResourceID: fs.id,
					Tags:       fs.tags,
					Check:      "no_lifecycle_policy",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"size=%.2fGB, no lifecycle policy - data never transitions to IA ($0.016/GB)",
						fs.sizeGB,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"efs",
						"no_lifecycle_policy",
						fs.id,
						"no lifecycle policy configured",
					),
				})
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "efs",
					ResourceID: fs.id,
					Tags:       fs.tags,
					Check:      "efs_cost",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"size=%.2fGB, active with lifecycle policy",
						fs.sizeGB,
					),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: monthlyCost,
				})
			}
			return results
		},
	), nil
}
