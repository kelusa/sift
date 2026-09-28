package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/aws/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
)

func init() {
	awsreg.Register(Module, "msk", AuditMSKCost)
}

func AuditMSKCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := kafka.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	var clusters []struct {
		arn        string
		name       string
		brokerType string
		brokers    int32
		storageGB  int32
		tags       map[string]string
	}

	input := &kafka.ListClustersV2Input{}
	for {
		resp, err := client.ListClustersV2(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list clusters: %w", err)
		}
		for _, c := range resp.ClusterInfoList {
			var brokerType string
			var brokers, storageGB int32
			if c.Provisioned != nil {
				brokerType = aws.ToString(c.Provisioned.BrokerNodeGroupInfo.InstanceType)
				brokers = aws.ToInt32(c.Provisioned.NumberOfBrokerNodes)
				if c.Provisioned.BrokerNodeGroupInfo.StorageInfo != nil &&
					c.Provisioned.BrokerNodeGroupInfo.StorageInfo.EbsStorageInfo != nil {
					storageGB = aws.ToInt32(
						c.Provisioned.BrokerNodeGroupInfo.StorageInfo.EbsStorageInfo.VolumeSize,
					)
				}
			}
			clusters = append(clusters, struct {
				arn        string
				name       string
				brokerType string
				brokers    int32
				storageGB  int32
				tags       map[string]string
			}{
				arn:        aws.ToString(c.ClusterArn),
				name:       aws.ToString(c.ClusterName),
				brokerType: brokerType,
				brokers:    brokers,
				storageGB:  storageGB,
				tags:       c.Tags,
			})
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	lookback := t.GetInt("msk", "cpu_lookback_days", 7)
	cpuThreshold := t.GetFloat("msk", "cpu_idle_percent", 10)
	end := time.Now()
	start := end.AddDate(0, 0, -lookback)

	return audit.ProcessAllMulti(
		ctx,
		clusters,
		"Auditing MSK cost",
		func(ctx context.Context, c struct {
			arn        string
			name       string
			brokerType string
			brokers    int32
			storageGB  int32
			tags       map[string]string
		}) []audit.Finding {
			var results []audit.Finding
			storageCost := float64(c.brokers) * float64(c.storageGB) * 0.10
			brokerCost := pricing.MSKMonthly(c.brokerType, c.brokers)
			monthlyCost := brokerCost + storageCost

			// Check BytesInPerSec (idle check)
			bytesResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/Kafka"),
				MetricName: aws.String("BytesInPerSec"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("Cluster Name"),
					Value: &c.name,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})

			var totalBytes float64
			if bytesResp != nil {
				for _, dp := range bytesResp.Datapoints {
					totalBytes += aws.ToFloat64(dp.Sum)
				}
			}

			if totalBytes == 0 {
				results = append(results, audit.Finding{
					Service:    "msk",
					ResourceID: c.name,
					Tags:       c.tags,
					Check:      "idle_cluster",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, brokers=%d, zero bytes in over %d days",
						c.brokerType,
						c.brokers,
						lookback,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"msk",
						"idle_cluster",
						c.name,
						"zero bytes in",
					),
				})
				return results
			}

			// Check CPU utilization
			cpuResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/Kafka"),
				MetricName: aws.String("CpuUser"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("Cluster Name"),
					Value: &c.name,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})

			if cpuResp != nil && len(cpuResp.Datapoints) > 0 {
				var total float64
				for _, dp := range cpuResp.Datapoints {
					total += aws.ToFloat64(dp.Average)
				}
				avgCPU := total / float64(len(cpuResp.Datapoints))
				if avgCPU < cpuThreshold {
					results = append(results, audit.Finding{
						Service:    "msk",
						ResourceID: c.name,
						Tags:       c.tags,
						Check:      "oversized_cluster",
						Status:     "WARN",
						Detail: fmt.Sprintf(
							"type=%s, brokers=%d, avg CPU=%.1f%% over %d days",
							c.brokerType,
							c.brokers,
							avgCPU,
							lookback,
						),
						RiskLevel: "MEDIUM",
						Remediation: remediation.Recommend(
							"cost",
							"msk",
							"oversized_cluster",
							c.name,
							fmt.Sprintf("avg CPU %.1f%%", avgCPU),
						),
					})
				}
			}

			// Check disk utilization
			diskResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/Kafka"),
				MetricName: aws.String("KafkaDataLogsDiskUsed"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("Cluster Name"),
					Value: &c.name,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})

			if diskResp != nil && len(diskResp.Datapoints) > 0 {
				var total float64
				for _, dp := range diskResp.Datapoints {
					total += aws.ToFloat64(dp.Average)
				}
				avgDisk := total / float64(len(diskResp.Datapoints))
				if avgDisk < 20 {
					results = append(results, audit.Finding{
						Service:    "msk",
						ResourceID: c.name,
						Tags:       c.tags,
						Check:      "overprovisioned_storage",
						Status:     "WARN",
						Detail: fmt.Sprintf(
							"type=%s, brokers=%d, storage=%dGB/broker, disk usage=%.1f%%",
							c.brokerType,
							c.brokers,
							c.storageGB,
							avgDisk,
						),
						RiskLevel:            "LOW",
						EstimatedMonthlyCost: monthlyCost,
						Remediation: remediation.Recommend(
							"cost",
							"msk",
							"overprovisioned_storage",
							c.name,
							fmt.Sprintf("disk usage %.1f%%", avgDisk),
						),
					})
				}
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "msk",
					ResourceID: c.name,
					Tags:       c.tags,
					Check:      "msk_cost",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"type=%s, brokers=%d, active",
						c.brokerType,
						c.brokers,
					),
					RiskLevel:            "MINIMAL",
					EstimatedMonthlyCost: monthlyCost,
				})
			}
			return results
		},
	), nil
}
