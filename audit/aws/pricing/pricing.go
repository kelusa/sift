package pricing

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed prices.json
var embeddedPrices embed.FS

type PriceTable struct {
	Region            string             `json:"region"`
	HoursPerMonth     float64            `json:"hours_per_month"`
	EC2Hourly         map[string]float64 `json:"ec2_hourly"`
	EBSPerGB          map[string]float64 `json:"ebs_per_gb"`
	EBSSnapshotPerGB  float64            `json:"ebs_snapshot_per_gb"`
	ElastiCacheHourly map[string]float64 `json:"elasticache_hourly"`
	RDSHourly         map[string]float64 `json:"rds_hourly"`
	DirectoryMonthly  map[string]float64 `json:"directory_monthly"`
	DMSHourly         map[string]float64 `json:"dms_hourly"`
	RedshiftHourly    map[string]float64 `json:"redshift_hourly"`
	GlueDPUHourly     map[string]float64 `json:"glue_dpu_hourly"`
	MSKHourly         map[string]float64 `json:"msk_hourly"`
	SageMakerHourly   map[string]float64 `json:"sagemaker_hourly"`
	FixedMonthly      map[string]float64 `json:"fixed_monthly"`
	StoragePerGB      map[string]float64 `json:"storage_per_gb"`
	DynamoDB          struct {
		PerRCU float64 `json:"per_rcu"`
		PerWCU float64 `json:"per_wcu"`
	} `json:"dynamodb_monthly"`
	Lambda struct {
		ProvisionedPerGBSecond float64 `json:"provisioned_per_gb_second"`
	} `json:"lambda"`
}

var table *PriceTable

func init() {
	table = load()
}

func load() *PriceTable {
	// Try user override first: ~/.sift/prices.json
	home, err := os.UserHomeDir()
	if err == nil {
		override := filepath.Join(home, ".sift", "prices.json")
		if data, err := os.ReadFile(override); err == nil {
			var t PriceTable
			if json.Unmarshal(data, &t) == nil {
				return &t
			}
		}
	}

	// Fall back to embedded
	data, err := embeddedPrices.ReadFile("prices.json")
	if err != nil {
		panic(fmt.Sprintf("failed to read embedded prices: %v", err))
	}
	var t PriceTable
	if err := json.Unmarshal(data, &t); err != nil {
		panic(fmt.Sprintf("failed to parse embedded prices: %v", err))
	}
	return &t
}

func EC2Monthly(instanceType string) float64 {
	if h, ok := table.EC2Hourly[instanceType]; ok {
		return h * table.HoursPerMonth
	}
	return 0
}

func EBSMonthly(volumeType string, sizeGB int32) float64 {
	if rate, ok := table.EBSPerGB[volumeType]; ok {
		return rate * float64(sizeGB)
	}
	return 0
}

func SnapshotMonthly(sizeGB int32) float64 {
	return table.EBSSnapshotPerGB * float64(sizeGB)
}

func ElastiCacheMonthly(nodeType string, nodes int32) float64 {
	if h, ok := table.ElastiCacheHourly[nodeType]; ok {
		return h * table.HoursPerMonth * float64(nodes)
	}
	return 0
}

func OpenSearchMonthly(instanceType string, nodes int32) float64 {
	// OpenSearch types are like "search.m5.large", strip "search" to look up EC2 pricing
	// (OpenSearch pricing is about 10-20% higher than EC2 but close enough for estimates)
	stripped := strings.TrimPrefix(instanceType, "search.")
	stripped = strings.TrimSuffix(stripped, ".search")
	if h, ok := table.EC2Hourly[stripped]; ok {
		return h * table.HoursPerMonth * float64(nodes) * 1.15 // ~15% markup over EC2
	}
	return 0
}

func MSKMonthly(brokerType string, brokers int32) float64 {
	if h, ok := table.MSKHourly[brokerType]; ok {
		return h * table.HoursPerMonth * float64(brokers)
	}
	return 0
}

func RDSMonthly(instanceClass string) float64 {
	if h, ok := table.RDSHourly[instanceClass]; ok {
		return h * table.HoursPerMonth
	}
	return 0
}

func DMSMonthly(instanceClass string) float64 {
	if h, ok := table.DMSHourly[instanceClass]; ok {
		return h * table.HoursPerMonth
	}
	return 0
}

func RedshiftMonthly(nodeType string, numNodes int32) float64 {
	if h, ok := table.RedshiftHourly[nodeType]; ok {
		return h * table.HoursPerMonth * float64(numNodes)
	}
	return 0
}

func ELBMonthly(lbType string) float64 {
	if lbType == "network" {
		return table.FixedMonthly["nlb"]
	}
	return table.FixedMonthly["alb"]
}

func NATGatewayMonthly() float64 {
	return table.FixedMonthly["nat_gateway"]
}

func EKSClusterMonthly() float64 {
	return table.FixedMonthly["eks_cluster"]
}

func SecretMonthly() float64 {
	return table.FixedMonthly["secret"]
}

func CloudWatchLogsMonthly(storedGB float64) float64 {
	return table.StoragePerGB["cloudwatch_logs"] * storedGB
}

func ECRMonthly(storedGB float64) float64 {
	return table.StoragePerGB["ecr"] * storedGB
}

func S3Monthly(storedGB float64) float64 {
	return table.StoragePerGB["s3_standard"] * storedGB
}

func DynamoDBProvisionedMonthly(readCap, writeCap int64) float64 {
	return float64(readCap)*table.DynamoDB.PerRCU + float64(writeCap)*table.DynamoDB.PerWCU
}

func LambdaProvisionedMonthly(memoryMB, concurrency int32) float64 {
	gbSeconds := float64(memoryMB) / 1024.0 * float64(concurrency) * 3600 * table.HoursPerMonth
	return table.Lambda.ProvisionedPerGBSecond * gbSeconds
}

func GlueJobHourlyCost(workerType string, workers int32) float64 {
	rate, ok := table.GlueDPUHourly[workerType]
	if !ok {
		rate = table.GlueDPUHourly["Standard"]
	}
	return rate * float64(workers)
}

func ElasticIPMonthly() float64 {
	return table.FixedMonthly["elastic_ip"]
}

func DirectoryMonthly(dirType, size string) float64 {
	key := strings.ToLower(dirType + "_" + size)
	if v, ok := table.DirectoryMonthly[key]; ok {
		return v
	}
	return 0
}

func SageMakerMonthly(instanceType string) float64 {
	if h, ok := table.SageMakerHourly[instanceType]; ok {
		return h * table.HoursPerMonth
	}
	return 0
}
