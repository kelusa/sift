package discover

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/list"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
)

var resourceTypeMap = map[string]string{
	"AWS::EC2::Instance":                        "ec2",
	"AWS::EC2::Volume":                          "ebs",
	"AWS::EC2::SecurityGroup":                   "ec2",
	"AWS::EC2::EIP":                             "ec2",
	"AWS::EC2::NatGateway":                      "network",
	"AWS::EC2::VPNConnection":                   "vpn",
	"AWS::S3::Bucket":                           "s3",
	"AWS::RDS::DBInstance":                      "rds",
	"AWS::Lambda::Function":                     "lambda",
	"AWS::DynamoDB::Table":                      "dynamodb",
	"AWS::EKS::Cluster":                         "eks",
	"AWS::ElasticLoadBalancingV2::LoadBalancer": "elb",
	"AWS::ElasticLoadBalancingV2::TargetGroup":  "elb",
	"AWS::ElasticLoadBalancingV2::Listener":     "elb",
	"AWS::IAM::Role":                            "iam",
	"AWS::KMS::Key":                             "kms",
	"AWS::SNS::Topic":                           "sns",
	"AWS::SQS::Queue":                           "sqs",
	"AWS::SecretsManager::Secret":               "secrets",
	"AWS::ECR::Repository":                      "ecr",
	"AWS::Glue::Job":                            "glue",
	"AWS::Kinesis::Stream":                      "kinesis",
	"AWS::ElastiCache::CacheCluster":            "elasticache",
	"AWS::OpenSearch::Domain":                   "opensearch",
	"AWS::Redshift::Cluster":                    "redshift",
	"AWS::DMS::ReplicationInstance":             "dms",
	"AWS::SageMaker::NotebookInstance":          "sagemaker",
	"AWS::CloudFront::Distribution":             "cloudfront",
	"AWS::WAFv2::WebACL":                        "waf",
	"AWS::Backup::BackupVault":                  "backup",
	"AWS::StepFunctions::StateMachine":          "stepfunctions",
	"AWS::EFS::FileSystem":                      "efs",
	"AWS::MSK::Cluster":                         "msk",
	"AWS::DocDB::DBCluster":                     "docdb",
	"AWS::Events::EventBus":                     "eventbridge",
	"AWS::Route53::HostedZone":                  "route53",
	"AWS::ACM::Certificate":                     "acm",
	"AWS::CloudWatch::LogGroup":                 "cloudwatch",
	"AWS::CloudTrail::Trail":                    "cloudtrail",
	"AWS::GuardDuty::Detector":                  "guardduty",
	"AWS::Config::ConfigurationRecorder":        "awsconfig",
}

type ServiceInfo struct {
	Name     string `json:"name"`
	Count    int    `json:"count"`
	Security bool   `json:"security"`
	Cost     bool   `json:"cost"`
	List     bool   `json:"list"`
}

func Discover(ctx context.Context, cfg aws.Config) ([]ServiceInfo, error) {
	client := configservice.NewFromConfig(cfg)

	resp, err := client.GetDiscoveredResourceCounts(
		ctx,
		&configservice.GetDiscoveredResourceCountsInput{},
	)
	if err != nil {
		return nil, fmt.Errorf("get discovered resource counts: %w", err)
	}

	securityServices := audit.ValidServices("security")
	costServices := audit.ValidServices("cost")
	listServices := make(map[string]bool)
	for _, s := range list.Services() {
		listServices[s] = true
	}

	counts := make(map[string]int)
	for _, rc := range resp.ResourceCounts {
		resType := string(rc.ResourceType)
		if svc, ok := resourceTypeMap[resType]; ok {
			counts[svc] += int(rc.Count)
		} else {
			// Extract a readable service name from AWS::Service::Resource
			parts := strings.Split(resType, "::")
			if len(parts) == 3 {
				svc := strings.ToLower(parts[1])
				counts[svc] += int(rc.Count)
			}
		}
	}

	// Supplement with Resource Explorer
	reClient := resourceexplorer2.NewFromConfig(cfg)
	reResp, err := reClient.Search(ctx, &resourceexplorer2.SearchInput{
		QueryString: aws.String("*"),
	})
	if err == nil {
		for _, r := range reResp.Resources {
			resType := aws.ToString(r.ResourceType)
			parts := strings.Split(resType, "::")
			if len(parts) < 2 {
				continue
			}
			svc := strings.ToLower(parts[1])
			if mapped, ok := resourceTypeMap[resType]; ok {
				svc = mapped
			}
			if counts[svc] == 0 {
				counts[svc]++
			}
		}
	}

	var services []ServiceInfo
	for svc, count := range counts {
		services = append(services, ServiceInfo{
			Name:     svc,
			Count:    count,
			Security: securityServices[svc],
			Cost:     costServices[svc],
			List:     listServices[svc],
		})
	}

	sort.Slice(services, func(i, j int) bool {
		return services[i].Count > services[j].Count
	})

	return services, nil
}

func FormatOutput(services []ServiceInfo) string {
	var sb strings.Builder

	// Calculate max service name width
	maxWidth := 7 // minimum "SERVICE" header width
	for _, s := range services {
		if len(s.Name) > maxWidth {
			maxWidth = len(s.Name)
		}
	}

	fmtStr := fmt.Sprintf("  %%-%ds  %%8s  %%s\n", maxWidth)
	sb.WriteString(fmt.Sprintf(fmtStr, "SERVICE", "COUNT", "COVERAGE"))
	sb.WriteString(fmt.Sprintf(fmtStr, strings.Repeat("-", maxWidth), "-----", "--------"))

	var secSvcs, costSvcs []string
	var uncovered []string
	rowFmt := fmt.Sprintf("  %%-%ds  %%8d  %%s %%s\n", maxWidth)
	for _, s := range services {
		var coverage []string
		if s.Security {
			coverage = append(coverage, "security")
			secSvcs = append(secSvcs, s.Name)
		}
		if s.Cost {
			coverage = append(coverage, "cost")
			costSvcs = append(costSvcs, s.Name)
		}
		if s.List {
			coverage = append(coverage, "list")
		}

		marker := "✓"
		coverStr := strings.Join(coverage, ", ")
		if len(coverage) == 0 {
			marker = "X"
			coverStr = "not covered"
			uncovered = append(uncovered, s.Name)
		}

		sb.WriteString(fmt.Sprintf(rowFmt, s.Name, s.Count, marker, coverStr))
	}

	sb.WriteString("\nSuggested commands:\n")
	if len(secSvcs) > 0 {
		sb.WriteString(fmt.Sprintf("  sift aws security --service %s\n", strings.Join(secSvcs, ",")))
	}
	if len(costSvcs) > 0 {
		sb.WriteString(fmt.Sprintf("  sift aws cost --service %s\n", strings.Join(costSvcs, ",")))
	}
	if len(uncovered) > 0 {
		sb.WriteString(fmt.Sprintf("\nNot covered: %s\n", strings.Join(uncovered, ", ")))
	}

	return sb.String()
}
