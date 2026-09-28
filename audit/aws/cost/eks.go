package cost

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/aws/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

func init() {
	awsreg.Register(Module, "eks", AuditEKSCost)
}

type eksCostNodegroup struct {
	cluster       string
	name          string
	instanceTypes []string
	desiredSize   int32
	tags          map[string]string
}

func parseEKSCostNodegroup(cluster string, ng *ekstypes.Nodegroup) eksCostNodegroup {
	n := eksCostNodegroup{
		cluster:       cluster,
		name:          aws.ToString(ng.NodegroupName),
		instanceTypes: ng.InstanceTypes,
		tags:          ng.Tags,
	}
	if ng.ScalingConfig != nil {
		n.desiredSize = aws.ToInt32(ng.ScalingConfig.DesiredSize)
	}
	return n
}

func AuditEKSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := eks.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	asgClient := autoscaling.NewFromConfig(cfg)
	ec2Client := ec2.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	var allClusters []string
	clusterInput := &eks.ListClustersInput{}
	for {
		resp, err := client.ListClusters(ctx, clusterInput)
		if err != nil {
			return nil, fmt.Errorf("list clusters: %w", err)
		}
		allClusters = append(allClusters, resp.Clusters...)
		if resp.NextToken == nil {
			break
		}
		clusterInput.NextToken = resp.NextToken
	}

	return audit.ProcessAllMulti(
		ctx,
		allClusters,
		"Auditing EKS cost",
		func(ctx context.Context, name string) []audit.Finding {
			desc, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
			var clusterTags map[string]string
			if err == nil {
				clusterTags = desc.Cluster.Tags
			}

			var allNodegroups []string
			ngInput := &eks.ListNodegroupsInput{ClusterName: &name}
			for {
				ngResp, err := client.ListNodegroups(ctx, ngInput)
				if err != nil {
					return []audit.Finding{audit.ErrorFinding("eks", name, "list_nodegroups", err)}
				}
				allNodegroups = append(allNodegroups, ngResp.Nodegroups...)
				if ngResp.NextToken == nil {
					break
				}
				ngInput.NextToken = ngResp.NextToken
			}
			if len(allNodegroups) == 0 {
				return []audit.Finding{{
					Service:              "eks",
					ResourceID:           name,
					Tags:                 clusterTags,
					Check:                "cluster_no_nodegroups",
					Status:               "WARN",
					Detail:               "paying for control plane ($0.10/hr) with no node groups",
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: pricing.EKSClusterMonthly(),
					Remediation: remediation.Recommend(
						"cost",
						"eks",
						"cluster_no_nodegroups",
						name,
						"no node groups attached",
					),
				}}
			}
			var results []audit.Finding
			for _, ngName := range allNodegroups {
				ngResp, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
					ClusterName:   &name,
					NodegroupName: &ngName,
				})
				if err != nil {
					results = append(
						results,
						audit.ErrorFinding(
							"eks_nodegroup",
							fmt.Sprintf("%s/%s", name, ngName),
							"describe_nodegroup",
							err,
						),
					)
					continue
				}
				n := parseEKSCostNodegroup(name, ngResp.Nodegroup)
				var nodeCost float64
				resolvedType := ""
				if len(n.instanceTypes) > 0 {
					resolvedType = n.instanceTypes[0]
				}
				// Resolve instance type from launch template if not set directly
				if resolvedType == "" && ngResp.Nodegroup.LaunchTemplate != nil {
					lt := ngResp.Nodegroup.LaunchTemplate
					ltInput := &ec2.DescribeLaunchTemplateVersionsInput{}
					if lt.Id != nil {
						ltInput.LaunchTemplateId = lt.Id
					} else if lt.Name != nil {
						ltInput.LaunchTemplateName = lt.Name
					}
					if ltInput.LaunchTemplateId != nil || ltInput.LaunchTemplateName != nil {
						if lt.Version != nil {
							ltInput.Versions = []string{*lt.Version}
						} else {
							ltInput.Versions = []string{"$Default"}
						}
						ltResp, ltErr := ec2Client.DescribeLaunchTemplateVersions(ctx, ltInput)
						if ltErr == nil && len(ltResp.LaunchTemplateVersions) > 0 {
							if data := ltResp.LaunchTemplateVersions[0].LaunchTemplateData; data != nil {
								resolvedType = string(data.InstanceType)
							}
						}
					}
				}
				// Fallback: resolve from running ASG instances
				if resolvedType == "" && ngResp.Nodegroup.Resources != nil {
					for _, asg := range ngResp.Nodegroup.Resources.AutoScalingGroups {
						if asg.Name == nil {
							continue
						}
						asgResp, err := asgClient.DescribeAutoScalingGroups(
							ctx,
							&autoscaling.DescribeAutoScalingGroupsInput{
								AutoScalingGroupNames: []string{*asg.Name},
							},
						)
						if err != nil || len(asgResp.AutoScalingGroups) == 0 {
							continue
						}
						for _, inst := range asgResp.AutoScalingGroups[0].Instances {
							if inst.InstanceType != nil {
								resolvedType = *inst.InstanceType
								break
							}
						}
						if resolvedType != "" {
							break
						}
					}
				}
				if resolvedType != "" {
					nodeCost = pricing.EC2Monthly(resolvedType)
				}
				var ngFindings []audit.Finding

				// Check previous-gen instance type using resolved type
				if resolvedType != "" {
					for _, prefix := range PrevGenPrefixes {
						if strings.HasPrefix(resolvedType, prefix) {
							ngFindings = append(ngFindings, audit.Finding{
								Service:    "eks_nodegroup",
								ResourceID: fmt.Sprintf("%s/%s", n.cluster, n.name),
								Tags:       n.tags,
								Check:      "previous_gen_node",
								Status:     "WARN",
								Detail: fmt.Sprintf(
									"type=%s, consider upgrading",
									resolvedType,
								),
								RiskLevel:            "LOW",
								EstimatedMonthlyCost: nodeCost,
								Remediation: remediation.Recommend(
									"cost",
									"eks",
									"previous_gen_node",
									fmt.Sprintf("%s/%s", n.cluster, n.name),
									fmt.Sprintf("type=%s", resolvedType),
								),
							})
							break
						}
					}
				}

				// Graviton opportunity
				if resolvedType != "" {
					gravitonType, _, _, savings := pricing.GravitonSavings(resolvedType)
					if gravitonType != "" && savings > 0 {
						ngFindings = append(ngFindings, audit.Finding{
							Service:    "eks_nodegroup",
							ResourceID: fmt.Sprintf("%s/%s", n.cluster, n.name),
							Tags:       n.tags,
							Check:      "graviton_opportunity",
							Status:     "WARN",
							Detail: fmt.Sprintf(
								"type=%s, switch to %s, save $%.0f/mo per node (nodes=%d)",
								resolvedType,
								gravitonType,
								savings,
								n.desiredSize,
							),
							RiskLevel:            "LOW",
							EstimatedMonthlyCost: savings * float64(n.desiredSize),
							Remediation: remediation.Recommend(
								"cost",
								"eks",
								"graviton_opportunity",
								fmt.Sprintf("%s/%s", n.cluster, n.name),
								fmt.Sprintf("switch %s to %s", resolvedType, gravitonType),
							),
						})
					}
				}
				if n.desiredSize == 0 {
					ngFindings = append(ngFindings, audit.Finding{
						Service:              "eks_nodegroup",
						ResourceID:           fmt.Sprintf("%s/%s", n.cluster, n.name),
						Tags:                 n.tags,
						Check:                "empty_nodegroup",
						Status:               "WARN",
						Detail:               "desired size is 0, consider removing if unused",
						RiskLevel:            "MEDIUM",
						EstimatedMonthlyCost: nodeCost,
						Remediation: remediation.Recommend(
							"cost",
							"eks",
							"empty_nodegroup",
							fmt.Sprintf("%s/%s", n.cluster, n.name),
							"desired size is 0",
						),
					})
				}
				// Check if nodegroup is oversized (low CPU)
				if n.desiredSize > 0 && ngResp.Nodegroup.Resources != nil {
					for _, asg := range ngResp.Nodegroup.Resources.AutoScalingGroups {
						if asg.Name == nil {
							continue
						}
						asgResp, err := asgClient.DescribeAutoScalingGroups(
							ctx,
							&autoscaling.DescribeAutoScalingGroupsInput{
								AutoScalingGroupNames: []string{*asg.Name},
							},
						)
						if err != nil || len(asgResp.AutoScalingGroups) == 0 {
							continue
						}
						var instanceIDs []string
						for _, inst := range asgResp.AutoScalingGroups[0].Instances {
							if inst.InstanceId != nil {
								instanceIDs = append(instanceIDs, *inst.InstanceId)
							}
							if nodeCost == 0 && inst.InstanceType != nil {
								nodeCost = pricing.EC2Monthly(*inst.InstanceType)
							}
						}
						if len(instanceIDs) == 0 {
							continue
						}

						lookback := t.GetInt("eks", "cpu_lookback_days", 7)
						end := time.Now()
						start := end.AddDate(0, 0, -lookback)
						cpuThreshold := t.GetFloat("eks", "cpu_idle_percent", 10)

						var totalCPU float64
						var datapoints int
						for _, id := range instanceIDs {
							resp, err := cwClient.GetMetricStatistics(
								ctx,
								&cloudwatch.GetMetricStatisticsInput{
									Namespace:  aws.String("AWS/EC2"),
									MetricName: aws.String("CPUUtilization"),
									Dimensions: []cwtypes.Dimension{{
										Name:  aws.String("InstanceId"),
										Value: aws.String(id),
									}},
									StartTime:  &start,
									EndTime:    &end,
									Period:     aws.Int32(86400),
									Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
								},
							)
							if err != nil {
								continue
							}
							for _, dp := range resp.Datapoints {
								totalCPU += aws.ToFloat64(dp.Average)
								datapoints++
							}
						}
						if datapoints > 0 {
							avgCPU := totalCPU / float64(datapoints)
							if avgCPU < cpuThreshold {
								ngFindings = append(ngFindings, audit.Finding{
									Service:    "eks_nodegroup",
									ResourceID: fmt.Sprintf("%s/%s", n.cluster, n.name),
									Tags:       n.tags,
									Check:      "oversized_nodegroup",
									Status:     "WARN",
									Detail: fmt.Sprintf(
										"instances=%d, avg CPU=%.1f%% over %d days, consider smaller instance type",
										len(instanceIDs),
										avgCPU,
										lookback,
									),
									RiskLevel:            "HIGH",
									EstimatedMonthlyCost: nodeCost * float64(n.desiredSize),
									Remediation: remediation.Recommend(
										"cost",
										"eks",
										"oversized_nodegroup",
										fmt.Sprintf("%s/%s", n.cluster, n.name),
										fmt.Sprintf("avg CPU %.1f%%", avgCPU),
									),
								})
							}
						}
					}
				}
				if len(ngFindings) > 0 {
					results = append(results, ngFindings...)
				} else {
					results = append(results, audit.Finding{
						Service:              "eks_nodegroup",
						ResourceID:           fmt.Sprintf("%s/%s", n.cluster, n.name),
						Tags:                 n.tags,
						Check:                "nodegroup_cost",
						Status:               "PASS",
						Detail:               fmt.Sprintf("desired=%d, current-gen instances", n.desiredSize),
						RiskLevel:            "MINIMAL",
						EstimatedMonthlyCost: nodeCost,
					})
				}
			}
			// Check Fargate profiles with no running pods
			fpInput := &eks.ListFargateProfilesInput{ClusterName: &name}
			for {
				fpResp, err := client.ListFargateProfiles(ctx, fpInput)
				if err != nil {
					break
				}
				for _, fpName := range fpResp.FargateProfileNames {
					// Check if any pods are scheduled on this profile via CloudWatch
					podResp, _ := cwClient.GetMetricStatistics(
						ctx,
						&cloudwatch.GetMetricStatisticsInput{
							Namespace:  aws.String("AWS/Usage"),
							MetricName: aws.String("ResourceCount"),
							Dimensions: []cwtypes.Dimension{
								{Name: aws.String("Service"), Value: aws.String("Fargate")},
								{Name: aws.String("Type"), Value: aws.String("Resource")},
								{Name: aws.String("Resource"), Value: aws.String("vCPU")},
								{Name: aws.String("Class"), Value: aws.String("None")},
							},
							StartTime:  aws.Time(time.Now().AddDate(0, 0, -7)),
							EndTime:    aws.Time(time.Now()),
							Period:     aws.Int32(86400),
							Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
						},
					)
					hasUsage := false
					if podResp != nil {
						for _, dp := range podResp.Datapoints {
							if aws.ToFloat64(dp.Average) > 0 {
								hasUsage = true
								break
							}
						}
					}
					if !hasUsage {
						results = append(results, audit.Finding{
							Service:    "eks_fargate",
							ResourceID: fmt.Sprintf("%s/%s", name, fpName),
							Tags:       clusterTags,
							Check:      "unused_fargate_profile",
							Status:     "WARN",
							Detail:     "Fargate profile with no detected pod usage in 7 days",
							RiskLevel:  "LOW",
							Remediation: remediation.Recommend(
								"cost",
								"eks",
								"unused_fargate_profile",
								fmt.Sprintf("%s/%s", name, fpName),
								"no pods scheduled",
							),
						})
					}
				}
				if fpResp.NextToken == nil {
					break
				}
				fpInput.NextToken = fpResp.NextToken
			}
			return results
		},
	), nil
}
