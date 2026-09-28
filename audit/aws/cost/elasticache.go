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
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
)

var elasticachePrevGen = []string{"cache.r4.", "cache.m4.", "cache.t2.", "cache.r3.", "cache.m3."}

func init() {
	awsreg.Register(Module, "elasticache", AuditElastiCacheCost)
}

func AuditElastiCacheCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := elasticache.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)

	var clusters []struct {
		id       string
		arn      string
		nodeType string
		engine   string
		nodes    int32
		tags     map[string]string
	}

	input := &elasticache.DescribeCacheClustersInput{}
	for {
		resp, err := client.DescribeCacheClusters(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe cache clusters: %w", err)
		}
		for _, c := range resp.CacheClusters {
			tags := make(map[string]string)
			if c.ARN != nil {
				tagResp, err := client.ListTagsForResource(
					ctx,
					&elasticache.ListTagsForResourceInput{
						ResourceName: c.ARN,
					},
				)
				if err == nil {
					for _, t := range tagResp.TagList {
						tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
					}
				}
			}
			clusters = append(clusters, struct {
				id       string
				arn      string
				nodeType string
				engine   string
				nodes    int32
				tags     map[string]string
			}{
				id:       aws.ToString(c.CacheClusterId),
				arn:      aws.ToString(c.ARN),
				nodeType: aws.ToString(c.CacheNodeType),
				engine:   aws.ToString(c.Engine),
				nodes:    aws.ToInt32(c.NumCacheNodes),
				tags:     tags,
			})
		}
		if resp.Marker == nil {
			break
		}
		input.Marker = resp.Marker
	}

	lookback := t.GetInt("elasticache", "cpu_lookback_days", 7)
	cpuThreshold := t.GetFloat("elasticache", "cpu_idle_percent", 10)
	end := time.Now()
	start := end.AddDate(0, 0, -lookback)

	return audit.ProcessAllMulti(
		ctx,
		clusters,
		"Auditing ElastiCache cost",
		func(ctx context.Context, c struct {
			id       string
			arn      string
			nodeType string
			engine   string
			nodes    int32
			tags     map[string]string
		}) []audit.Finding {
			var results []audit.Finding

			// Check connections
			connResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/ElastiCache"),
				MetricName: aws.String("CurrConnections"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("CacheClusterId"),
					Value: &c.id,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})

			var avgConns float64
			if connResp != nil && len(connResp.Datapoints) > 0 {
				var total float64
				for _, dp := range connResp.Datapoints {
					total += aws.ToFloat64(dp.Average)
				}
				avgConns = total / float64(len(connResp.Datapoints))
			}

			// Check CPU
			cpuResp, _ := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/ElastiCache"),
				MetricName: aws.String("CPUUtilization"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("CacheClusterId"),
					Value: &c.id,
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
			})

			var avgCPU float64
			hasMetrics := false
			if cpuResp != nil && len(cpuResp.Datapoints) > 0 {
				hasMetrics = true
				var total float64
				for _, dp := range cpuResp.Datapoints {
					total += aws.ToFloat64(dp.Average)
				}
				avgCPU = total / float64(len(cpuResp.Datapoints))
			}

			if avgConns <= 1 && hasMetrics && avgCPU < cpuThreshold {
				monthlyCost := pricing.ElastiCacheMonthly(c.nodeType, c.nodes)
				detail := fmt.Sprintf(
					"engine=%s, type=%s, nodes=%d, avg_conns=%.0f, avg_cpu=%.1f%% over %d days",
					c.engine,
					c.nodeType,
					c.nodes,
					avgConns,
					avgCPU,
					lookback,
				)
				results = append(results, audit.Finding{
					Service:              "elasticache",
					ResourceID:           c.id,
					Tags:                 c.tags,
					Check:                "idle_cluster",
					Status:               "WARN",
					Detail:               detail,
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"elasticache",
						"idle_cluster",
						c.id,
						"zero connections and low CPU",
					),
				})
			} else if hasMetrics && avgCPU < cpuThreshold {
				monthlyCost := pricing.ElastiCacheMonthly(c.nodeType, c.nodes)
				detail := fmt.Sprintf("engine=%s, type=%s, nodes=%d, avg_cpu=%.1f%% over %d days, consider downsizing", c.engine, c.nodeType, c.nodes, avgCPU, lookback)
				results = append(results, audit.Finding{
					Service:              "elasticache",
					ResourceID:           c.id,
					Tags:                 c.tags,
					Check:                "oversized_cluster",
					Status:               "WARN",
					Detail:               detail,
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: monthlyCost,
					Remediation:          remediation.Recommend("cost", "elasticache", "oversized_cluster", c.id, fmt.Sprintf("avg CPU %.1f%%", avgCPU)),
				})
			}

			// Previous gen check
			for _, prefix := range elasticachePrevGen {
				if strings.HasPrefix(c.nodeType, prefix) {
					results = append(results, audit.Finding{
						Service:    "elasticache",
						ResourceID: c.id,
						Tags:       c.tags,
						Check:      "previous_gen_node",
						Status:     "WARN",
						Detail: fmt.Sprintf(
							"type=%s, consider upgrading to current gen",
							c.nodeType,
						),
						RiskLevel: "LOW",
						Remediation: remediation.Recommend(
							"cost",
							"elasticache",
							"previous_gen_node",
							c.id,
							"previous-gen node type",
						),
					})
					break
				}
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    "elasticache",
					ResourceID: c.id,
					Tags:       c.tags,
					Check:      "elasticache_cost",
					Status:     "PASS",
					Detail: fmt.Sprintf(
						"engine=%s, type=%s, nodes=%d, active",
						c.engine,
						c.nodeType,
						c.nodes,
					),
					RiskLevel: "MINIMAL",
				})
			}

			return results
		},
	), nil
}
