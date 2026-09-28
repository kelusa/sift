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
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func init() {
	Register(Lister{
		Service: "lambda",
		Columns: map[string][]Column{
			"function": {
				{Key: "runtime", Header: "RUNTIME"},
				{Key: "memory_mb", Header: "MEMORY(MB)"},
				{Key: "code_mb", Header: "CODE(MB)"},
				{Key: "timeout", Header: "TIMEOUT(s)"},
				{Key: "last_invoked", Header: "LAST INVOKED"},
				{Key: "invocations_30d", Header: "INVOCATIONS(30d)"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, _ string) ([]audit.Resource, error) {
			return ListLambdaFunctions(ctx, cfg)
		},
	})
}

func ListLambdaFunctions(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := lambda.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)

	type fnInfo struct {
		name    string
		runtime string
		memory  int32
		codeMB  float64
		timeout int32
		tags    map[string]string
	}

	var fns []fnInfo
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list functions: %w", err)
		}
		for _, f := range page.Functions {
			fns = append(fns, fnInfo{
				name:    aws.ToString(f.FunctionName),
				runtime: string(f.Runtime),
				memory:  aws.ToInt32(f.MemorySize),
				codeMB:  float64(f.CodeSize) / (1024 * 1024),
				timeout: aws.ToInt32(f.Timeout),
			})
		}
	}

	end := time.Now()
	start := end.AddDate(0, 0, -30)

	resources := audit.FetchAll(ctx, fns, "Listing Lambda functions",
		func(ctx context.Context, f fnInfo) audit.Resource {
			props := map[string]string{
				"runtime":   f.runtime,
				"memory_mb": strconv.Itoa(int(f.memory)),
				"code_mb":   fmt.Sprintf("%.1f", f.codeMB),
				"timeout":   strconv.Itoa(int(f.timeout)),
			}

			resp, err := cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
				Namespace:  aws.String("AWS/Lambda"),
				MetricName: aws.String("Invocations"),
				Dimensions: []cwtypes.Dimension{{
					Name:  aws.String("FunctionName"),
					Value: aws.String(f.name),
				}},
				StartTime:  &start,
				EndTime:    &end,
				Period:     aws.Int32(86400),
				Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
			})
			if err == nil && len(resp.Datapoints) > 0 {
				var total float64
				var latest time.Time
				for _, dp := range resp.Datapoints {
					total += aws.ToFloat64(dp.Sum)
					if dp.Timestamp != nil && dp.Timestamp.After(latest) {
						latest = *dp.Timestamp
					}
				}
				props["invocations_30d"] = strconv.FormatInt(int64(total), 10)
				if !latest.IsZero() {
					props["last_invoked"] = latest.Format("2006-01-02")
				}
			}

			return audit.Resource{
				Service:    "lambda",
				ResourceID: f.name,
				Type:       "function",
				Properties: props,
				Tags:       f.tags,
			}
		},
	)
	return resources, nil
}
