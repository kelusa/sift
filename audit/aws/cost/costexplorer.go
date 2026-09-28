package cost

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

// FetchSpendByTag calls Cost Explorer for the last 30 days grouped by tagKey
// Returns map of tag_value -> monthly spend
func FetchSpendByTag(
	ctx context.Context,
	cfg aws.Config,
	tagKey string,
) (map[string]float64, string, error) {
	client := costexplorer.NewFromConfig(cfg)

	end := time.Now()
	start := end.AddDate(0, -1, 0)
	period := start.Format("2006-01-02") + " to " + end.Format("2006-01-02")

	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod: &types.DateInterval{
			Start: aws.String(start.Format("2006-01-02")),
			End:   aws.String(end.Format("2006-01-02")),
		},
		Granularity: types.GranularityMonthly,
		Metrics:     []string{"UnblendedCost"},
		GroupBy: []types.GroupDefinition{
			{
				Type: types.GroupDefinitionTypeTag,
				Key:  aws.String(tagKey),
			},
		},
	}

	resp, err := client.GetCostAndUsage(ctx, input)
	if err != nil {
		return nil, period, err
	}

	result := map[string]float64{}
	for _, group := range resp.ResultsByTime {
		for _, g := range group.Groups {
			val := "(untagged)"
			if len(g.Keys) > 0 && g.Keys[0] != "" {
				// Keys come as "TagKey$TagValue"
				key := g.Keys[0]
				for i, c := range key {
					if c == '$' {
						val = key[i+1:]
						break
					}
				}
				if val == "" {
					val = "(untagged)"
				}
			}
			if m, ok := g.Metrics["UnblendedCost"]; ok && m.Amount != nil {
				var amount float64
				fmt.Sscanf(*m.Amount, "%f", &amount)
				result[val] += amount
			}
		}
	}
	return result, period, nil
}

// FetchSpendByService calls Cost Explorer for the last 30 days grouped by AWS service.
// Returns map of service_name -> monthly spend
func FetchSpendByService(ctx context.Context, cfg aws.Config) (map[string]float64, string, error) {
	client := costexplorer.NewFromConfig(cfg)

	end := time.Now()
	start := end.AddDate(0, -1, 0)
	period := start.Format("2006-01-02") + " to " + end.Format("2006-01-02")

	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod: &types.DateInterval{
			Start: aws.String(start.Format("2006-01-02")),
			End:   aws.String(end.Format("2006-01-02")),
		},
		Granularity: types.GranularityMonthly,
		Metrics:     []string{"UnblendedCost"},
		GroupBy: []types.GroupDefinition{
			{
				Type: types.GroupDefinitionTypeDimension,
				Key:  aws.String("SERVICE"),
			},
		},
	}

	resp, err := client.GetCostAndUsage(ctx, input)
	if err != nil {
		return nil, period, err
	}

	result := map[string]float64{}
	for _, group := range resp.ResultsByTime {
		for _, g := range group.Groups {
			if len(g.Keys) == 0 {
				continue
			}
			val := g.Keys[0]
			if m, ok := g.Metrics["UnblendedCost"]; ok && m.Amount != nil {
				var amount float64
				fmt.Sscanf(*m.Amount, "%f", &amount)
				result[val] += amount
			}
		}
	}
	return result, period, nil
}
