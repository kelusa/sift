package access

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// EventSources maps sift service names to CloudTrail event sources.
var EventSources = map[string]string{
	"timestream":    "timestream.amazonaws.com",
	"s3":            "s3.amazonaws.com",
	"rds":           "rds.amazonaws.com",
	"ec2":           "ec2.amazonaws.com",
	"eks":           "eks.amazonaws.com",
	"lambda":        "lambda.amazonaws.com",
	"dynamodb":      "dynamodb.amazonaws.com",
	"sqs":           "sqs.amazonaws.com",
	"sns":           "sns.amazonaws.com",
	"secrets":       "secretsmanager.amazonaws.com",
	"kms":           "kms.amazonaws.com",
	"iam":           "iam.amazonaws.com",
	"glue":          "glue.amazonaws.com",
	"redshift":      "redshift.amazonaws.com",
	"elasticache":   "elasticache.amazonaws.com",
	"opensearch":    "es.amazonaws.com",
	"cloudfront":    "cloudfront.amazonaws.com",
	"efs":           "elasticfilesystem.amazonaws.com",
	"docdb":         "rds.amazonaws.com",
	"msk":           "kafka.amazonaws.com",
	"kinesis":       "kinesis.amazonaws.com",
	"stepfunctions": "states.amazonaws.com",
	"bedrock":       "bedrock.amazonaws.com",
}

// Principal represents an aggregated view of access by one IAM principal.
type Principal struct {
	ARN        string
	Operations map[string]int
	Count      int
	LastAccess time.Time
}

// Result holds the full access audit output.
type Result struct {
	Service    string
	Days       int
	Principals []Principal
}

// Audit queries CloudTrail for access events for a given service.
func Audit(ctx context.Context, cfg aws.Config, service string, days int) (*Result, error) {
	eventSource, ok := EventSources[service]
	if !ok {
		return nil, fmt.Errorf("unsupported service %q for access audit\nAvailable: %s",
			service, strings.Join(Services(), ", "))
	}

	client := cloudtrail.NewFromConfig(cfg)
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -days)

	principals := map[string]*Principal{}

	input := &cloudtrail.LookupEventsInput{
		StartTime: &startTime,
		EndTime:   &endTime,
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyEventSource,
				AttributeValue: &eventSource,
			},
		},
		MaxResults: aws.Int32(50),
	}

	for {
		resp, err := client.LookupEvents(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("lookup events: %w", err)
		}

		for _, event := range resp.Events {
			arn := aws.ToString(event.Username)
			if arn == "" {
				arn = extractPrincipal(event)
			}
			if arn == "" {
				arn = "(unknown)"
			}

			op := aws.ToString(event.EventName)
			ts := aws.ToTime(event.EventTime)

			p, ok := principals[arn]
			if !ok {
				p = &Principal{
					ARN:        arn,
					Operations: map[string]int{},
				}
				principals[arn] = p
			}
			p.Operations[op]++
			p.Count++
			if ts.After(p.LastAccess) {
				p.LastAccess = ts
			}
		}

		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	result := &Result{
		Service: service,
		Days:    days,
	}
	for _, p := range principals {
		result.Principals = append(result.Principals, *p)
	}
	sort.Slice(result.Principals, func(i, j int) bool {
		return result.Principals[i].Count > result.Principals[j].Count
	})

	return result, nil
}

func extractPrincipal(event types.Event) string {
	for _, r := range event.Resources {
		if aws.ToString(r.ResourceType) == "AWS::IAM::Role" ||
			aws.ToString(r.ResourceType) == "AWS::IAM::User" {
			return aws.ToString(r.ResourceName)
		}
	}
	return ""
}

// Services returns all supported service names for access audit.
func Services() []string {
	var s []string
	for k := range EventSources {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}
