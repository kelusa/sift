package security

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type FlowEvent struct {
	Timestamp string `json:"timestamp"`
	SrcAddr   string `json:"src_addr"`
	DstAddr   string `json:"dst_addr"`
	DstPort   string `json:"dst_port"`
	Bytes     string `json:"bytes"`
}

func FindPublicConnections(
	ctx context.Context,
	client *cloudwatchlogs.Client,
	logGroup string,
	srcIP string,
) ([]FlowEvent, error) {
	query := fmt.Sprintf(`
	fields @timestamp, srcAddr, dstAddr, dstPort, bytes | filter srcAddr = "%s" and action = "ACCEPT" | sort @timestamp desc | limit 200`, srcIP)

	startTime := time.Now().Add(-24 * time.Hour).Unix()
	endTime := time.Now().Unix()

	startOut, err := client.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupName: &logGroup,
		StartTime:    &startTime,
		EndTime:      &endTime,
		QueryString:  &query,
	})
	if err != nil {
		return nil, fmt.Errorf("start query: %w", err)
	}

	events, err := pollQuery(ctx, client, *startOut.QueryId)
	if err != nil {
		return nil, err
	}

	// Filter to public IPs only
	var public []FlowEvent
	for _, e := range events {
		if !isPrivateIP(e.DstAddr) {
			public = append(public, e)
		}
	}
	return public, nil
}

func pollQuery(
	ctx context.Context,
	client *cloudwatchlogs.Client,
	queryID string,
) ([]FlowEvent, error) {
	timeout := time.After(2 * time.Minute)
	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("query timed out after 2 minutes")
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}

		res, err := client.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{
			QueryId: &queryID,
		})
		if err != nil {
			return nil, fmt.Errorf("get query results: %w", err)
		}
		if res.Status == cwtypes.QueryStatusComplete {
			return parseFlowEvents(res.Results), nil
		}
		if res.Status == cwtypes.QueryStatusFailed || res.Status == cwtypes.QueryStatusCancelled {
			return nil, fmt.Errorf("query %s: %s", queryID, res.Status)
		}
	}
}

func parseFlowEvents(rows [][]cwtypes.ResultField) []FlowEvent {
	var events []FlowEvent
	for _, row := range rows {
		event := FlowEvent{}
		for _, field := range row {
			if field.Field == nil || field.Value == nil {
				continue
			}
			switch *field.Field {
			case "@timestamp":
				event.Timestamp = *field.Value
			case "srcAddr":
				event.SrcAddr = *field.Value
			case "dstAddr":
				event.DstAddr = *field.Value
			case "dstPort":
				event.DstPort = *field.Value
			case "bytes":
				event.Bytes = *field.Value
			}
		}
		events = append(events, event)
	}
	return events
}

var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"} {
		_, network, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, network)
	}
}

func isPrivateIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
