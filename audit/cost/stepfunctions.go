package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

func init() {
	audit.RegisterAWS(Module, "stepfunctions", AuditStepFunctionsCost)
}

func AuditStepFunctionsCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := sfn.NewFromConfig(cfg)

	var machines []sfntypes.StateMachineListItem
	input := &sfn.ListStateMachinesInput{}
	for {
		resp, err := client.ListStateMachines(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list state machines: %w", err)
		}
		machines = append(machines, resp.StateMachines...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	cutoff := time.Now().AddDate(0, 0, -30)

	return audit.ProcessAll(
		ctx,
		machines,
		"Auditing Step Functions cost",
		func(ctx context.Context, sm sfntypes.StateMachineListItem) audit.Finding {
			arn := aws.ToString(sm.StateMachineArn)
			name := aws.ToString(sm.Name)

			// Get tags
			var tags map[string]string
			tagResp, tagErr := client.ListTagsForResource(
				ctx,
				&sfn.ListTagsForResourceInput{ResourceArn: &arn},
			)
			if tagErr == nil {
				tags = make(map[string]string, len(tagResp.Tags))
				for _, t := range tagResp.Tags {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
			}

			execResp, err := client.ListExecutions(ctx, &sfn.ListExecutionsInput{
				StateMachineArn: &arn,
				MaxResults:      1,
			})
			if err != nil {
				return audit.ErrorFinding("stepfunctions", name, "list_executions", err)
			}

			if len(execResp.Executions) == 0 || execResp.Executions[0].StartDate.Before(cutoff) {
				detail := fmt.Sprintf("type=%s, no executions in last 30 days", sm.Type)
				return audit.Finding{
					Service:    "stepfunctions",
					ResourceID: name,
					Tags:       tags,
					Check:      "unused_state_machine",
					Status:     "WARN",
					Detail:     detail,
					RiskLevel:  "LOW",
					Remediation: remediation.Recommend(
						"cost",
						"stepfunctions",
						"unused_state_machine",
						name,
						detail,
					),
				}
			}
			return audit.Finding{
				Service:    "stepfunctions",
				ResourceID: name,
				Tags:       tags,
				Check:      "unused_state_machine",
				Status:     "PASS",
				Detail: fmt.Sprintf(
					"type=%s, last_execution=%s",
					sm.Type,
					execResp.Executions[0].StartDate.Format("2006-01-02"),
				),
				RiskLevel: "MINIMAL",
			}
		},
	), nil
}
