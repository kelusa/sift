package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

func init() {
	audit.RegisterAWS(Module, "stepfunctions", AuditStepFunctions)
}

func AuditStepFunctions(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
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

	return audit.ProcessAllMulti(
		ctx,
		machines,
		"Auditing Step Functions security",
		func(ctx context.Context, sm sfntypes.StateMachineListItem) []audit.Finding {
			arn := aws.ToString(sm.StateMachineArn)
			name := aws.ToString(sm.Name)

			desc, err := client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
				StateMachineArn: &arn,
			})
			if err != nil {
				return []audit.Finding{audit.ErrorFinding("stepfunctions", name, "describe", err)}
			}

			loggingEnabled := desc.LoggingConfiguration != nil &&
				desc.LoggingConfiguration.Level != sfntypes.LogLevelOff
			tracingEnabled := desc.TracingConfiguration != nil &&
				desc.TracingConfiguration.Enabled

			var results []audit.Finding
			if !loggingEnabled {
				detail := fmt.Sprintf("logging_disabled, type=%s", sm.Type)
				results = append(results, audit.Finding{
					Service: "stepfunctions", ResourceID: name, Check: "no_logging",
					Status: "FAIL", Detail: detail, RiskLevel: "MEDIUM",
					Remediation: remediation.Recommend(
						"security",
						"stepfunctions",
						"no_logging",
						name,
						detail,
					),
				})
			}
			if !tracingEnabled {
				detail := fmt.Sprintf("X-Ray tracing disabled, type=%s", sm.Type)
				results = append(results, audit.Finding{
					Service: "stepfunctions", ResourceID: name, Check: "no_tracing",
					Status: "FAIL", Detail: detail, RiskLevel: "LOW",
					Remediation: remediation.Recommend(
						"security",
						"stepfunctions",
						"no_tracing",
						name,
						detail,
					),
				})
			}
			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service: "stepfunctions", ResourceID: name, Check: "stepfunctions_posture",
					Status: "PASS", Detail: fmt.Sprintf("logging=true, tracing=true, type=%s", sm.Type), RiskLevel: "MINIMAL",
				})
			}
			return results
		},
	), nil
}
