package ops

import (
	"context"

	"sift/audit"
	"sift/audit/aws/awsreg"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const Module = "ops"

func Audit(ctx context.Context, cfg aws.Config, services []string) ([]audit.Finding, error) {
	return awsreg.RunChecks(ctx, cfg, services, audit.CheckersFor("aws", Module), "Auditing ops risks")
}
