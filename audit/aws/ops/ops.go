package ops

import (
	"context"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const Module = "ops"

func Audit(ctx context.Context, cfg aws.Config, services []string) ([]audit.Finding, error) {
	return audit.RunChecks(ctx, cfg, services, audit.CheckersFor(Module), "Auditing ops risks")
}
