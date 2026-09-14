package cost

import (
	"context"
	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const Module = "cost"

var PrevGenPrefixes = []string{
	"m1.",
	"m2.",
	"m3.",
	"m4.",
	"c1.",
	"c3.",
	"c4.",
	"r3.",
	"r4.",
	"i2.",
	"t1.",
	"t2.",
}

func Audit(ctx context.Context, cfg aws.Config, services []string) ([]audit.Finding, error) {
	return audit.RunChecks(ctx, cfg, services, audit.CheckersFor(Module), "Auditing cost waste")
}
