package security

import (
	"context"
	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const Module = "security"

type TriageTarget struct {
	ResourceID  string
	Service     string
	PrivateIP   *string
	RoleARN     *string
	OpenToWorld bool
	IMDSv1      bool
}

func statusFromRisk(risk string) string {
	if risk == "MINIMAL" {
		return "PASS"
	}
	return "FAIL"
}

func Audit(ctx context.Context, cfg aws.Config, services []string) ([]audit.Finding, error) {
	return audit.RunChecks(ctx, cfg, services, audit.CheckersFor(Module), "Running security audit")
}
