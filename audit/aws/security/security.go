package security

import (
	"context"
	"sift/audit"
	"sift/audit/aws/awsreg"

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
	return awsreg.RunChecks(ctx, cfg, services, audit.CheckersFor("aws", Module), "Running security audit")
}
