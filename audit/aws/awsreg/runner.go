package awsreg

import (
	"context"
	"strings"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// RunChecks is the AWS-native orchestrator entry point. It wraps the aws.Config
// into a provider-neutral Scope (injecting the AWS "service not available"
// error classifier) and delegates to audit.RunScopedChecks. AWS module Audit
// functions call this.
func RunChecks(
	ctx context.Context,
	cfg aws.Config,
	services []string,
	all []audit.Checker,
	label string,
) ([]audit.Finding, error) {
	scope := audit.Scope{
		Provider:  "aws",
		ID:        cfg.Region,
		Client:    cfg,
		SkipError: isServiceNotAvailable,
	}
	return audit.RunScopedChecks(ctx, scope, services, all, label)
}

// isServiceNotAvailable reports whether an error indicates the AWS service is
// not active/subscribed in the account, in which case the runner records a
// PASS rather than an error.
func isServiceNotAvailable(err error) bool {
	msg := err.Error()
	indicators := []string{
		"ResourceNotFoundException",
		"SubscriptionRequiredException",
		"OptInRequired",
		"InvalidClientTokenId",
		"UnrecognizedClientException",
		"NotSignedUp",
		"is not subscribed",
		"is not authorized to use this service",
		"Namespace default not found",
	}
	for _, ind := range indicators {
		if strings.Contains(msg, ind) {
			return true
		}
	}
	return false
}
