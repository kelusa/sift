// Package awsreg is the AWS bridge between AWS-native checkers and
// the provider-neutral audit core. It adapts AWS-native check functions
// (which take an aws.Config) into the neutral audit.CheckFn, registers them
// under the "aws" provider, and provides the AWS-specific orchestrator entry point.
package awsreg

import (
	"context"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// CheckFn is the AWS-native checker signature. Checkers keep this shape.
// Register adapts them to the neutral audit.CheckFn.
type CheckFn func(context.Context, aws.Config) ([]audit.Finding, error)

// Config recovers the aws.Config from an AWS scope.
func Config(s audit.Scope) aws.Config {
	return s.Client.(aws.Config)
}

// wrapAWS adapts an AWS-native checker into a provider-neutral CheckFn.
func wrapAWS(fn CheckFn) audit.CheckFn {
	return func(ctx context.Context, s audit.Scope) ([]audit.Finding, error) {
		return fn(ctx, Config(s))
	}
}

// Register registers an AWS-native checker under the "aws" provider and the
// given module. AWS service files call this from their init().
func Register(module, name string, fn CheckFn) {
	audit.Register("aws", module, audit.Checker{Name: name, Fn: wrapAWS(fn)})
}
