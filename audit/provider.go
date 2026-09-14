package audit

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Scope is a provider-netural unit of work handed to a checker.
//
// The core orchestrator (RunChecks) is agnostic about what a scope represents:
// for AWS it is a single region (Client holds an aws.Config); for a future
// provider such as VMware Aria Automation it is a single endpoint/tenant
// (Client holds that provider's client). Checkers recover the concrete client
// via a provider-specific accessor (e.g. audit.AWSConfig).
type Scope struct {
	// Provider identifies the source, e.g. "aws" or "aria".
	Provider string
	// ID labels the scope within a provider: an AWS region, or an Aria host.
	// It is surfaced on findings for history/diff/report
	ID string
	// Client carries the provider-specific client. Recovered via a typed
	// accessor rather than asserted inline at every call site.
	Client any
}

// CheckFn is the provider-neutral checker signature. Each checker receives a
// single Scope and returns findings for that scope.
type CheckFn func(context.Context, Scope) ([]Finding, error)

// Provider yields the set of scopes to audit for a given run. Each provider
// decides its own fan-out unit (AWS: regions; Aria: endpoints).
type Provider interface {
	Name() string
	Scopes(ctx context.Context) ([]Scope, error)
}

// AWSConfig recovers the aws.Config from an AWS scope. Checkers registered via
// RegisterAWS call this once at the top of the function body.
func AWSConfig(s Scope) aws.Config {
	return s.Client.(aws.Config)
}

// AWSCheckFn is the legacy AWS checker signature; it operates directly on an
// aws.Config. Existing checkers keep this shape; RegisterAWS adapts them to
// the provider-neutral CheckFn.
type AWSCheckFn func(context.Context, aws.Config) ([]Finding, error)

// wrapAWS adapts an AWS-native checker into a provider-neutral CheckFn.
func wrapAWS(fn AWSCheckFn) CheckFn {
	return func(ctx context.Context, s Scope) ([]Finding, error) {
		return fn(ctx, AWSConfig(s))
	}
}
