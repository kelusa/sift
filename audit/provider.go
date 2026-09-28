package audit

import (
	"context"
)

// Scope is a provider-netural unit of work handed to a checker.
//
// The core orchestrator (RunScopedChecks) is agnostic about what a scope represents:
// for AWS it is a single region (Client holds an aws.Config); for a future
// provider such as VMware Aria Automation it is a single endpoint/tenant
// (Client holds that provider's client). Checkers recover the concrete client
// via a provider-specific accessor (e.g. awsreg.Config or aria.ClientFrom).
type Scope struct {
	// Provider identifies the source, e.g. "aws" or "aria".
	Provider string
	// ID labels the scope within a provider: an AWS region, or an Aria host.
	// It is surfaced on findings for history/diff/report.
	ID string
	// Client carries the provider-specific client. Recovered via a typed
	// accessor rather than asserted inline at every call site.
	Client any
	// SkipError, when non-nil, classifies a checker error as "not applicable"
	// (e.g. an AWS service not subscribed in the account). WHen it returns
	// true, the runner records a PASS instead of an error. Providers that have
	// no such notion leave it nil.
	SkipError func(error) bool
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
