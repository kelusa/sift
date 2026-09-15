# Adding a New Service

This guide explains how to add a new audit service to sift.

## Architecture

```bash
audit/provider.go   — Provider-neutral Scope/Provider abstraction + RegisterAWS adapter
audit/registry.go   — Self-registration of checkers per module (security, cost, ops)
audit/runner.go     — Generic parallel orchestrator (RunChecks)
audit/process.go    — Concurrent item processor (ProcessAll, ProcessAllMulti, FetchAll)
```

Each module (`security`, `cost`, `ops`) has a registry. Services register themselves via `init()`, so adding a new service requires **one file with zero edits elsewhere**.

`audit/provider.go` defines the provider-neutral `Scope`/`Provider` abstraction and the internal `CheckFn(ctx, audit.Scope)` signature the runner consumes. AWS services register with `audit.RegisterAWS(Module, "<name>", <Fn>)`, which adapts an AWS checker (`func(ctx, aws.Config) ([]audit.Finding, error)`) to that internal signature. Non-AWS providers register with the plain `audit.Register` using a `CheckFn(ctx, audit.Scope)` directly.

### Package layout

```bash
audit/
├── runner.go          # RunChecks — generic orchestrator
├── provider.go        # Scope/Provider abstraction + RegisterAWS adapter
├── registry.go        # Register/CheckersFor/ValidServices
├── process.go         # ProcessAll, ProcessAllMulti, FetchAll
├── finding.go         # Finding struct
├── security/          # Security audit checkers
├── cost/              # Cost audit checkers
├── ops/               # Ops audit checkers
└── triage/            # Triage investigation (own package, consumes security helpers)
```

## Adding a Security Check

Create `audit/security/<service>.go`:

```go
package security

import (
    "context"
    "fmt"
    "sift/audit"
    "sift/audit/remediation"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/sqs"
)

func init() {
    audit.RegisterAWS(Module, "sqs", AuditSQS)
}

func AuditSQS(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
    client := sqs.NewFromConfig(cfg)

    // 1. Paginate to collect resources
    var queues []string
    // ... pagination logic ...

    // 2. Process each item — emit one finding per issue found
    return audit.ProcessAllMulti(ctx, queues, "Auditing SQS security",
        func(ctx context.Context, url string) []audit.Finding {
            // Fetch attributes, check conditions
            var results []audit.Finding

            if !encrypted {
                d := "server-side encryption disabled"
                results = append(results, audit.Finding{
                    Service: "sqs", ResourceID: url, Check: "no_encryption",
                    Status: "FAIL", Detail: d, RiskLevel: "HIGH",
                    Remediation: remediation.Recommend("security", "sqs", "no_encryption", url, d),
                })
            }
            if publicPolicy {
                d := "queue policy allows public access"
                results = append(results, audit.Finding{
                    Service: "sqs", ResourceID: url, Check: "public_access",
                    Status: "FAIL", Detail: d, RiskLevel: "CRITICAL",
                    Remediation: remediation.Recommend("security", "sqs", "public_access", url, d),
                })
            }

            if len(results) == 0 {
                results = append(results, audit.Finding{
                    Service: "sqs", ResourceID: url, Check: "sqs_posture",
                    Status: "PASS", Detail: "encrypted=true, private=true", RiskLevel: "MINIMAL",
                })
            }
            return results
        },
    ), nil
}
```

Then add remediation templates to `audit/aws/remediations.json`:

```json
"sqs": {
  "no_encryption": {
    "action": "Enable server-side encryption",
    "command": "aws sqs set-queue-attributes --queue-url {{.ResourceID}} --attributes KmsMasterKeyId=alias/aws/sqs",
    "confidence": "HIGH",
    "action_risk": "LOW"
  },
  "public_access": {
    "action": "Restrict queue policy",
    "command": "aws sqs set-queue-attributes --queue-url {{.ResourceID}} --attributes Policy=<restricted-policy>",
    "confidence": "HIGH",
    "action_risk": "MEDIUM"
  }
}
```

### Template variables

Commands support these variables, resolved at `sift fix` time:

| Variable | Source | Example |
|----------|--------|---------|
| `{{.ResourceID}}` | 4th arg to `Recommend()` | `my-queue`, `arn:aws:...` |
| `{{.Region}}` | Finding's region | `eu-west-1` |
| `{{.AccountID}}` | STS GetCallerIdentity | `123456789012` |
| `{{.ClusterName}}` | Split ResourceID on `/` (EKS) | `my-cluster` |
| `{{.NodegroupName}}` | Split ResourceID on `/` (EKS) | `my-ng` |
| `{{.DatabaseName}}` | Split ResourceID on `/` (Timestream) | `my-db` |
| `{{.TableName}}` | Split ResourceID on `/` (Timestream/DynamoDB) | `my-table` |
| `{{.IndexName}}` | Split ResourceID on `/` (DynamoDB GSI) | `my-gsi` |

For composite ResourceIDs (e.g., `cluster/nodegroup`), pass the full composite to `Recommend()` and use the service-specific variables in templates.

Unresolvable values (user must fill in) use `<placeholder>` syntax and trigger a warning in `sift fix`.

That's it. The service automatically appears in `sift aws security --service sqs`.

## Adding a Cost Check

Same pattern in `audit/cost/<service>.go`:

```go
package cost

import (
    "context"
    "sift/audit"

    "github.com/aws/aws-sdk-go-v2/aws"
)

func init() {
    audit.RegisterAWS(Module, "sqs", AuditSQSCost)
}

func AuditSQSCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
    // ... fetch resources ...

    return audit.ProcessAll(ctx, items, "Auditing SQS cost", func(ctx context.Context, item Item) audit.Finding {
        // cost analysis logic
    }), nil
}
```

## Processing Helpers

| Helper | Returns | Use when |
|--------|---------|----------|
| `audit.ProcessAll[T]` | `[]Finding` | Each item produces exactly **one** finding |
| `audit.ProcessAllMulti[T]` | `[]Finding` | Each item may produce **multiple** findings |
| `audit.FetchAll[T, R]` | `[]R` | You need to fetch domain objects (not findings) in parallel |

All three handle concurrency (semaphore), progress bars, and respect `--concurrency` and `--quiet` flags automatically.

### Domain objects vs Findings

**Findings** (`audit.Finding`) are the output format shown to users — fixed structure with service, resource ID, risk level, status, detail, remediation.

**Domain objects** are intermediate structs with raw AWS data, fetched before you can assess risk.

Use `FetchAll` → domain objects when you have a multi-phase pipeline:

```bash
1. Fetch      — describe N resources in parallel → domain objects (FetchAll)
2. Enrich     — batch-fetch shared data (SGs, route tables) using info from step 1
3. Assess     — compute risk per item using enriched context → findings (ProcessAll)
```

If everything can be done in one pass (no shared lookups), skip domain objects and use `ProcessAll` directly.

### FetchAll example

Use `FetchAll` when you need to describe resources in parallel before processing them (e.g., batch-fetching data that feeds into a later assessment phase):

```go
notebooks := audit.FetchAll(ctx, names, "Describing notebooks", func(ctx context.Context, name string) Notebook {
    desc, err := client.Describe(ctx, &DescribeInput{Name: &name})
    if err != nil {
        return Notebook{} // filter out later
    }
    return Notebook{Name: name, Status: desc.Status}
})
```

## Adding an Ops Check

Register in `audit/ops/`:

```go
func init() {
    audit.RegisterAWS(ops.Module, "myservice", AuditMyServiceOps)
}
```

The `--check` flag for sub-check filtering is passed via context (`audit.GetChecks(ctx)`).

## When Helpers Don't Fit

Some services have multi-phase logic that doesn't map to "process each item independently":

- **Pre-computed lookup maps** (e.g., DMS task counts per instance) — compute the map first, then pass it into `ProcessAllMulti` via closure capture.
- **Simple fan-out** (e.g., baseline runs CloudTrail + GuardDuty in parallel) — use a plain `sync.WaitGroup` with 2 goroutines.
- **Nested parallelism** (e.g., EKS clusters → nodegroups) — use `ProcessAllMulti` at the outer level and sequential loops inside.

## Instance Type Resolution

Some AWS resources don't expose instance types directly (e.g., EKS nodegroups using launch templates). When you need the instance type for cost calculations or prev-gen checks, follow this resolution chain:

1. **Direct field** — use the resource's own `InstanceTypes` / `InstanceClass` field
2. **Launch template** — describe the launch template version and read `LaunchTemplateData.InstanceType`
3. **Running instances** — describe the ASG and read `InstanceType` from a running instance

Only fall through to the next step if the previous one returns empty. See `audit/cost/eks.go` for the reference implementation.

## Adding a List Command

The `list` module is **architecturally different** from security/cost/ops:

| | Security / Cost / Ops | List |
|--|----------------------|------|
| Registration | Self-registers via `init()` | Manually wired in `cmd/list.go` |
| Return type | `[]audit.Finding` | `[]audit.Resource` |
| Orchestration | `audit.RunChecks` + registry | Direct function calls |
| Output | Findings table (risk, status) | Resource table (properties) |

List is **inventory**, not audit. It doesn't emit pass/fail findings or risk levels — it shows resources with metadata.

### Adding a new list subcommand

1. Create `audit/list/<service>.go`:

```go
package list

import (
    "context"
    "sift/audit"
    "github.com/aws/aws-sdk-go-v2/aws"
)

func ListMyResources(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
    // Paginate AWS API, build []audit.Resource
    // Each resource has Service, ResourceID, Type, Properties map, Tags
    return resources, nil
}
```

2. Wire it in `cmd/list.go`:

```go
var listMyServiceCmd = &cobra.Command{
    Use:   "myservice [resource]",
    Short: "List MyService resources",
    // ... call list.ListMyResources() ...
}

func init() {
    listCmd.AddCommand(listMyServiceCmd)
}
```

No self-registration, no remediation, no ProcessAll helpers needed.

## Checklist

1. Create one file in the appropriate `audit/<module>/` directory
2. Add `func init()` with `audit.RegisterAWS()`
3. Implement the `func(context.Context, aws.Config) ([]audit.Finding, error)` signature
4. Use `ProcessAll`, `ProcessAllMulti`, or `FetchAll` for the processing loop
5. Add remediation via `remediation.Recommend()` for non-MINIMAL findings
6. Add remediation template to `audit/aws/remediations.json`
7. Use descriptive check names per issue (e.g., `no_encryption`, `public_access`) — not generic `<service>_security`
8. Use `len(results) == 0` to emit a PASS finding, not a separate boolean
9. Build and test: `go build ./... && go test ./...`

No changes needed in `cmd/`, no service maps to update, no orchestrator edits.

## Testing

Tests verify the finding logic directly — no AWS mocks or interfaces needed for most checkers.

### Approach

Since checkers use `ProcessAllMulti` with inline logic, tests replicate the decision logic and verify correct check names and risk levels:

```go
func TestDynamoDBCheckNames(t *testing.T) {
    tests := []struct {
        name       string
        encrypted  bool
        pitr       bool
        delProtect bool
        wantChecks []string
        wantRisks  []string
    }{
        {"fully configured", true, true, true, []string{"dynamodb_posture"}, []string{"MINIMAL"}},
        {"no encryption", false, true, true, []string{"no_encryption"}, []string{"HIGH"}},
        {"all issues", false, false, false, []string{"no_encryption", "no_pitr", "no_delete_protection"}, []string{"HIGH", "MEDIUM", "MEDIUM"}},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            var checks, risks []string
            if !tt.encrypted { checks = append(checks, "no_encryption"); risks = append(risks, "HIGH") }
            if !tt.pitr { checks = append(checks, "no_pitr"); risks = append(risks, "MEDIUM") }
            if !tt.delProtect { checks = append(checks, "no_delete_protection"); risks = append(risks, "MEDIUM") }
            if len(checks) == 0 { checks = append(checks, "dynamodb_posture"); risks = append(risks, "MINIMAL") }
            // assert checks and risks match expected
        })
    }
}
```

### When to use interfaces

For complex checkers with helper functions that make secondary AWS calls (e.g., `ec2.go` with its `listEC2Instances` → `parseInstance` pipeline), you may define an interface to enable mock-based testing. This is optional and only recommended when the logic is complex enough to warrant it.

Place test files next to the code: `ecr_test.go` alongside `ecr.go`.
