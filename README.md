# sift

![sift](assets/sift.png)

AWS security and cost audit CLI tool. Sift scans your AWS resources for misconfigurations, overly permissive policies, unused resources, and network exposure risks. It also includes estimated cost per resource and scan history with delta reporting.

## Install

```bash
make build
```

Requires Go 1.25+ and a configured AWS profile (supports SSO, static credentials, and all standard AWS credential sources).

### Development setup

```bash
pre-commit install
```

## Usage

AWS audit commands live under the `aws` provider group:

```bash
sift aws <command> --profile <aws-profile> [flags]
```

Cross-provider commands stay at the top level:

```bash
sift <report|history|ai|fix> [flags]
```

### Global flags

These root-level flags apply to all commands:

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `table` (terminal) / `json` (pipe) | Output format: `json`, `csv`, or `table` |
| `--risk-level` | | Minimum risk level to show: `MINIMAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--sort-by` | `risk` | Sort results by: `risk` or `cost` |
| `--concurrency` | | Maximum number of concurrent checks |
| `--diff` | `false` | Compare results to previous scan |
| `--no-save` | `false` | Don't save scan results to history |
| `--verbose` | `false` | Show debug-level log output |
| `--progress` | `false` | Show progress bars |
| `--output`, `-o` | stdout | Write results to file instead of stdout |

> `--profile` and `--region` are flags of the `sift aws` command group (they apply to `sift aws <subcommand>`), not root-level global flags. Cross-provider commands (`report`, `history`, `ai`) use `--provider` and `--account` to filter stored findings instead.

### Commands

#### Security

Audit AWS resource security posture across services.

```bash
# All services
sift aws security --profile dev

# Specific services
sift aws security --profile dev --service ec2,s3
sift aws security --profile dev --service eks

# Only high and critical findings
sift aws security --profile dev --risk-level HIGH
```

Available services: `ec2`, `sagemaker`, `s3`, `rds`, `eks`, `iam`, `secrets`, `glue`, `lambda`, `dynamodb`, `elb`, `dms`, `ecr`, `redshift`, `stepfunctions`, `backup`, `cloudtrail`, `guardduty`, `ebs`, `elasticache`, `opensearch`, `kms`, `kinesis`, `waf`, `cloudfront`, `acm`, `route53`, `sqs`, `sns`, `eventbridge`, `efs`, `docdb`, `msk`, `directory`, `cloudwatch`, `timestream`, `awsconfig`

#### Cost

Detect cost waste across AWS resources. Shows estimated monthly cost per resource.

```bash
# All services
sift aws cost --profile dev

# Specific services
sift aws cost --profile dev --service ec2,s3
sift aws cost --profile dev --service ebs,cloudwatch

# Sort by highest cost first
sift aws cost --profile dev --sort-by cost

# Group waste by tag
sift aws cost --profile dev --group-by Project
sift aws cost --profile dev --group-by Team

# Show what changed since last scan
sift aws cost --profile dev --diff
```

Available services: `ec2`, `ebs`, `rds`, `s3`, `eks`, `network`, `cloudwatch`, `ecr`, `secrets`, `glue`, `lambda`, `dynamodb`, `dms`, `elb`, `sagemaker`, `redshift`, `stepfunctions`, `backup`, `kms`, `vpn`, `waf`, `kinesis`, `awsconfig`, `elasticache`, `opensearch`, `efs`, `docdb`, `directory`, `timestream`, `quicksight`, `msk`, `sqs`, `sns`, `eventbridge`, `route53`, `cloudfront`

#### Ops

Audit operational risks and service limits.

```bash
# All services
sift aws ops --profile dev

# Specific services
sift aws ops --profile dev --service glue

# Specific checks within a service
sift aws ops --profile dev --service glue --check table_versions
sift aws ops --profile dev --service glue --check crawlers,job_versions
```

Available services: `glue`

| Flag | Description |
|------|-------------|
| `--service` | Comma-separated services to audit |
| `--check` | Comma-separated checks to run within a service |

Available checks for `glue`: `table_versions`, `crawlers`, `job_versions`

#### List

List AWS resources with metadata for inventory and discovery.

```bash
# List all Glue resources
sift aws list glue --profile dev

# List specific resource types
sift aws list glue jobs --profile dev
sift aws list glue crawlers --profile dev --format csv -o crawlers.csv

# List VPC subnets with IP usage
sift aws list vpc --profile dev
sift aws list vpc subnets --profile dev --format table

# List EC2 instances
sift aws list ec2 --profile dev

# List RDS instances
sift aws list rds --profile dev

# List S3 buckets with size, versioning, access
sift aws list s3 --profile dev

# List EBS volumes
sift aws list ebs --profile dev

# List Lambda functions with invocation data
sift aws list lambda --profile dev

# List EKS clusters with nodegroup details
sift aws list eks --profile dev

# List IAM roles with usage
sift aws list iam --profile dev

# List DynamoDB tables
sift aws list dynamodb --profile dev

# List load balancers
sift aws list elb --profile dev
```

Available services: `glue`, `vpc`, `ec2`, `rds`, `s3`, `ebs`, `lambda`, `eks`, `iam`, `dynamodb`, `elb`

#### Discover

Discover active AWS services in your account and show sift coverage. Uses AWS Config to detect which services have resources.

```bash
sift aws discover --profile dev
```

Output shows resource counts per service, which sift modules cover each service (security, cost, list), and suggests commands to run.

Requires AWS Config to be enabled in the account.

#### Triage

Issue triage with two modes: posture correlation and incident investigation.

##### Posture

Correlate findings across security, cost, and governance modules per resource. Ranks by risk × blast radius × cost impact. Flags quick wins.

```bash
# Single profile
sift aws triage posture --profile dev

# Aggregated across environments
sift aws triage posture --profile dev,qa,prd

# All profiles in history
sift aws triage posture
```

Requires prior scan data (`sift aws security`, `sift aws cost`, `sift aws governance`).

##### Incident

Deep investigation of specific services during an incident.

```bash
# EC2: posture + IAM + flow logs
sift aws triage incident ec2 --profile dev --log-group /vpc/flowlogs

# Single instance
sift aws triage incident ec2 --profile dev --log-group /vpc/flowlogs --instance i-0abc123
```

| Flag | Required | Description |
|------|----------|-------------|
| `--log-group` | Yes (ec2) | CloudWatch log group for VPC flow logs |
| `--instance` | No | Target a specific EC2 instance ID |

#### Governance

Audit governance compliance across AWS resources. Config-driven checks for tagging, naming, and policy enforcement.

```bash
# All governance checks
sift aws governance --profile dev

# Tagging compliance only
sift aws governance --profile dev --check tagging

# Tagging scoped to specific services
sift aws governance --profile dev --check tagging --service ec2,rds,s3
```

| Flag | Description |
|------|-------------|
| `--check` | Comma-separated governance checks (e.g., `tagging`) |
| `--service` | Comma-separated AWS services to scope |

Available checks: `tagging`

##### Tagging configuration

Create `~/.sift/tagging.json` to define your tagging policy:

```json
{
  "baseline_tags": ["ProductCode", "Environment"],
  "iac_tags": ["stack", "stack_env", "security_data_sensitivity", "stack_lifecycle", "project", "stack_version"],
  "cost_tags": ["Project", "UseCase"],
  "ownership_tags": ["TechnicalOwner", "BusinessOwner"],
  "conditional_tags": {
    "Backup_Plan": {
      "when_tag": "Environment",
      "when_values": ["production", "prod", "prd"]
    }
  }
}
```

| Tier | Risk | Description |
|------|------|-------------|
| Baseline | CRITICAL | Mandatory tags without which resources should not exist |
| IaC | HIGH | Tags indicating proper Terraform deployment |
| Cost | MEDIUM | Tags for cost allocation and tracking |
| Ownership | LOW | Tags identifying technical and business owners |
| Conditional | HIGH | Tags required only under certain conditions (e.g., Backup_Plan in production) |

## Estimated cost

Cost findings include an `estimated_monthly_cost` field calculated from a static pricing table (eu-west-1). The table output shows a `$/MO` column and the summary shows total estimated waste.

Pricing can be customized without rebuilding by placing a `prices.json` at `~/.sift/prices.json`. See `audit/pricing/prices.json` for the format.

## Scan history & diff

Scan results are stored in a local SQLite database at `~/.sift/sift.db`. Use `--diff` to compare against the previous scan:

```bash
sift aws cost --profile dev --diff
```

Output:

```bash
Diff vs previous scan:
  New:      2
  Resolved: 1
  Ongoing:  32
```

Disable saving with `--no-save`.

### Querying history

```bash
# Show last 5 scans
sift history --last 5

# Query latest findings by service and risk
sift history --service ec2 --risk CRITICAL

# Filter by module (security or cost)
sift history --module security
sift history --module cost

# Filter by provider and account/identity
sift history --provider aws --account dev

# Track a specific finding over time
sift history --finding <id>

# JSON output
sift history --service s3 --format json
```

| Flag | Description |
|------|-------------|
| `--finding` | Show history for a specific finding ID |
| `--module` | Filter by module (security, cost) |
| `--service` | Filter findings by service |
| `--risk` | Filter findings by risk level |
| `--last` | Show last N scans |
| `--provider` | Filter stored findings by provider (`aws`, `aria`). Default: all |
| `--account` | Filter stored findings by account/identity. Default: all |

## AI analysis

Analyze findings with a local or remote LLM:

```bash
# Start local LLM
docker compose up -d

# Analyze latest findings
sift ai --account dev

# Scope to module/service
sift ai --account dev --module security
sift ai --account dev --service ec2

# Custom question
sift ai --account dev "What's the most urgent fix?"
```

Analysis reads from stored findings, so filter with `--provider aws|aria` and `--account <identity>` to scope which findings are analyzed. Configure the endpoint in `~/.sift/ai.json`. See [docs/ai.md](docs/ai.md) for full setup and options.

## Executive report

Generate a summary for business stakeholders:

```bash
# Single environment
sift report --account dev

# Aggregated across environments
sift report --account icloud-dev,icloud-qa,icloud-prd

# HTML output
sift report --account dev --format html -o report.html

# JSON output
sift report --account dev --format json

# With AI-generated summary and recommendations
sift report --account dev --ai
```

Output includes:
- **Platform health score** (risk-weighted, 0-100)
- **Risk overview** (CRITICAL/HIGH/MEDIUM/LOW counts)
- **Estimated waste** (total $/month)
- **Top security issues** by risk level
- **Top cost issues** by risk and cost impact
- **Compliance scores** (security, cost, tagging — % of resources with no issues per module)
- **Aging findings** (issues open >7 days, sorted by age)
- **Cost attribution by tags** (fully tagged/untagged metrics + breakdown by tag value with $/mo and %)
- **Security attribution by tags** (fully tagged/untagged metrics + breakdown by tag value with CRITICAL/HIGH counts)
- **Service breakdown** (issues per service)

The health score penalizes CRITICAL findings 4x more than LOW, giving a single trackable number for platform posture.

| Flag | Description |
|------|-------------|
| `--provider` | Filter stored findings by provider (`aws`, `aria`). Default: all |
| `--account` | Filter stored findings by account/identity. Default: all |
| `--format` | Output format: `text` (default), `html`, `json` |
| `--ai` | Enrich report with AI-generated summary and recommended actions |
| `-o` | Write output to file |

Tags used for attribution are read from `cost_tags` in `~/.sift/tagging.json`.

## Remediation recommendations

Findings include actionable remediation recommendations with:

- **Action**: What to do
- **Command**: AWS CLI command to execute
- **Evidence**: Data supporting the recommendation
- **Confidence**: HIGH, MEDIUM, or LOW — based on signal strength
- **Action risk**: LOW, MEDIUM, or HIGH — risk of taking the action

Example (JSON output):

```json
{
  "service": "elb",
  "resource_id": "k8s-chronograph-bsdfdu8437",
  "check": "idle_lb",
  "status": "WARN",
  "risk_level": "HIGH",
  "estimated_monthly_cost": 18.40,
  "remediation": {
    "action": "Delete idle load balancer",
    "command": "aws elbv2 delete-load-balancer --load-balancer-arn <arn>",
    "evidence": "zero traffic over 30 days",
    "confidence": "HIGH",
    "action_risk": "HIGH"
  }
}
```

Remediations can be customized without rebuilding by placing a `remediations.json` at `~/.sift/remediations.json`. See `audit/remediation/remediations.json` for the format.

### Executing remediations

Use `sift fix` to show or execute the remediation command for a specific finding:

```bash
# Show the command without executing
sift fix <finding-id> --dry-run

# Show and prompt to execute
sift fix <finding-id>
```

The finding ID is shown in the `ID` column of scan output and `sift history`.

## Risk matrices

### EC2

| Public IP | Open to World | IMDSv1 | Risk |
|-----------|--------------|--------|------|
| ✓ | ✓ | any | CRITICAL |
| ✗ | ✓ | any | HIGH |
| ✓ | ✗ | ✓ | HIGH |
| ✓ | ✗ | ✗ | MEDIUM |
| ✗ | ✗ | ✓ | MEDIUM |
| ✗ | ✗ | ✗ | MINIMAL |

### S3

| Public Access Blocked | Encrypted | Versioning | Logging | Risk |
|-----------------------|-----------|------------|---------|------|
| ✗ | ✗ | any | any | CRITICAL |
| ✗ | ✓ | any | any | HIGH |
| ✓ | ✗ | any | any | MEDIUM |
| ✓ | ✓ | ✗ or no logging | any | LOW |
| ✓ | ✓ | ✓ | ✓ | MINIMAL |

### RDS

| Publicly Accessible | Encrypted | Backup < 7d or No Delete Protection | Multi-AZ / Auto Upgrade | Risk |
|---------------------|-----------|--------------------------------------|------------------------|------|
| ✓ | ✗ | any | any | CRITICAL |
| ✓ | ✓ | any | any | HIGH |
| ✗ | ✗ | any | any | HIGH |
| ✗ | ✓ | ✓ | any | MEDIUM |
| ✗ | ✓ | ✗ | missing | LOW |
| ✗ | ✓ | ✗ | ✓ | MINIMAL |

### EKS

| Public Endpoint | Private Endpoint | Secrets Encrypted | Logging | Risk |
|-----------------|-----------------|-------------------|---------|------|
| ✓ | ✗ | ✗ | any | CRITICAL |
| ✓ | ✗ | ✓ | any | HIGH |
| ✓ | ✓ | any | any | MEDIUM |
| ✗ | ✓ | ✗ or disabled logs | any | LOW |
| ✗ | ✓ | ✓ | all enabled | MINIMAL |

### SageMaker Exposure

| Direct Internet Access | Public Subnet | SG Open to World | Risk |
|------------------------|--------------|-------------------|------|
| Enabled | — | — | HIGH |
| Disabled | ✓ | ✓ | HIGH |
| Disabled | ✓ | ✗ | MEDIUM |
| Disabled | ✗ | ✓ | LOW |
| Disabled | ✗ | ✗ | MINIMAL |

### IAM

#### Policy analysis (per-role)

| Condition | Risk |
|-----------|------|
| `Action=*` + `Resource=*` or AdministratorAccess/PowerUserAccess | HIGH |
| Wildcard service actions (e.g. `s3:*`) | MEDIUM |
| No findings | MINIMAL |

#### Hygiene

| Condition | Risk |
|-----------|------|
| Active access key never used or unused > 90 days | HIGH |
| Role never used or unused > 90 days | MEDIUM |

### DMS

| Publicly Accessible | Encrypted | Risk |
|---------------------|-----------|------|
| ✓ | ✗ | CRITICAL |
| ✓ | ✓ | HIGH |
| ✗ | ✗ | HIGH |
| ✗ | ✓ | MINIMAL |

### ECR

| Scan on Push | Image Tag Mutable | Risk |
|--------------|-------------------|------|
| ✗ | ✓ | HIGH |
| ✗ | ✗ | MEDIUM |
| ✓ | ✓ | LOW |
| ✓ | ✗ | MINIMAL |

### Lambda

| Condition | Risk |
|-----------|------|
| Public function URL with no auth | CRITICAL |
| Public function URL with auth | MEDIUM |
| Deprecated runtime | HIGH |

### Secrets Manager

| Condition | Risk |
|-----------|------|
| No rotation, never rotated | HIGH |
| No rotation enabled | MEDIUM |
| Rotation overdue (>90d) | MEDIUM |
| Rotation enabled and current | MINIMAL |

### DynamoDB

| Encrypted | PITR | Deletion Protection | Risk |
|-----------|------|---------------------|------|
| ✗ | any | any | HIGH |
| ✓ | ✗ | ✗ | MEDIUM |
| ✓ | ✗ | ✓ | LOW |
| ✓ | ✓ | ✗ | LOW |
| ✓ | ✓ | ✓ | MINIMAL |

### ELB

| Internet-facing | DB/Cache Port Exposed | SG Open to World | Risk |
|-----------------|----------------------|-------------------|------|
| ✓ | ✓ | ✓ | CRITICAL |
| ✓ | ✗ | ✓ | HIGH |
| ✓ | ✓ | ✗ | MEDIUM |
| ✓ | ✗ | ✗ | LOW |
| ✗ (internal) | any | any | MINIMAL |

Sensitive ports flagged: MongoDB (27017-27018), MySQL (3306), PostgreSQL (5432), Redis (6379), Elasticsearch (9200-9300), Memcached (11211), MSSQL (1433), Oracle (1521), Redshift (5439).

### Glue

| Condition | Risk |
|-----------|------|
| No catalog or connection encryption | HIGH |
| Partial encryption | MEDIUM |
| Job without security configuration | LOW |
| Fully configured | MINIMAL |

### EBS

| Condition | Risk |
|-----------|------|
| Public snapshot + unencrypted | CRITICAL |
| Public snapshot | HIGH |
| Volume not encrypted | MEDIUM |
| Encrypted, private | MINIMAL |

### ElastiCache

| Condition | Risk |
|-----------|------|
| No at-rest + no in-transit + no AUTH | CRITICAL |
| No at-rest + no in-transit encryption | HIGH |
| Missing at-rest or in-transit encryption | MEDIUM |
| No AUTH token | LOW |
| All encryption and auth enabled | MINIMAL |

### OpenSearch

| Condition | Risk |
|-----------|------|
| Public access + no encryption + no fine-grained access | CRITICAL |
| Public access + no fine-grained access | HIGH |
| Public access with fine-grained access | MEDIUM |
| No encryption at rest or no node-to-node | MEDIUM |
| No fine-grained access control | LOW |
| VPC + all encryption + fine-grained access | MINIMAL |

### KMS

| Condition | Risk |
|-----------|------|
| Wildcard principal + no rotation | CRITICAL |
| Wildcard principal in key policy | HIGH |
| Automatic rotation disabled | MEDIUM |
| Rotation enabled, restricted policy | MINIMAL |

### Kinesis

| Condition | Risk |
|-----------|------|
| Server-side encryption disabled | HIGH |
| Encryption enabled | MINIMAL |

### WAF

| Condition | Risk |
|-----------|------|
| Default ALLOW with no rules | CRITICAL |
| Default ALLOW without rate-based rule | HIGH |
| Default BLOCK or has rate limiting | MINIMAL |

### CloudFront

| Condition | Risk |
|-----------|------|
| Viewer protocol allows HTTP | HIGH |
| Minimum TLS below 1.2 | MEDIUM |
| No WAF web ACL associated | MEDIUM |
| HTTPS enforced, TLS current, WAF attached | MINIMAL |

### ACM

| Condition | Risk |
|-----------|------|
| Certificate expired | CRITICAL |
| Certificate expires within 30 days | HIGH |
| Not eligible for auto-renewal | LOW |
| Valid and auto-renewable | MINIMAL |

### Route53

| Condition | Risk |
|-----------|------|
| Dangling CNAME (subdomain takeover risk) | CRITICAL |
| DNSSEC not enabled | LOW |
| No issues | MINIMAL |

### SQS

| Condition | Risk |
|-----------|------|
| Queue policy allows wildcard principal | CRITICAL |
| Server-side encryption disabled | HIGH |
| Encrypted, no public access | MINIMAL |

### SNS

| Condition | Risk |
|-----------|------|
| Topic policy allows wildcard principal | CRITICAL |
| Server-side encryption disabled | HIGH |
| Encrypted, no public access | MINIMAL |

### EventBridge

| Condition | Risk |
|-----------|------|
| Event bus policy allows wildcard principal | HIGH |
| Rule target without dead-letter queue | MEDIUM |
| No issues | MINIMAL |

### EFS

| Condition | Risk |
|-----------|------|
| Not encrypted at rest | HIGH |
| Encrypted | MINIMAL |

### DocDB

| Condition | Risk |
|-----------|------|
| Publicly accessible + unencrypted | CRITICAL |
| Publicly accessible | HIGH |
| Not encrypted | HIGH |
| No deletion protection | LOW |
| Encrypted, private, deletion protection | MINIMAL |

### MSK

| Condition | Risk |
|-----------|------|
| No encryption at rest + no in-transit + no auth | CRITICAL |
| No in-transit encryption + no auth | HIGH |
| No encryption at rest | MEDIUM |
| No client authentication | LOW |
| All encryption and auth enabled | MINIMAL |

### Directory Service

| Condition | Risk |
|-----------|------|
| No LDAPS + no VPC | HIGH |
| No LDAPS enabled | MEDIUM |
| No VPC isolation | MEDIUM |
| LDAPS enabled + VPC | MINIMAL |

### CloudWatch Logs

| Condition | Risk |
|-----------|------|
| Log group not encrypted with KMS | MEDIUM |
| Encrypted with customer-managed KMS key | MINIMAL |

### Timestream

| Condition | Risk |
|-----------|------|
| Using AWS-managed key (no CMK) | LOW |
| Customer-managed KMS key | MINIMAL |

### Triage

| Condition | Risk |
|-----------|------|
| Public connections + open SG | CRITICAL |
| Public connections detected | HIGH |
| IAM HIGH + open SG | HIGH |
| Open SG or IMDSv1 | MEDIUM |
| None of the above | LOW |

### Baseline (CloudTrail / GuardDuty) — included in Triage

| Condition | Risk |
|-----------|------|
| No CloudTrail trails or logging disabled | CRITICAL |
| GuardDuty not enabled or detector disabled | CRITICAL |
| CloudTrail not multi-region | HIGH |
| CloudTrail no log file validation | MEDIUM |
| All enabled and configured | MINIMAL |

### Ops

#### Glue

| Condition | Risk |
|-----------|------|
| Crawler version ≥ 95% of limit | CRITICAL |
| Crawler version ≥ 80% of limit | HIGH |
| Crawler version ≥ 60% of limit | MEDIUM |

The crawler version limit (default 1,000,000) is fetched automatically from AWS Service Quotas to reflect any account-level increases.

### Cost

#### EC2

| Issue | Risk | Rationale |
|-------|------|-----------|
| Stopped instance | MEDIUM | EBS still incurs cost |
| Previous-gen instance | LOW | Works fine, just costs more per unit |
| Unused Elastic IP | LOW | $3.65/mo each |

#### EBS

| Issue | Risk | Rationale |
|-------|------|-----------|
| Unattached volume | MEDIUM | Pure waste, easy to snapshot+delete |
| Old snapshot (>90d) | LOW | Accumulates slowly |
| GP2 volume | LOW | ~20% savings via GP3 migration |

#### RDS

| Issue | Risk | Rationale |
|-------|------|-----------|
| Stopped instance | MEDIUM | Storage still costs, auto-restarts after 7 days |
| Oversized instance (<10% CPU) | HIGH | Continuous overspend |
| Graviton opportunity | LOW | ~20% savings switching to Graviton |

#### S3

| Issue | Risk | Rationale |
|-------|------|-----------|
| No lifecycle policy | MEDIUM | Unbounded growth |

#### EKS

| Issue | Risk | Rationale |
|-------|------|-----------|
| Cluster with no node groups | HIGH | $73/mo for nothing |
| Oversized nodegroup (low CPU) | HIGH | Continuous overspend on capacity |
| Previous-gen nodes | LOW | Same as EC2 prev-gen |
| Graviton opportunity | LOW | ~20% savings switching to Graviton |
| Empty node group (desired=0) | MEDIUM | Config overhead, minor cost |

#### Network

| Issue | Risk | Rationale |
|-------|------|-----------|
| Idle NAT gateway | HIGH | ~$35/mo, zero traffic |

#### CloudWatch

| Issue | Risk | Rationale |
|-------|------|-----------|
| No retention policy | MEDIUM | $0.03/GB/mo, grows forever |

#### ECR

| Issue | Risk | Rationale |
|-------|------|-----------|
| No lifecycle policy | LOW | $0.10/GB/mo, grows slowly |

#### Secrets Manager

| Issue | Risk | Rationale |
|-------|------|-----------|
| Unused secret (>90d) | LOW | $0.40/mo each |

#### Glue

| Issue | Risk | Rationale |
|-------|------|-----------|
| Active dev endpoint | HIGH | $0.44/DPU/hr, runs 24/7, deprecated |
| Failed job | MEDIUM | Wasting DPU-hours on failures |
| Unused job (>90d) | LOW | No active cost, just clutter |
| Consider Python Shell | LOW | Optimization suggestion |
| Consider Flex execution class | LOW | ~35% savings for non-urgent batch jobs |
| Expensive worker type (G.2X) | MEDIUM | 2x cost if memory isn't needed |
| Overprovisioned job | MEDIUM | Paying for unused DPUs |

#### Lambda

| Issue | Risk | Rationale |
|-------|------|-----------|
| Unused function | LOW | No invocations = no cost |
| Unused provisioned concurrency | HIGH | Paying for reserved capacity with zero usage |

#### DynamoDB

| Issue | Risk | Rationale |
|-------|------|-----------|
| Provisioned mode | LOW | Consider on-demand if traffic is unpredictable |
| Unused GSI (zero items) | MEDIUM | Wasting provisioned capacity |

#### DMS

| Issue | Risk | Rationale |
|-------|------|-----------|
| Idle instance (no tasks) | HIGH | Paying for compute with zero workload |
| All tasks stopped | MEDIUM | Instance cost continues while tasks idle |
| Oversized instance (low CPU) | MEDIUM | Continuous overspend on capacity |
| Previous-gen instance | LOW | Newer gen is cheaper per unit |
| Multi-AZ enabled | LOW | 2x cost if HA isn't needed |

#### SageMaker

| Issue | Risk | Rationale |
|-------|------|-----------|
| Stopped notebook | MEDIUM | EBS storage still incurring cost |

#### ELB

| Issue | Risk | Rationale |
|-------|------|-----------|
| Idle load balancer | HIGH | ~$18/mo base cost, zero traffic |
| No target groups | MEDIUM | LB serving nothing |

#### SQS

| Issue | Risk | Rationale |
|-------|------|-----------|
| Idle queue | MEDIUM | Zero messages in 30 days, potential stuck DLQ |

#### SNS

| Issue | Risk | Rationale |
|-------|------|-----------|
| Idle topic | LOW | Zero publishes in 30 days |

#### EventBridge

| Issue | Risk | Rationale |
|-------|------|-----------|
| Idle bus | LOW | Zero invocations in 30 days (excludes default bus) |

#### Route53

| Issue | Risk | Rationale |
|-------|------|-----------|
| Empty hosted zone | LOW | $0.50/mo, only SOA+NS records |

#### CloudFront

| Issue | Risk | Rationale |
|-------|------|-----------|
| Idle distribution | LOW | Zero requests in 30 days |

## Project structure

```
sift/
├── main.go                     # Entry point
├── Makefile                    # Build script
├── docs/
│   └── adding-a-service.md    # Developer guide for adding new services
├── cmd/                        # CLI commands (cobra)
│   ├── root.go                 # Root command + shared global flags (format, risk-level, etc.)
│   ├── aws.go                  # AWS provider parent command; owns --profile/--region
│   ├── filters.go              # Shared --provider/--account filter flags for cross-provider commands
│   ├── run.go                  # Shared audit runner + history save
│   ├── security.go             # Security audit command
│   ├── cost.go                 # Cost audit command
│   ├── ops.go                  # Ops audit command
│   ├── list.go                 # List command (registry-driven)
│   ├── discover.go             # Service discovery command
│   ├── triage.go               # Triage command (posture + incident subcommands)
│   ├── governance.go           # Governance audit command
│   ├── history.go              # Query scan history
│   ├── report.go               # Executive summary report
│   ├── ai.go                   # AI analysis command
│   └── fix.go                  # Remediation execution
├── config/
│   └── config.go               # AWS credential/profile loading
└── audit/
    ├── finding.go              # Finding struct definition
    ├── provider.go             # Provider-neutral Scope/Provider abstraction + AWS adapter (RegisterAWS)
    ├── registry.go             # Service self-registration (Register/CheckersFor)
    ├── runner.go               # Generic parallel orchestrator (RunChecks)
    ├── process.go              # Concurrent processors (ProcessAll/ProcessAllMulti/FetchAll)
    ├── output.go               # JSON/CSV/table output formatter
    ├── thresholds.go           # Configurable thresholds
    ├── pricing/
    │   ├── pricing.go          # Price lookup (embedded + ~/.sift/prices.json override)
    │   └── prices.json         # Static pricing data (eu-west-1)
    ├── history/
    │   ├── db.go               # SQLite storage (scans, findings, queries)
    │   ├── migrations.go       # Versioned schema migrations
    │   └── diff.go             # Delta computation between scans
    ├── progress/
    │   └── progress.go         # Progress bar utilities
    ├── remediation/
    │   ├── remediation.go      # Remediation recommendation engine
    │   └── remediations.json   # Remediation templates
    ├── ai/
    │   └── ai.go               # LLM integration (Ollama/OpenAI-compatible)
    ├── report/
    │   ├── report.go           # ReportData struct definitions
    │   ├── build.go            # Data computation from history DB
    │   ├── text.go             # Text renderer
    │   ├── html.go             # HTML renderer (embedded template)
    │   ├── json.go             # JSON renderer
    │   ├── ai.go               # AI enrichment (summary + recommendations)
    │   └── template.html       # HTML report template with CSS
    ├── security/
    │   ├── security.go         # Module registration + Audit entry point
    │   ├── sg.go               # Shared SG open-to-world helpers
    │   ├── ec2.go              # EC2 posture analysis
    │   ├── sagemaker.go        # SageMaker notebook + network exposure
    │   ├── s3.go               # S3 bucket audit
    │   ├── rds.go              # RDS instance audit
    │   ├── eks.go              # EKS cluster audit
    │   ├── iam.go              # IAM role policy analysis + caching
    │   ├── secrets.go          # Secrets Manager rotation audit
    │   ├── glue.go             # Glue catalog encryption + job security
    │   ├── lambda.go           # Lambda public URLs + deprecated runtimes
    │   ├── dynamodb.go         # DynamoDB encryption + PITR
    │   ├── elb.go              # ELB exposure + DDoS readiness
    │   ├── dms.go              # DMS public access + encryption
    │   ├── ecr.go              # ECR scan-on-push + tag immutability
    │   ├── redshift.go         # Redshift public access + encryption
    │   ├── stepfunctions.go    # Step Functions logging + tracing
    │   ├── backup.go           # Backup vault encryption
    │   ├── baseline.go         # CloudTrail + GuardDuty (registered as cloudtrail, guardduty)
    │   ├── ebs.go              # EBS volume encryption + public snapshots
    │   ├── elasticache.go      # ElastiCache encryption + AUTH
    │   ├── opensearch.go       # OpenSearch access control + encryption
    │   ├── kms.go              # KMS key rotation + policy
    │   ├── kinesis.go          # Kinesis stream encryption
    │   ├── waf.go              # WAF rule coverage + rate limiting
    │   ├── cloudfront.go       # CloudFront HTTPS + TLS + WAF
    │   ├── acm.go              # ACM certificate expiry + renewal
    │   ├── route53.go          # Route53 dangling records + DNSSEC
    │   ├── sqs.go              # SQS public policies + encryption
    │   ├── sns.go              # SNS public policies + encryption
    │   ├── eventbridge.go      # EventBridge bus policies + DLQ
    │   ├── efs.go              # EFS encryption at rest
    │   ├── docdb.go            # DocDB public access + encryption
    │   ├── msk.go              # MSK encryption + authentication
    │   ├── directory.go        # Directory Service LDAPS + VPC
    │   ├── cloudwatch.go       # CloudWatch log group encryption
    │   ├── timestream.go       # Timestream CMK encryption
    │   └── network.go          # VPC flow log queries
    ├── triage/
    │   ├── ec2.go              # Incident: EC2 deep investigation (IAM + flow logs)
    │   ├── engine.go           # Posture: cross-module correlation + ranking
    │   └── triage_test.go
    ├── list/
    │   ├── registry.go         # Lister registration + column definitions
    │   ├── glue.go             # Glue jobs (run frequency, avg DPU) + crawlers
    │   ├── vpc.go              # VPC subnets with IP usage
    │   ├── ec2.go              # EC2 instances
    │   ├── rds.go              # RDS instances
    │   ├── s3.go               # S3 buckets (size, versioning, access)
    │   ├── ebs.go              # EBS volumes
    │   ├── lambda.go           # Lambda functions (invocations, runtime)
    │   ├── eks.go              # EKS clusters (nodegroups, nodes, instance types)
    │   ├── iam.go              # IAM roles (last used, policies, trust)
    │   ├── dynamodb.go         # DynamoDB tables (mode, items, PITR)
    │   └── elb.go              # Load balancers (type, scheme, targets)
    ├── discover/
    │   └── discover.go         # Service discovery via AWS Config
    ├── ops/
    │   ├── ops.go              # Module const + Audit entry point
    │   └── glue.go             # Crawler version limit checks
    ├── governance/
    │   └── tagging.go          # Tag compliance (baseline, IaC, cost, ownership, conditional)
    └── cost/
        ├── cost.go             # Module registration + Audit entry point
        ├── ec2.go              # Stopped instances, prev-gen, unused EIPs
        ├── ebs.go              # Unattached volumes, old snapshots, GP2→GP3
        ├── rds.go              # Stopped/oversized RDS instances
        ├── s3.go               # Lifecycle policies + multipart uploads
        ├── eks.go              # Empty clusters, prev-gen nodes
        ├── network.go          # Idle NAT gateways
        ├── cloudwatch.go       # Log groups without retention
        ├── ecr.go              # Repos without lifecycle policies
        ├── secrets.go          # Unused secrets
        ├── glue.go             # Dev endpoints, job cost analysis
        ├── lambda.go           # Unused functions, provisioned concurrency
        ├── dynamodb.go         # Provisioned mode, unused GSIs
        ├── dms.go              # Idle/oversized DMS instances
        ├── elb.go              # Idle load balancers
        ├── sagemaker.go        # Stopped notebooks
        ├── redshift.go         # Oversized clusters
        ├── stepfunctions.go    # Unused state machines
        ├── backup.go           # Old recovery points
        ├── kms.go              # Unrotated customer-managed keys
        ├── vpn.go              # Idle VPN connections
        ├── waf.go              # Unused Web ACLs
        ├── kinesis.go          # Idle streams
        ├── awsconfig.go        # Over-broad recording, unused rules
        ├── elasticache.go      # Idle/oversized clusters
        ├── opensearch.go       # Idle/oversized domains
        ├── efs.go              # Unused file systems
        ├── docdb.go            # Idle DocumentDB clusters
        ├── directory.go        # Idle directory services
        ├── timestream.go       # Unused Timestream databases
        ├── quicksight.go       # Unused QuickSight resources
        ├── msk.go              # Idle MSK clusters
        ├── sqs.go              # Idle SQS queues
        ├── sns.go              # Idle SNS topics
        ├── eventbridge.go      # Idle EventBridge buses
        ├── route53.go          # Empty hosted zones
        └── cloudfront.go       # Idle CloudFront distributions
```

## Authentication

Sift uses the standard AWS SDK credential chain. Any method supported by the AWS SDK for Go v2 works:

- **SSO** (recommended): `aws configure sso`, then `aws sso login --profile <name>` before running sift
- **Static credentials**: `~/.aws/credentials`
- **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- **IAM roles**: EC2 instance profiles, ECS task roles

## Configuration

| Path | Description |
|------|-------------|
| `~/.sift/prices.json` | Custom pricing overrides (optional) |
| `~/.sift/sift.db` | Scan history database (auto-created) |
| `~/.sift/sift.log` | Structured JSON log (always written) |

## Logging

Sift writes structured JSON logs to `~/.sift/sift.log` on every run, regardless of flags. These logs include:
- Service check start/completion with duration and findings count
- Cost Explorer fetch results
- AI call telemetry (model, tokens, duration)
- DB save operations

By default, info-level logs are printed to stderr (service progress, durations). Use `--verbose` for debug-level output. Use `--progress` to show progress bars instead of log lines for interactive use.

The log file is designed for consumption by log collectors (Filebeat, Fluentd) for shipping to ELK or similar.

## Environment variables

| Variable | Description |
|----------|-------------|
| `AWS_PROFILE` | Override default profile |
