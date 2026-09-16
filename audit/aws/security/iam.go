package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"sift/audit"
	"sift/audit/aws/awsreg"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func init() {
	awsreg.Register(Module, "iam", AuditIAMHygiene)
}

type IAMFinding struct {
	PolicyName string `json:"policy_name"`
	PolicyType string `json:"policy_type"`
	Issue      string `json:"issue"`
	Detail     string `json:"detail"`
}

type RoleFinding struct {
	RoleARN   string       `json:"role_arn"`
	RoleName  string       `json:"role_name"`
	Findings  []IAMFinding `json:"findings"`
	RiskLevel string       `json:"risk_level"`
}

type RoleCache struct {
	mu    sync.Mutex
	cache map[string]*RoleFinding
}

func NewRoleCache() *RoleCache {
	return &RoleCache{cache: make(map[string]*RoleFinding)}
}

func (rc *RoleCache) Get(arn string) (*RoleFinding, bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	f, ok := rc.cache[arn]
	return f, ok
}

func (rc *RoleCache) Set(arn string, f *RoleFinding) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.cache[arn] = f
}

func CachedAnalyzeRole(
	ctx context.Context,
	cfg aws.Config,
	arnStr string,
	cache *RoleCache,
) (*RoleFinding, error) {
	if f, ok := cache.Get(arnStr); ok {
		return f, nil
	}
	f, err := AnalyzeRole(ctx, cfg, arnStr)
	if err != nil {
		return nil, err
	}
	cache.Set(arnStr, f)
	return f, nil
}

type policyDocument struct {
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Resource interface{} `json:"Resource"`
}

func AnalyzeRole(ctx context.Context, cfg aws.Config, arnStr string) (*RoleFinding, error) {
	client := iam.NewFromConfig(cfg)

	parts := strings.Split(arnStr, "/")
	name := parts[len(parts)-1]
	roleName := name

	if strings.Contains(arnStr, ":instance-profile/") {
		ipResp, err := client.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{
			InstanceProfileName: &name,
		})
		if err != nil {
			return nil, fmt.Errorf("get instance profile %s: %w", name, err)
		}
		if len(ipResp.InstanceProfile.Roles) == 0 {
			return &RoleFinding{
				RoleARN:  arnStr,
				RoleName: name,
				Findings: []IAMFinding{{
					Issue:  "no_role",
					Detail: "instance profile has no associated role",
				}},
				RiskLevel: "MEDIUM",
			}, nil
		}
		roleName = *ipResp.InstanceProfile.Roles[0].RoleName
	}

	finding := &RoleFinding{
		RoleARN:  arnStr,
		RoleName: roleName,
	}

	// Check inline policies
	inlineResp, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("list role policies for %s: %w", roleName, err)
	}
	for _, policyName := range inlineResp.PolicyNames {
		polResp, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		})
		if err != nil {
			continue
		}
		findings := checkPolicyDocument(*polResp.PolicyDocument, policyName, "inline")
		finding.Findings = append(finding.Findings, findings...)
	}

	// Check attached managed policies
	attachedResp, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("list atteched policies for %s: %w", roleName, err)
	}
	for _, pol := range attachedResp.AttachedPolicies {
		if pol.PolicyArn == nil {
			continue
		}
		// Check for known dangerous managed policies
		arn := *pol.PolicyArn
		if strings.HasSuffix(arn, "/AdministratorAccess") ||
			strings.HasSuffix(arn, "/PowerUserAccess") {
			finding.Findings = append(
				finding.Findings,
				IAMFinding{
					PolicyName: *pol.PolicyName,
					PolicyType: "managed",
					Issue:      "dangerous_managed_policy",
					Detail:     arn,
				})
			continue
		}

		// Get policy version to inspect document
		verResp, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: pol.PolicyArn,
		})
		if err != nil || verResp.Policy == nil || verResp.Policy.DefaultVersionId == nil {
			continue
		}
		docResp, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: pol.PolicyArn,
			VersionId: verResp.Policy.DefaultVersionId,
		})
		if err != nil || docResp.PolicyVersion == nil || docResp.PolicyVersion.Document == nil {
			continue
		}
		findings := checkPolicyDocument(*docResp.PolicyVersion.Document, *pol.PolicyName, "managed")
		finding.Findings = append(finding.Findings, findings...)
	}

	// Determine risk
	switch {
	case len(finding.Findings) == 0:
		finding.RiskLevel = "MINIMAL"
	case hasHighRisk(finding.Findings):
		finding.RiskLevel = "HIGH"
	default:
		finding.RiskLevel = "MEDIUM"
	}
	return finding, nil
}

func AuditIAMHygiene(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := iam.NewFromConfig(cfg)
	var findings []audit.Finding

	// Unused roles (not used in 90 days)
	rolesPaginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for rolesPaginator.HasMorePages() {
		page, err := rolesPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list roles: %w", err)
		}
		for _, role := range page.Roles {
			name := aws.ToString(role.RoleName)
			if strings.HasPrefix(name, "aws-service-role/") ||
				strings.HasPrefix(name, "AWSServiceRole") {
				continue
			}
			if role.RoleLastUsed == nil || role.RoleLastUsed.LastUsedDate == nil {
				detail := "role has never been used"
				findings = append(findings, audit.Finding{
					Service:    "iam",
					ResourceID: name,
					Check:      "unused_role",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"security",
						"iam",
						"unused_role",
						name,
						detail,
					),
				})
				continue
			}
			daysSince := int(time.Since(*role.RoleLastUsed.LastUsedDate).Hours() / 24)
			if daysSince > 90 {
				detail := fmt.Sprintf("last used %d days ago", daysSince)
				findings = append(findings, audit.Finding{
					Service:    "iam",
					ResourceID: name,
					Check:      "unused_role",
					Status:     "FAIL",
					Detail:     detail,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"security",
						"iam",
						"unused_role",
						name,
						detail,
					),
				})
			}
		}
	}

	// Unused access keys (not used in 90 days)
	var allUsers []iamtypes.User
	usersPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for usersPaginator.HasMorePages() {
		page, err := usersPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list users: %w", err)
		}
		allUsers = append(allUsers, page.Users...)
	}

	keyFindings := audit.ProcessAllMulti(
		ctx,
		allUsers,
		"Auditing IAM access keys",
		func(ctx context.Context, user iamtypes.User) []audit.Finding {
			keysResp, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: user.UserName,
			})
			if err != nil {
				return nil
			}
			var results []audit.Finding
			for _, key := range keysResp.AccessKeyMetadata {
				if string(key.Status) != "Active" {
					continue
				}
				lastUsed, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
					AccessKeyId: key.AccessKeyId,
				})
				if err != nil {
					continue
				}
				keyName := fmt.Sprintf(
					"%s/%s",
					aws.ToString(user.UserName),
					aws.ToString(key.AccessKeyId),
				)
				if lastUsed.AccessKeyLastUsed == nil ||
					lastUsed.AccessKeyLastUsed.LastUsedDate == nil {
					detail := "active access key has never been used"
					results = append(results, audit.Finding{
						Service:    "iam",
						ResourceID: keyName,
						Check:      "unused_access_key",
						Status:     "FAIL",
						Detail:     detail,
						RiskLevel:  "HIGH",
						Remediation: remediation.Recommend(
							"security",
							"iam",
							"unused_access_key",
							keyName,
							detail,
						),
					})
				} else {
					daysSince := int(time.Since(*lastUsed.AccessKeyLastUsed.LastUsedDate).Hours() / 24)
					if daysSince > 90 {
						detail := fmt.Sprintf("last used %d days ago", daysSince)
						results = append(results, audit.Finding{
							Service:     "iam",
							ResourceID:  keyName,
							Check:       "unused_access_key",
							Status:      "FAIL",
							Detail:      detail,
							RiskLevel:   "HIGH",
							Remediation: remediation.Recommend("security", "iam", "unused_access_key", keyName, detail),
						})
					}
				}
			}
			return results
		},
	)
	findings = append(findings, keyFindings...)

	return findings, nil
}

func checkPolicyDocument(rawDoc string, policyName string, policyType string) []IAMFinding {
	decoded, err := url.QueryUnescape(rawDoc)
	if err != nil {
		decoded = rawDoc
	}

	var doc policyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil
	}

	var findings []IAMFinding
	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		actions := toStringSlice(stmt.Action)
		resources := toStringSlice(stmt.Resource)

		for _, a := range actions {
			if a == "*" {
				for _, r := range resources {
					if r == "*" {
						findings = append(findings, IAMFinding{
							PolicyName: policyName,
							PolicyType: policyType,
							Issue:      "wildcard_admin",
							Detail:     "Action=* Resource=*",
						})
					}
				}
			}
			if strings.HasSuffix(a, ":*") {
				findings = append(findings, IAMFinding{
					PolicyName: policyName,
					PolicyType: policyType,
					Issue:      "wildcard_action",
					Detail:     a,
				})
			}
		}
	}
	return findings
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func hasHighRisk(findings []IAMFinding) bool {
	for _, f := range findings {
		if f.Issue == "wildcard_admin" || f.Issue == "dangerous_managed_policy" {
			return true
		}
	}
	return false
}
