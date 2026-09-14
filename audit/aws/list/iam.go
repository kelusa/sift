package list

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func init() {
	Register(Lister{
		Service:  "iam",
		SubTypes: []string{"roles"},
		Columns: map[string][]Column{
			"role": {
				{Key: "last_used", Header: "LAST USED"},
				{Key: "policies", Header: "POLICIES"},
				{Key: "trust", Header: "TRUST"},
				{Key: "created", Header: "CREATED"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, subType string) ([]audit.Resource, error) {
			return ListIAMRoles(ctx, cfg)
		},
	})
}

func ListIAMRoles(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := iam.NewFromConfig(cfg)

	var resources []audit.Resource
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list roles: %w", err)
		}
		for _, role := range page.Roles {
			lastUsed := "-"
			if role.RoleLastUsed != nil && role.RoleLastUsed.LastUsedDate != nil {
				days := int(time.Since(*role.RoleLastUsed.LastUsedDate).Hours() / 24)
				lastUsed = fmt.Sprintf("%dd ago", days)
			}

			// Count attached policies
			polResp, _ := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: role.RoleName,
			})
			polCount := 0
			if polResp != nil {
				polCount = len(polResp.AttachedPolicies)
			}

			// Extract trust principal
			trust := ""
			if role.AssumeRolePolicyDocument != nil {
				trust = extractTrustService(aws.ToString(role.AssumeRolePolicyDocument))
			}

			props := map[string]string{
				"last_used": lastUsed,
				"policies":  strconv.Itoa(polCount),
				"trust":     trust,
			}
			if role.CreateDate != nil {
				props["created"] = role.CreateDate.Format("2006-01-02")
			}

			resources = append(resources, audit.Resource{
				Service:    "iam",
				ResourceID: aws.ToString(role.RoleName),
				Type:       "role",
				Properties: props,
			})
		}
	}
	return resources, nil
}

func extractTrustService(doc string) string {
	// Simple extraction of first Service principal from URL-decoded policy
	// Looks for "Service":"..." or "Service":["..."]
	i := 0
	for i < len(doc) {
		idx := indexOf(doc[i:], "Service")
		if idx == -1 {
			break
		}
		i += idx + 7
		// Find the value after colon and quotes
		for i < len(doc) && (doc[i] == '"' || doc[i] == ':' || doc[i] == ' ' || doc[i] == '[') {
			i++
		}
		end := i
		for end < len(doc) && doc[end] != '"' && doc[end] != ']' {
			end++
		}
		if end > i {
			return doc[i:end]
		}
	}
	return ""
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
