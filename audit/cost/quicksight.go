package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func init() {
	audit.RegisterAWS(Module, "quicksight", AuditQuickSightCost)
}

func AuditQuickSightCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("get caller identity: %w", err)
	}
	accountID := aws.ToString(identity.Account)

	client := quicksight.NewFromConfig(cfg)
	t := audit.GetThresholds(ctx)
	unusedDays := t.GetInt("quicksight", "unused_days", 30)
	cutoff := time.Now().AddDate(0, 0, -unusedDays)

	var users []struct {
		name   string
		email  string
		role   string
		active bool
	}

	input := &quicksight.ListUsersInput{
		AwsAccountId: &accountID,
		Namespace:    aws.String("default"),
	}
	for {
		resp, err := client.ListUsers(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list quicksight users: %w", err)
		}
		for _, u := range resp.UserList {
			active := u.Active
			users = append(users, struct {
				name   string
				email  string
				role   string
				active bool
			}{
				name:   aws.ToString(u.UserName),
				email:  aws.ToString(u.Email),
				role:   string(u.Role),
				active: active,
			})
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	return audit.ProcessAll(
		ctx,
		users,
		"Auditing QuickSight cost",
		func(_ context.Context, u struct {
			name   string
			email  string
			role   string
			active bool
		}) audit.Finding {
			// Authors cost $18/mo, Readers cost per session
			monthlyCost := 0.0
			if u.role == "AUTHOR" || u.role == "ADMIN" {
				monthlyCost = 18.0
			} else if u.role == "READER" {
				monthlyCost = 5.0 // max per reader/mo
			}

			_ = cutoff // used for future last-login check if API supports it

			if !u.active {
				return audit.Finding{
					Service:    "quicksight",
					ResourceID: u.name,
					Check:      "inactive_user",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"role=%s, email=%s, inactive account",
						u.role,
						u.email,
					),
					RiskLevel:            "HIGH",
					EstimatedMonthlyCost: monthlyCost,
					Remediation: remediation.Recommend(
						"cost",
						"quicksight",
						"inactive_user",
						u.name,
						"inactive QuickSight user",
					),
				}
			}
			return audit.Finding{
				Service:              "quicksight",
				ResourceID:           u.name,
				Check:                "inactive_user",
				Status:               "PASS",
				Detail:               fmt.Sprintf("role=%s, active", u.role),
				RiskLevel:            "MINIMAL",
				EstimatedMonthlyCost: monthlyCost,
			}
		},
	), nil
}
