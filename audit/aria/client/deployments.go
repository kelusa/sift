package client

import (
	"context"
	"encoding/json"
)

// Deployment is a subset of the Aria Automation deployment object
// (Get /deployment/api/deployments). Only fields sift surfaces or audits are
// modeled; unknown fields are ignored by the JSON decoder.
type Deployment struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	OrgID       string `json:"orgId"`
	ProjectID   string `json:"projectId"`
	Status      string `json:"status"`

	CatalogItemID      string `json:"catalogItemId"`
	CatalogItemVersion string `json:"catalogItemVersion"`
	BlueprintID        string `json:"blueprintId"`
	BlueprintVersion   string `json:"blueprintVersion"`

	CreatedAt     string `json:"createdAt"`
	CreatedBy     string `json:"createdBy"`
	OwnedBy       string `json:"ownedBy"`
	OwnerType     string `json:"ownerType"`
	LastUpdatedAt string `json:"lastUpdatedAt"`
	LastUpdatedBy string `json:"lastUpdatedBy"`

	LeaseGracePeriodDays int `json:"leaseGracePeriodDays"`
}

const deploymentsPath = "/deployment/api/deployments"

// ListDeployments pages through all deployments visible to the token.
func (c *Client) ListDeployments(ctx context.Context) ([]Deployment, error) {
	raws, err := c.GetAll(ctx, deploymentsPath, 100)
	if err != nil {
		return nil, err
	}
	out := make([]Deployment, 0, len(raws))
	for _, raw := range raws {
		var d Deployment
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}
