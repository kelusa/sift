package client

import (
	"context"
	"encoding/json"
)

// Project is a subset of the Aria Automation project object from the list view
// (GET /iaas/api/projects). The list endpoint returns a lightweight summary;
// richer detail (members, zones, constraints, custom properties) is available
// from GET /iaas/api/projects/{id}. Unknown fields are ignored by the decoder.
type Project struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	OrgID          string `json:"orgId"`
	OrganizationID string `json:"organizationId"`
}

const projectsPath = "/iaas/api/projects"

// ListProjects pages through all projects visible to the token.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	raws, err := c.GetAll(ctx, projectsPath, 100)
	if err != nil {
		return nil, err
	}
	out := make([]Project, 0, len(raws))
	for _, raw := range raws {
		var p Project
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
