package client

import (
	"context"
	"encoding/json"
)

// Resource is a subset of an Aria Automation deployment resource
// (GET /deployment/api/resources, or per-deployment
// GET /deployment/api/deployments/{id}/resources). Only fields sift
// surfaces are modeled; the free-form Properties map carries the rest
// (t-shirt size, environment, site, etc.) since resource types vary widely
// (VMs, networks, custom OpenShift projects, ...). Unknown top-level fields
// are ignored.
type Resource struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Type         string         `json:"type"`
	State        string         `json:"state"`
	SyncStatus   string         `json:"syncStatus"`
	Origin       string         `json:"origin"`
	CreatedAt    string         `json:"createdAt"`
	DeploymentID string         `json:"deploymentId"`
	ProjectID    string         `json:"projectId"`
	Properties   map[string]any `json:"properties"`
}

// Prop returns a string-valued property from the free-form Properties map,
// or "" if absent or non-string.
func (r Resource) Prop(key string) string {
	if r.Properties == nil {
		return ""
	}
	if v, ok := r.Properties[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

const resourcesPath = "/deployment/api/resources"

// ListResources pages through all deployment resources visible to the token.
func (c *Client) ListResources(ctx context.Context) ([]Resource, error) {
	raws, err := c.GetAll(ctx, resourcesPath, 100)
	if err != nil {
		return nil, err
	}
	out := make([]Resource, 0, len(raws))
	for _, raw := range raws {
		var r Resource
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
