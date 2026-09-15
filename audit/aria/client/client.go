// Package client is a minimal REST client for on-prem VMware Aria Automation 8.x
//
// Authentication is a token exchange: a long-lived refresh token (API token)
// is exchanged for a short-lived bearer access token, which is then sent as
// `Authorization: Bearer <token>` on every subsequent request.
//
// The refresh token is NEVER accepted on the command line; it is read from
// configuration (see cmd/aria.go) and passed to New here.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to a single Aria Automation appliance/host.
type Client struct {
	host  string // e.g. "https://aria.corp.example.com" (scheme required)
	http  *http.Client
	token string // bearer access token (populated by Login)
}

// Options configures a Client.
type Options struct {
	// Host is the Aria appliance base URL, with scheme (https://...).
	Host string
	// InsecureSkipVerify disables TLS verification (common for on-prem
	// appliances using self-signed certs). Off by default.
	InsecureSkipVerify bool
	// Timeout for individual HTTP requests. Defaults to 30s.
	Timeout time.Duration
}

// New constructs a Client. Call Login before making authenticated calls.
func New(opts Options) (*Client, error) {
	host := strings.TrimRight(strings.TrimSpace(opts.Host), "/")
	if host == "" {
		return nil, fmt.Errorf("aria: host is required")
	}
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		return nil, fmt.Errorf("aria: host must include scheme (https://...): %q", host)
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.InsecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	return &Client{
		host: host,
		http: &http.Client{Timeout: timeout, Transport: transport},
	}, nil
}

// Host returns the base URL this client targets (used as the scope ID).
func (c *Client) Host() string { return c.host }

// loginRequest / loginResponse model the on-prem 8.x IaaS login token exchange:
//
//	POST {host}/iaas/api/login { "refreshToken": "<api-token>" }
//		-> 200 { "token": "<bearer>" }
//
// NOTE: field names confirmed against the target instance's Swagger before
// finalizing. If the appliance uses the CSP gateway path instead
// (/csp/gateway/am/api/login returning { "access_token": ... }), adjust
// loginPath and the response field here.
const loginPath = "/iaas/api/login"

type loginRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type loginResponse struct {
	Token string `json:"token"`
}

// Login exchanges the refresh token for a bearer access token and stores it
// on the client for subsequent requests.
func (c *Client) Login(ctx context.Context, refreshToken string) error {
	if strings.TrimSpace(refreshToken) == "" {
		return fmt.Errorf("aria: refresh token is required")
	}

	body, err := json.Marshal(loginRequest{RefreshToken: refreshToken})
	if err != nil {
		return fmt.Errorf("aria: marshal login request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+loginPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("aria: login request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("aria: login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("aria: login returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var lr loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return fmt.Errorf("aria: decode login response: %w", err)
	}
	if lr.Token == "" {
		return fmt.Errorf("aria: login response contained no token")
	}
	c.token = lr.Token
	return nil
}

// GetJSON performs an authenticated GET against path (which may include a query
// string) and decodes the JSOn response into out.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	if c.token == "" {
		return fmt.Errorf("aria: not authenticated (call Login first)")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+path, nil)
	if err != nil {
		return fmt.Errorf("aria: build request %s: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("aria: request %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("aria: GET %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("aria: decode %s response: %w", path, err)
	}
	return nil
}

// Page is the standard Aria paged-response envelope. Field names follow the
// common Aria/Spring convention; confirm against the instance Swagger.
type Page[T any] struct {
	Content          []T `json:"content"`
	TotalElements    int `json:"totalElements"`
	NumberOfElements int `json:"numberOfElements"`
	TotalPages       int `json:"totalPages"`
}

// GetAll pages through a collection endpoint using $top/$skip and returns all
// items. basePath must not already contain $top/$skip.
func (c *Client) GetAll(ctx context.Context, basePath string, top int) ([]json.RawMessage, error) {
	if top <= 0 {
		top = 100
	}
	var all []json.RawMessage
	skip := 0
	for {
		sep := "?"
		if strings.Contains(basePath, "?") {
			sep = "&"
		}
		path := fmt.Sprintf("%s%s$top=%d&$skip=%d", basePath, sep, top, skip)

		var page Page[json.RawMessage]
		if err := c.GetJSON(ctx, path, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Content...)

		skip += len(page.Content)
		if len(page.Content) == 0 || skip >= page.TotalElements || page.TotalElements == 0 {
			break
		}
	}
	return all, nil
}

// escape is a tiny helper for callers that build query values.
func escape(v string) string { return url.QueryEscape(v) }

var _ = escape // retained for checker query-building; remove if unused
