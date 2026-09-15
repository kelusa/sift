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
	token string // bearer access token (provided at construction)
}

// Options configures a Client.
type Options struct {
	// Host is the Aria appliance base URL, with scheme (https://...).
	Host string
	// Token is a pre-obtained bearer access token. On instances where API
	// tokens / service accounts are not available (login is via browser
	// OAuth/PKCE), users obtain this token from an authenticated browser
	// session and provide it via the SIFT_ARIA_TOKEN environment variable or a
	// secure prompt - never on the command line, never persisted to config.
	Token string
	// InsecureSkipVerify disables TLS verification (common for on-prem
	// appliances using self-signed certs). Off by default.
	InsecureSkipVerify bool
	// Timeout for individual HTTP requests. Defaults to 30s.
	Timeout time.Duration
}

// New constructs a Client from a pre-obtained bearer token. The client is
// ready to make authenticated calls immediately.
func New(opts Options) (*Client, error) {
	host := strings.TrimRight(strings.TrimSpace(opts.Host), "/")
	if host == "" {
		return nil, fmt.Errorf("aria: host is required")
	}
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		return nil, fmt.Errorf("aria: host must include scheme (https://...): %q", host)
	}
	if strings.TrimSpace(opts.Token) == "" {
		return nil, fmt.Errorf("aria: bearer token is required (set SIFT_ARIA_TOKEN)")
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
		host:  host,
		http:  &http.Client{Timeout: timeout, Transport: transport},
		token: strings.TrimSpace(opts.Token),
	}, nil
}

// Host returns the base URL this client targets (used as the scope ID).
func (c *Client) Host() string { return c.host }

// GetJSON performs an authenticated GET against path (which may include a query
// string) and decodes the JSOn response into out.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	if c.token == "" {
		return fmt.Errorf("aria: not authenticated (no bearer token)")
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
