// Package aria holds the VMware Aria Automation (on-prem 8.x) provider: config
// loading, a client factory, and the scope accessor used by checkers.
//
// Authentication uses a pre-obtained bearer token (the instance issues tokens
// via a browser OAuth/PKCE flow and does not expose API tokens). The token is
// read from the SIFT_ARIA_TOKEN environment variable - never from the command
// line and never persisted to config. Host may come from the --host flag or
// ~/.sift/providers.json
package aria

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sift/audit"
	"sift/audit/aria/client"
)

// Module names for Aria checkers (provider-neutral registry keys).
const (
	ModuleSecurity   = "security"
	ModuleGovernance = "governance"
)

// TokenEnvVar is the environment variable holding the bearer access token.
const TokenEnvVar = "SIFT_ARIA_TOKEN"

// Config is the resolved connection configuration for a single Aria host.
type Config struct {
	Host     string
	Token    string
	Insecure bool
}

// providersFile mirrors ~/.sift/providers.json. Only the aria section is used
// here. The token is intentionally NOT read from this file.
type providersFile struct {
	Aria struct {
		Host     string `json:"host"`
		Insecure bool   `json:"insecure"`
	} `json:"aria"`
}

// LoadConfig resolves the Aria connection config. hostFlag (from --host) takes
// precedence over the providers.json host. The token always comes from the
// environment. insecureFlag forces TLS skip when true; otherwise the value
// from providers.json is used.
func LoadConfig(hostFlag string, insecureFlag bool) (Config, error) {
	var cfg Config

	fileHost, fileInsecure := loadProvidersFile()

	cfg.Host = strings.TrimSpace(hostFlag)
	if cfg.Host == "" {
		cfg.Host = fileHost
	}
	if cfg.Host == "" {
		return cfg, fmt.Errorf("aria: no host configured (pass --host or set aria.host in ~/.sift/providers.json)")
	}

	cfg.Insecure = insecureFlag || fileInsecure

	cfg.Token = strings.TrimSpace(os.Getenv(TokenEnvVar))
	if cfg.Token == "" {
		return cfg, fmt.Errorf("aria: no bearer token found; set %s (obtain it from an authenticated browser session)", TokenEnvVar)
	}

	return cfg, nil
}

// loadProvidersFile reads ~/.sift/providers.json, returning host and insecure.
// Missing/invalid file is not an error (returns zero values).
func loadProvidersFile() (host string, insecure bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	data, err := os.ReadFile(filepath.Join(home, ".sift", "providers.json"))
	if err != nil {
		return "", false
	}
	var pf providersFile
	if json.Unmarshal(data, &pf) != nil {
		return "", false
	}
	return strings.TrimSpace(pf.Aria.Host), pf.Aria.Insecure
}

// NewClient builds an authenticated Aria client from resolved config.
func NewClient(cfg Config) (*client.Client, error) {
	return client.New(client.Options{
		Host:               cfg.Host,
		Token:              cfg.Token,
		InsecureSkipVerify: cfg.Insecure,
	})
}

// ClientFrom recovers the *client.Client from an Aria scope. Checkers call this
// at the top of their body (mirrors audit.AWSConfig for the AWS provider).
// Kept in this package rather than package audit to avoid an import cycle.
func ClientFrom(s audit.Scope) *client.Client {
	return s.Client.(*client.Client)
}

// Provider implements audit.Provider for Aria. Each configured host is one
// scope. Currently a single host is supported.
type Provider struct {
	cfg Config
}

// NewProvider constructs the Aria provider from resolved config.
func NewProvider(cfg Config) *Provider { return &Provider{cfg: cfg} }

func (p *Provider) Name() string { return "aria" }

func (p *Provider) Scopes(ctx context.Context) ([]audit.Scope, error) {
	c, err := NewClient(p.cfg)
	if err != nil {
		return nil, err
	}
	return []audit.Scope{{
		Provider: "aria",
		ID:       c.Host(),
		Client:   c,
	}}, nil
}
