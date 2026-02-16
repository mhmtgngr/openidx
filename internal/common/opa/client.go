// Package opa provides an HTTP client for Open Policy Agent authorization decisions
package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/resilience"
)

// Input represents the authorization input sent to OPA
type Input struct {
	User     UserContext     `json:"user"`
	Resource ResourceContext `json:"resource"`
	Method   string         `json:"method"`
	Path     string         `json:"path"`
}

// UserContext contains the authenticated user's identity info
type UserContext struct {
	ID            string   `json:"id"`
	Roles         []string `json:"roles"`
	Groups        []string `json:"groups,omitempty"`
	TenantID      string   `json:"tenant_id,omitempty"`
	Authenticated bool     `json:"authenticated"`
}

// ResourceContext describes the resource being accessed
type ResourceContext struct {
	Type  string `json:"type,omitempty"`
	Owner string `json:"owner,omitempty"`
}

// Decision represents OPA's authorization response
type Decision struct {
	Allow bool     `json:"allow"`
	Deny  []string `json:"deny,omitempty"`
}

// opaResponse wraps the OPA REST API response structure
type opaResponse struct {
	Result Decision `json:"result"`
}

// Client communicates with an OPA server for policy decisions
type Client struct {
	baseURL    string
	httpClient *resilience.ResilientHTTPClient
	logger     *zap.Logger
	policyPath string
}

// NewClient creates a new OPA client
func NewClient(baseURL string, logger *zap.Logger) *Client {
	rawClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	cb := resilience.NewCircuitBreaker(resilience.CircuitBreakerConfig{
		Name:         "opa",
		Threshold:    5,
		ResetTimeout: 15 * time.Second,
		Logger:       logger.With(zap.String("component", "opa-circuit-breaker")),
	})
	return &Client{
		baseURL:    baseURL,
		httpClient: resilience.NewResilientHTTPClient(rawClient, cb),
		logger:     logger,
		policyPath: "/v1/data/openidx/authz",
	}
}

// Authorize sends an authorization request to OPA and returns the decision
func (c *Client) Authorize(ctx context.Context, input Input) (*Decision, error) {
	payload := map[string]interface{}{
		"input": input,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal OPA input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+c.policyPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Warn("OPA request failed", zap.Error(err))
		return nil, fmt.Errorf("OPA request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	var opaResp opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("decode OPA response: %w", err)
	}

	return &opaResp.Result, nil
}
