// Package metrics provides OAuth service specific metrics
package metrics

import (
	"context"
	"time"
)

// OAuthMetricsCollector collects OAuth-specific business metrics
type OAuthMetricsCollector struct {
	serviceName string
	db          OAuthDBStats
}

// OAuthDBStats interface for OAuth database stats
type OAuthDBStats interface {
	ActiveTokenCount(ctx context.Context) (int64, error)
	ClientCount(ctx context.Context) (int64, error)
	AuthorizationCodeCount(ctx context.Context) (int64, error)
}

// NewOAuthMetricsCollector creates a new OAuth metrics collector
func NewOAuthMetricsCollector(serviceName string, db OAuthDBStats) *OAuthMetricsCollector {
	return &OAuthMetricsCollector{
		serviceName: serviceName,
		db:          db,
	}
}

// Start starts the metrics collection loop
func (g *OAuthMetricsCollector) Start(ctx context.Context) {
	// Initial collection
	g.collectMetrics(ctx)

	// Collect every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				g.collectMetrics(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// collectMetrics gathers all OAuth metrics
func (g *OAuthMetricsCollector) collectMetrics(ctx context.Context) {
	if g.db == nil {
		return
	}

	// Could add gauges for token counts, etc.
}

// RecordAuthorizationRequest records an OAuth authorization request
func (g *OAuthMetricsCollector) RecordAuthorizationRequest(grantType string) {
	RecordTokenOperation("authorization_request", grantType)
}

// RecordAuthorizationApproved records an approved authorization
func (g *OAuthMetricsCollector) RecordAuthorizationApproved() {
	RecordTokenOperation("authorization", "approved")
}

// RecordAuthorizationDenied records a denied authorization
func (g *OAuthMetricsCollector) RecordAuthorizationDenied(reason string) {
	RecordTokenOperation("authorization", "denied")
}

// RecordTokenIssued records an access token issuance
func (g *OAuthMetricsCollector) RecordTokenIssued(grantType string) {
	RecordTokenOperation("token_issue", "success")
}

// RecordTokenRefresh records a token refresh
func (g *OAuthMetricsCollector) RecordTokenRefresh(success bool) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordTokenOperation("token_refresh", outcome)
}

// RecordTokenRevoked records a token revocation
func (g *OAuthMetricsCollector) RecordTokenRevoked(tokenType string) {
	RecordTokenOperation("token_revoke", tokenType)
}

// RecordTokenValidation records a token validation
func (g *OAuthMetricsCollector) RecordTokenValidation(success bool) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordTokenOperation("token_validation", outcome)
}

// RecordClientAuthentication records a client authentication attempt
func (g *OAuthMetricsCollector) RecordClientAuthentication(method string, success bool) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordAuthAttempt(method, outcome)
}

// RecordPKCEUsed records a PKCE usage
func (g *OAuthMetricsCollector) RecordPKCEUsed() {
	RecordTokenOperation("pkce", "used")
}

// RecordConsentGranted records user consent granted
func (g *OAuthMetricsCollector) RecordConsentGranted(scopesCount int) {
	RecordTokenOperation("consent", "granted")
}

// RecordConsentDenied records user consent denied
func (g *OAuthMetricsCollector) RecordConsentDenied() {
	RecordTokenOperation("consent", "denied")
}

// RecordUserInfoRequest records a UserInfo request
func (g *OAuthMetricsCollector) RecordUserInfoRequest(success bool) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	RecordTokenOperation("userinfo", outcome)
}

// Common grant types
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypePassword          = "password"
	GrantTypeImplicit          = "implicit"
)

// Common token types
const (
	TokenTypeAccess = "access_token"
	TokenTypeRefresh = "refresh_token"
	TokenTypeID = "id_token"
)

// Common auth methods
const (
	AuthMethodClientSecretPost = "client_secret_post"
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodPrivateKeyJWT = "private_key_jwt"
	AuthMethodNone = "none"
)
