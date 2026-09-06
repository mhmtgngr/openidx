// Package oauth: shared OAuth types and small helpers used by the live service.
//
// This file preserves the handful of symbols that were previously defined in
// the now-removed legacy OAuth core (client.go / authorize_flow.go /
// token_flow.go). That legacy cluster implemented a second, parallel
// OAuth/OIDC pipeline (Client/ClientRepository/AuthorizeFlow/TokenFlow) that
// was never wired to a live route and had diverged from the authoritative
// implementation in service.go (notably a less-strict, wildcard-subdomain
// redirect_uri check that risked open redirects). It was removed to eliminate
// the "two representations that can disagree" hazard. The authoritative OAuth
// client representation is OAuthClient (+ OAuthClientStore); the live token,
// authorize, and userinfo flows live in service.go / authorize.go.
package oauth

import (
	"time"
)

// RFC 6749 / OIDC error codes. ErrorServerError and
// ErrorTemporarilyUnavailable are used by the live brownout/unavailability
// path (unavailable.go); the rest are the standard set kept alongside them for
// consistent error responses.
const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorUnauthorizedClient      = "unauthorized_client"
	ErrorAccessDenied            = "access_denied"
	ErrorUnsupportedResponseType = "unsupported_response_type"
	ErrorInvalidScope            = "invalid_scope"
	ErrorServerError             = "server_error"
	ErrorTemporarilyUnavailable  = "temporarily_unavailable"
	ErrorInvalidClient           = "invalid_client"
	ErrorInvalidGrant            = "invalid_grant"
	ErrorUnsupportedGrantType    = "unsupported_grant_type"
)

// TokenFlowResponse represents a successful token response (RFC 6749 Section 5.1).
// Retained because the live social-login fallback path
// (Service.generateTokensForUser) returns it.
type TokenFlowResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// AccessTokenData is the Redis-stored shape of a minted access token.
//
// It moved here when internal/oauth/store.go was deleted: that file was 539
// lines of a second, parallel token store with no non-test caller, and this
// struct was the one thing in it the live code used
// (generateTokensForUser in service.go).
type AccessTokenData struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
