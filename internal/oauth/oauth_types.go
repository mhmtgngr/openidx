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
	"crypto/rand"
	"fmt"
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

// generateUUID returns a random RFC 4122 version 4 UUID string.
// Retained because the live token store (store.go) uses it to mint family IDs.
func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	// Set version and variant bits.
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
