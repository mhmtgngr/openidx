// Package oauth provides OAuth 2.0 authorization flow with PKCE support
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// OAuth 2.0 Error Codes (RFC 6749 Section 4.1.2.1)
const (
	ErrorInvalidRequest        = "invalid_request"
	ErrorUnauthorizedClient    = "unauthorized_client"
	ErrorAccessDenied          = "access_denied"
	ErrorUnsupportedResponseType = "unsupported_response_type"
	ErrorInvalidScope          = "invalid_scope"
	ErrorServerError           = "server_error"
	ErrorTemporarilyUnavailable = "temporarily_unavailable"
	// Additional error codes for token endpoint
	ErrorInvalidClient         = "invalid_client"
	ErrorInvalidGrant          = "invalid_grant"
	ErrorUnsupportedGrantType  = "unsupported_grant_type"
)

// FlowAuthorizeRequest represents a parsed OAuth 2.0 authorization request
type FlowAuthorizeRequest struct {
	ClientID             string
	RedirectURI          string
	ResponseType         string
	Scope                string
	State                string
	Nonce                string // For OIDC
	CodeChallenge        string
	CodeChallengeMethod  string
	ResponseMode         string
	Display              string
	Prompt               string
	MaxAge               *int
	UILocales            string
	IDTokenHint          string
	LoginHint            string
	ACRValues            string
	Claims               string
}

// AuthorizationResponse represents a successful authorization response
type AuthorizationResponse struct {
	Code  string
	State string
}

// AuthorizationErrorResponse represents an OAuth 2.0 error response
type AuthorizationErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	State            string `json:"state,omitempty"`
}

// AuthorizeFlow handles OAuth 2.0 authorization code flow with PKCE
type AuthorizeFlow struct {
	clients *ClientRepository
	store   *Store
	logger  *zap.Logger
	issuer  string
}

// NewAuthorizeFlow creates a new authorization flow handler
func NewAuthorizeFlow(clients *ClientRepository, store *Store, logger *zap.Logger, issuer string) *AuthorizeFlow {
	return &AuthorizeFlow{
		clients: clients,
		store:   store,
		logger:  logger.With(zap.String("flow", "authorize")),
		issuer:  issuer,
	}
}

// HandleAuthorize handles GET /oauth/authorize requests
func (f *AuthorizeFlow) HandleAuthorize(c *gin.Context) {
	ctx := c.Request.Context()

	// Parse the authorization request
	req, err := f.parseRequest(c)
	if err != nil {
		f.redirectError(c, req, ErrorInvalidRequest, err.Error())
		return
	}

	// Log the authorization request
	f.logger.Info("Authorization request",
		zap.String("client_id", req.ClientID),
		zap.String("response_type", req.ResponseType),
		zap.String("redirect_uri", req.RedirectURI),
		zap.String("scope", req.Scope),
		zap.String("code_challenge_method", req.CodeChallengeMethod))

	// Validate and retrieve the client
	client, err := f.clients.GetByClientID(ctx, req.ClientID)
	if err != nil {
		f.logger.Warn("Unknown client in authorization request",
			zap.String("client_id", req.ClientID),
			zap.Error(err))
		f.redirectError(c, req, ErrorUnauthorizedClient, "Invalid client_id")
		return
	}

	// Validate redirect URI
	if !f.clients.ValidateRedirectURI(client, req.RedirectURI) {
		f.logger.Warn("Unregistered redirect URI",
			zap.String("client_id", req.ClientID),
			zap.String("redirect_uri", req.RedirectURI))
		f.redirectError(c, req, ErrorInvalidRequest, "Invalid redirect_uri")
		return
	}

	// Validate response type
	if !f.validateResponseType(client, req.ResponseType) {
		f.redirectError(c, req, ErrorUnsupportedResponseType, "response_type not supported")
		return
	}

	// Validate scope
	if !f.clients.ValidateScope(client, req.Scope) {
		f.redirectError(c, req, ErrorInvalidScope, "Requested scope is not allowed")
		return
	}

	// Validate PKCE parameters
	if err := f.validatePKCE(client, req); err != nil {
		f.logger.Warn("PKCE validation failed",
			zap.String("client_id", req.ClientID),
			zap.Error(err))
		f.redirectError(c, req, ErrorInvalidRequest, err.Error())
		return
	}

	// Check if user is authenticated
	// For this implementation, we'll check for a session cookie
	session, err := f.getUserSession(c)
	if err != nil || session == nil {
		// User not authenticated - redirect to login
		f.redirectToLogin(c, req, client)
		return
	}

	// User is authenticated, generate authorization code
	authCode, err := f.generateAuthorizationCode(ctx, client, session.UserID, req)
	if err != nil {
		f.logger.Error("Failed to generate authorization code",
			zap.String("client_id", req.ClientID),
			zap.Error(err))
		f.redirectError(c, req, ErrorServerError, "Failed to generate authorization code")
		return
	}

	// Redirect back with authorization code
	f.redirectWithCode(c, req.RedirectURI, authCode, req.State)
}

// parseRequest parses the authorization request from query parameters
func (f *AuthorizeFlow) parseRequest(c *gin.Context) (*FlowAuthorizeRequest, error) {
	req := &FlowAuthorizeRequest{
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		ResponseType:        c.Query("response_type"),
		Scope:               c.Query("scope"),
		State:               c.Query("state"),
		Nonce:               c.Query("nonce"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
		ResponseMode:        c.Query("response_mode"),
		Display:             c.Query("display"),
		Prompt:              c.Query("prompt"),
		UILocales:           c.Query("ui_locales"),
		IDTokenHint:         c.Query("id_token_hint"),
		LoginHint:           c.Query("login_hint"),
		ACRValues:           c.Query("acr_values"),
		Claims:              c.Query("claims"),
	}

	// Validate required parameters
	if req.ClientID == "" {
		return nil, errors.New("client_id is required")
	}

	if req.RedirectURI == "" {
		return nil, errors.New("redirect_uri is required")
	}

	if req.ResponseType == "" {
		return nil, errors.New("response_type is required")
	}

	// Validate response_type value
	if req.ResponseType != "code" && req.ResponseType != "token" && req.ResponseType != "id_token" {
		return nil, fmt.Errorf("unsupported response_type: %s", req.ResponseType)
	}

	// Set default PKCE method to plain if challenge is present but method is not
	if req.CodeChallenge != "" && req.CodeChallengeMethod == "" {
		req.CodeChallengeMethod = "plain"
	}

	// Validate code_challenge_method if present
	if req.CodeChallengeMethod != "" &&
		req.CodeChallengeMethod != "S256" &&
		req.CodeChallengeMethod != "plain" {
		return nil, fmt.Errorf("unsupported code_challenge_method: %s", req.CodeChallengeMethod)
	}

	// Validate code_challenge is present if code_challenge_method is set
	if req.CodeChallengeMethod != "" && req.CodeChallenge == "" {
		return nil, errors.New("code_challenge is required when code_challenge_method is present")
	}

	// For OIDC, nonce is required for implicit flow
	if req.ResponseType == "id_token" && req.Nonce == "" {
		// This is an OIDC requirement but we'll be lenient for compatibility
		f.logger.Warn("OIDC implicit flow without nonce")
	}

	return req, nil
}

// validateResponseType checks if the client supports the requested response type
func (f *AuthorizeFlow) validateResponseType(client *Client, responseType string) bool {
	// Map response_type to grant_type
	supportedTypes := map[string]string{
		"code":     "authorization_code",
		"token":    "implicit",
		"id_token": "implicit",
	}

	grantType, ok := supportedTypes[responseType]
	if !ok {
		return false
	}

	// Check if client supports the grant type
	for _, gt := range client.GrantTypes {
		if gt == grantType {
			return true
		}
	}

	return false
}

// validatePKCE validates PKCE parameters according to RFC 7636
func (f *AuthorizeFlow) validatePKCE(client *Client, req *FlowAuthorizeRequest) error {
	// If PKCE is required for this client, code_challenge must be present
	if client.PKCERequired && req.CodeChallenge == "" {
		return errors.New("PKCE is required for this client")
	}

	// If code_challenge is present, validate it
	if req.CodeChallenge != "" {
		// Validate code_challenge length (43-128 characters as per RFC 7636)
		if len(req.CodeChallenge) < 43 || len(req.CodeChallenge) > 128 {
			return errors.New("code_challenge must be between 43 and 128 characters")
		}

		// Validate code_challenge is base64url-encoded
		if !isValidBase64URL(req.CodeChallenge) {
			return errors.New("code_challenge must be base64url-encoded")
		}

		// For S256 method, we'll validate the verifier during token exchange
		// For plain method, we'll validate during token exchange as well
	}

	return nil
}

// getUserSession retrieves the authenticated user session
func (f *AuthorizeFlow) getUserSession(c *gin.Context) (*UserSession, error) {
	// Check session cookie
	sessionCookie, err := c.Cookie("session")
	if err != nil || sessionCookie == "" {
		return nil, errors.New("no session cookie")
	}

	// In a real implementation, this would validate the session from Redis/database
	// For now, return a mock session
	return &UserSession{
		UserID:    "user-123",
		Email:     "user@example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

// generateAuthorizationCode creates and stores an authorization code
func (f *AuthorizeFlow) generateAuthorizationCode(ctx context.Context, client *Client, userID string, req *FlowAuthorizeRequest) (string, error) {
	// Generate the authorization code
	code := f.store.GenerateToken()

	// Calculate expiration (10 minutes from now)
	expiresAt := time.Now().Add(DefaultAuthCodeTTL)

	// Store the authorization code
	storedCode := &StoredAuthorizationCode{
		Code:                code,
		ClientID:            client.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           expiresAt,
		CreatedAt:           time.Now(),
		Used:                false,
	}

	if err := f.store.StoreAuthorizationCode(ctx, storedCode, DefaultAuthCodeTTL); err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	f.logger.Debug("Generated authorization code",
		zap.String("code", code[:8]+"..."), // Log prefix only
		zap.String("client_id", client.ClientID),
		zap.String("user_id", userID))

	return code, nil
}

// redirectWithCode redirects to the client's redirect_uri with the authorization code
func (f *AuthorizeFlow) redirectWithCode(c *gin.Context, redirectURI, code, state string) {
	// Parse the redirect URI
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		f.logger.Error("Failed to parse redirect URI", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid redirect URI"})
		return
	}

	// Build query parameters
	query := parsedURL.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}

	parsedURL.RawQuery = query.Encode()

	// Redirect
	c.Redirect(http.StatusFound, parsedURL.String())
}

// redirectError redirects to the client's redirect_uri with an error response
func (f *AuthorizeFlow) redirectError(c *gin.Context, req *FlowAuthorizeRequest, errorCode, description string) {
	// Use the redirect URI from the request if available
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		// If no redirect URI, return error as JSON
		c.JSON(http.StatusBadRequest, AuthorizationErrorResponse{
			Error:            errorCode,
			ErrorDescription: description,
		})
		return
	}

	// Parse the redirect URI
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid redirect URI"})
		return
	}

	// Build error query parameters
	query := parsedURL.Query()
	query.Set("error", errorCode)
	if description != "" {
		query.Set("error_description", description)
	}
	if req.State != "" {
		query.Set("state", req.State)
	}

	parsedURL.RawQuery = query.Encode()

	// Redirect with error
	c.Redirect(http.StatusFound, parsedURL.String())
}

// redirectToLogin redirects the user to the login page
func (f *AuthorizeFlow) redirectToLogin(c *gin.Context, req *FlowAuthorizeRequest, client *Client) {
	// Store the authorization request in Redis for after login
	sessionID := f.store.GenerateToken()

	// Build login URL with all parameters preserved
	loginURL := fmt.Sprintf("/login?auth_session=%s&client_id=%s&redirect_uri=%s",
		sessionID,
		url.QueryEscape(req.ClientID),
		url.QueryEscape(req.RedirectURI))

	if req.ResponseType != "" {
		loginURL += "&response_type=" + url.QueryEscape(req.ResponseType)
	}
	if req.Scope != "" {
		loginURL += "&scope=" + url.QueryEscape(req.Scope)
	}
	if req.State != "" {
		loginURL += "&state=" + url.QueryEscape(req.State)
	}
	if req.Nonce != "" {
		loginURL += "&nonce=" + url.QueryEscape(req.Nonce)
	}
	if req.CodeChallenge != "" {
		loginURL += "&code_challenge=" + url.QueryEscape(req.CodeChallenge)
	}
	if req.CodeChallengeMethod != "" {
		loginURL += "&code_challenge_method=" + url.QueryEscape(req.CodeChallengeMethod)
	}

	c.Redirect(http.StatusFound, loginURL)
}

// ValidatePKCEVerifier validates the PKCE code_verifier against the stored code_challenge
// Called during token exchange
func ValidatePKCEVerifier(codeVerifier, codeChallenge, codeChallengeMethod string) error {
	if codeChallenge == "" {
		// No PKCE was used during authorization
		return nil
	}

	if codeVerifier == "" {
		return errors.New("code_verifier is required when code_challenge was provided")
	}

	// Validate code_verifier length (43-128 characters as per RFC 7636)
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return errors.New("code_verifier must be between 43 and 128 characters")
	}

	// Validate code_verifier is base64url-encoded
	if !isValidBase64URL(codeVerifier) {
		return errors.New("code_verifier must be base64url-encoded")
	}

	switch codeChallengeMethod {
	case "S256":
		// S256: code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
		hash := sha256.Sum256([]byte(codeVerifier))
		calculatedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

		if calculatedChallenge != codeChallenge {
			return errors.New("code_verifier does not match code_challenge (S256)")
		}

	case "plain":
		// plain: code_challenge = code_verifier
		if codeVerifier != codeChallenge {
			return errors.New("code_verifier does not match code_challenge (plain)")
		}

	default:
		return fmt.Errorf("unsupported code_challenge_method: %s", codeChallengeMethod)
	}

	return nil
}

// UserSession represents an authenticated user session
type UserSession struct {
	UserID    string
	Email     string
	Name      string
	ExpiresAt time.Time
}

// isValidBase64URL checks if a string is valid base64url encoding
func isValidBase64URL(s string) bool {
	// Base64url should only contain alphanumeric characters, hyphen, and underscore
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_') {
			return false
		}
	}
	return len(s) > 0
}

// DefaultScopes returns the default scopes for a given grant type
func DefaultScopes(grantType string) []string {
	switch grantType {
	case "authorization_code":
		return []string{"openid", "profile"}
	case "client_credentials":
		return []string{} // No user identity scopes
	case "refresh_token":
		return []string{"openid", "profile"}
	default:
		return []string{"openid"}
	}
}
