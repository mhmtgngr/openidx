// Package oauth provides OAuth 2.0 token endpoint functionality
package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/errors"
)

// OAuth 2.0 Token Error Codes (RFC 6749 Section 5.2)
const (
	TokenErrorInvalidRequest           = "invalid_request"
	TokenErrorInvalidClient            = "invalid_client"
	TokenErrorInvalidGrant             = "invalid_grant"
	TokenErrorUnauthorizedClient       = "unauthorized_client"
	TokenErrorUnsupportedGrantType     = "unsupported_grant_type"
	TokenErrorInvalidScope             = "invalid_scope"
	TokenErrorServerError              = "server_error"
)

// TokenRequest represents a token request
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	RefreshToken string `form:"refresh_token"`
	Scope        string `form:"scope"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	CodeVerifier string `form:"code_verifier"`
}

// TokenResponse represents a successful token response (RFC 6749 Section 5.1)
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenErrorResponse represents an OAuth 2.0 token error response (RFC 6749 Section 5.2)
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// TokenFlow handles OAuth 2.0 token endpoint requests
type TokenFlow struct {
	clients   *ClientRepository
	store     *Store
	jwtSigner jwt.SigningMethod
	issuer    string
	logger    *zap.Logger
	privateKey interface{} // RSA private key for JWT signing
}

// NewTokenFlow creates a new token flow handler
func NewTokenFlow(clients *ClientRepository, store *Store, privateKey interface{}, issuer string, logger *zap.Logger) *TokenFlow {
	return &TokenFlow{
		clients:   clients,
		store:     store,
		jwtSigner: jwt.GetSigningMethod("RS256"),
		issuer:    issuer,
		logger:    logger.With(zap.String("flow", "token")),
		privateKey: privateKey,
	}
}

// HandleToken handles POST /oauth/token requests
func (f *TokenFlow) HandleToken(c *gin.Context) {
	ctx := c.Request.Context()

	// Parse the token request
	var req TokenRequest

	// Try to parse from form data (standard OAuth 2.0)
	if err := c.ShouldBind(&req); err != nil {
		f.logger.Warn("Invalid token request", zap.Error(err))
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorInvalidRequest,
			ErrorDescription: "Invalid request parameters",
		})
		return
	}

	// Authenticate the client
	client, err := f.authenticateClient(ctx, c, req)
	if err != nil {
		f.logger.Warn("Client authentication failed", zap.Error(err))
		c.Header("WWW-Authenticate", `Basic realm="OAuth Token"`)
		c.JSON(http.StatusUnauthorized, TokenErrorResponse{
			Error:            TokenErrorInvalidClient,
			ErrorDescription: "Client authentication failed",
		})
		return
	}

	f.logger.Info("Token request",
		zap.String("client_id", client.ClientID),
		zap.String("grant_type", req.GrantType))

	// Route to the appropriate grant handler
	switch req.GrantType {
	case "authorization_code":
		f.handleAuthorizationCodeGrant(ctx, c, client, &req)

	case "refresh_token":
		f.handleRefreshTokenGrant(ctx, c, client, &req)

	case "client_credentials":
		f.handleClientCredentialsGrant(ctx, c, client, &req)

	default:
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorUnsupportedGrantType,
			ErrorDescription: fmt.Sprintf("Unsupported grant_type: %s", req.GrantType),
		})
	}
}

// authenticateClient authenticates the client using either HTTP Basic Auth or POST body
func (f *TokenFlow) authenticateClient(ctx context.Context, c *gin.Context, req *TokenRequest) (*Client, error) {
	// Try HTTP Basic Authentication first (client_secret_basic)
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if ok {
		return f.clients.AuthenticateClient(ctx, clientID, clientSecret)
	}

	// Fall back to POST body authentication (client_secret_post)
	if req.ClientID != "" && req.ClientSecret != "" {
		return f.clients.AuthenticateClient(ctx, req.ClientID, req.ClientSecret)
	}

	// For public clients, try client_id only (no secret)
	if req.ClientID != "" {
		client, err := f.clients.GetByClientID(ctx, req.ClientID)
		if err == nil && client.ClientAuthentication == "none" {
			return client, nil
		}
	}

	return nil, errors.New("client authentication failed")
}

// handleAuthorizationCodeGrant handles the authorization_code grant type
func (f *TokenFlow) handleAuthorizationCodeGrant(ctx context.Context, c *gin.Context, client *Client, req *TokenRequest) {
	// Validate required parameters
	if req.Code == "" {
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorInvalidRequest,
			ErrorDescription: "code is required",
		})
		return
	}

	// Validate redirect_uri must match the original authorization request
	if req.RedirectURI == "" {
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorInvalidRequest,
			ErrorDescription: "redirect_uri is required",
		})
		return
	}

	// Retrieve the authorization code
	storedCode, err := f.store.GetAuthorizationCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, ErrCodeNotFound) {
			c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            TokenErrorInvalidGrant,
				ErrorDescription: "Invalid authorization code",
			})
			return
		}
		if errors.Is(err, ErrCodeExpired) {
			c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            TokenErrorInvalidGrant,
				ErrorDescription: "Authorization code has expired",
			})
			return
		}
		if errors.Is(err, ErrCodeAlreadyUsed) {
			// Replay attack detected - potentially compromised code
			f.logger.Warn("Replay attack detected - authorization code already used",
				zap.String("client_id", client.ClientID))
			c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            TokenErrorInvalidGrant,
				ErrorDescription: "Authorization code already used",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error: TokenErrorServerError,
		})
		return
	}

	// Verify the code belongs to the authenticated client
	if storedCode.ClientID != client.ClientID {
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorInvalidGrant,
			ErrorDescription: "Authorization code was issued to a different client",
		})
		return
	}

	// Verify redirect_uri matches the original request
	if storedCode.RedirectURI != req.RedirectURI {
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorInvalidGrant,
			ErrorDescription: "redirect_uri does not match the original authorization request",
		})
		return
	}

	// Validate PKCE code_verifier
	if err := ValidatePKCEVerifier(req.CodeVerifier, storedCode.CodeChallenge, storedCode.CodeChallengeMethod); err != nil {
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorInvalidGrant,
			ErrorDescription: fmt.Sprintf("PKCE validation failed: %s", err.Error()),
		})
		return
	}

	// Mark the authorization code as used (single-use)
	if err := f.store.ConsumeAuthorizationCode(ctx, req.Code); err != nil {
		f.logger.Error("Failed to consume authorization code", zap.Error(err))
		c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error: TokenErrorServerError,
		})
		return
	}

	// Determine the scope for the tokens
	scope := storedCode.Scope
	if req.Scope != "" {
		// If scope was requested in token request, ensure it's a subset
		if !isScopeSubset(req.Scope, storedCode.Scope) {
			c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            TokenErrorInvalidScope,
				ErrorDescription: "Requested scope exceeds original authorization",
			})
			return
		}
		scope = req.Scope
	}

	// Issue tokens
	tokens, err := f.issueTokens(ctx, client, storedCode.UserID, scope, "")
	if err != nil {
		f.logger.Error("Failed to issue tokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error: TokenErrorServerError,
		})
		return
	}

	// Store refresh token if offline_access was requested
	if strings.Contains(scope, "offline_access") && client.RefreshTokenLifetime > 0 {
		refreshToken := f.store.GenerateToken()
		refreshExpiry := time.Now().Add(time.Duration(client.RefreshTokenLifetime) * time.Second)

		storedRefresh := &StoredRefreshToken{
			Token:     refreshToken,
			ClientID:  client.ClientID,
			UserID:    storedCode.UserID,
			Scope:     scope,
			ExpiresAt: refreshExpiry,
			CreatedAt: time.Now(),
			Revoked:   false,
		}

		if err := f.store.StoreRefreshToken(ctx, storedRefresh, "", time.Duration(client.RefreshTokenLifetime)*time.Second); err != nil {
			f.logger.Error("Failed to store refresh token", zap.Error(err))
		} else {
			tokens.RefreshToken = refreshToken
		}
	}

	c.JSON(http.StatusOK, tokens)
}

// handleRefreshTokenGrant handles the refresh_token grant type with token rotation
func (f *TokenFlow) handleRefreshTokenGrant(ctx context.Context, c *gin.Context, client *Client, req *TokenRequest) {
	// Validate required parameters
	if req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorInvalidRequest,
			ErrorDescription: "refresh_token is required",
		})
		return
	}

	// Validate client supports refresh_token grant
	if !f.clients.ValidateGrantType(client, "refresh_token") {
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorUnauthorizedClient,
			ErrorDescription: "Client does not support refresh_token grant",
		})
		return
	}

	// Retrieve the refresh token
	storedToken, err := f.store.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) || errors.Is(err, ErrRefreshTokenExpired) {
			c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            TokenErrorInvalidGrant,
				ErrorDescription: "Invalid or expired refresh token",
			})
			return
		}
		if errors.Is(err, ErrTokenInvalidated) {
			// Token was revoked - potentially leaked
			c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            TokenErrorInvalidGrant,
				ErrorDescription: "Refresh token has been revoked",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error: TokenErrorServerError,
		})
		return
	}

	// Verify the token belongs to the authenticated client
	if storedToken.ClientID != client.ClientID {
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorInvalidGrant,
			ErrorDescription: "Refresh token was issued to a different client",
		})
		return
	}

	// Determine scope for new tokens
	scope := storedToken.Scope
	if req.Scope != "" {
		// Ensure requested scope is a subset of original
		if !isScopeSubset(req.Scope, storedToken.Scope) {
			c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            TokenErrorInvalidScope,
				ErrorDescription: "Requested scope exceeds original grant",
			})
			return
		}
		scope = req.Scope
	}

	// Issue new access token
	tokens, err := f.issueTokens(ctx, client, storedToken.UserID, scope, storedToken.FamilyID)
	if err != nil {
		f.logger.Error("Failed to issue tokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error: TokenErrorServerError,
		})
		return
	}

	// Rotate the refresh token (RFC 6819 security best practice)
	newRefreshToken := f.store.GenerateToken()
	refreshExpiry := time.Now().Add(time.Duration(client.RefreshTokenLifetime) * time.Second)

	storedRefresh := &StoredRefreshToken{
		Token:     newRefreshToken,
		ClientID:  client.ClientID,
		UserID:    storedToken.UserID,
		Scope:     scope,
		ExpiresAt: refreshExpiry,
		CreatedAt: time.Now(),
		Revoked:   false,
	}

	// Rotate tokens - this will revoke the old token
	if err := f.store.RotateRefreshToken(ctx, req.RefreshToken, storedRefresh, time.Duration(client.RefreshTokenLifetime)*time.Second); err != nil {
		if errors.Is(err, ErrTokenInvalidated) {
			// Token family was compromised
			c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            TokenErrorInvalidGrant,
				ErrorDescription: "Token has been invalidated due to suspicious activity",
			})
			return
		}
		f.logger.Error("Failed to rotate refresh token", zap.Error(err))
		// Continue without rotation for compatibility
	} else {
		tokens.RefreshToken = newRefreshToken
	}

	c.JSON(http.StatusOK, tokens)
}

// handleClientCredentialsGrant handles the client_credentials grant type
func (f *TokenFlow) handleClientCredentialsGrant(ctx context.Context, c *gin.Context, client *Client, req *TokenRequest) {
	// Validate client supports client_credentials grant
	if !f.clients.ValidateGrantType(client, "client_credentials") {
		c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            TokenErrorUnauthorizedClient,
			ErrorDescription: "Client does not support client_credentials grant",
		})
		return
	}

	// Validate scope if requested
	if req.Scope != "" {
		if !f.clients.ValidateScope(client, req.Scope) {
			c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            TokenErrorInvalidScope,
				ErrorDescription: "Requested scope is not allowed for this client",
			})
			return
		}
	}

	scope := req.Scope
	if scope == "" {
		scope = BuildScopeString(client.Scopes)
	}

	// For client credentials, there's no user - use client_id as subject
	userID := fmt.Sprintf("client:%s", client.ClientID)

	// Issue access token only (no refresh token for client credentials)
	tokens, err := f.issueTokens(ctx, client, userID, scope, "")
	if err != nil {
		f.logger.Error("Failed to issue tokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error: TokenErrorServerError,
		})
		return
	}

	// Client credentials should not return refresh tokens
	tokens.RefreshToken = ""

	c.JSON(http.StatusOK, tokens)
}

// issueTokens creates and returns access token (and optionally ID token)
func (f *TokenFlow) issueTokens(ctx context.Context, client *Client, userID, scope, familyID string) (*TokenResponse, error) {
	now := time.Now()

	// Determine token lifetimes
	accessLifetime := DefaultAccessTokenTTL
	if client.AccessTokenLifetime > 0 {
		accessLifetime = time.Duration(client.AccessTokenLifetime) * time.Second
	}

	// Generate access token
	accessToken := f.store.GenerateToken()
	accessExpiry := now.Add(accessLifetime)

	// Store access token metadata
	accessTokenData := &AccessTokenData{
		Token:     accessToken,
		ClientID:  client.ClientID,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: accessExpiry,
		CreatedAt: now,
	}

	if err := f.store.StoreAccessToken(ctx, accessTokenData, accessLifetime); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// Build token response
	response := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(accessLifetime.Seconds()),
		Scope:       scope,
	}

	// If openid scope is present, generate ID token
	if strings.Contains(scope, "openid") {
		idToken, err := f.generateIDToken(client, userID, scope, accessToken, now, accessLifetime)
		if err != nil {
			f.logger.Error("Failed to generate ID token", zap.Error(err))
		} else {
			response.IDToken = idToken
		}
	}

	return response, nil
}

// generateIDToken creates an OpenID Connect ID Token (JWT)
func (f *TokenFlow) generateIDToken(client *Client, userID, scope, accessToken string, now time.Time, lifetime time.Duration) (string, error) {
	// Build JWT claims
	claims := jwt.MapClaims{
		"iss": f.issuer,                          // Issuer
		"sub": userID,                            // Subject (user identifier)
		"aud": client.ClientID,                   // Audience (client_id)
		"exp": now.Add(lifetime).Unix(),          // Expiration
		"iat": now.Unix(),                        // Issued At
		"auth_time": now.Unix(),                  // Authentication Time
		"jti": f.store.GenerateToken(),           // JWT ID (unique identifier)
	}

	// Add at_hash if access token is present
	if accessToken != "" {
		// at_hash is base64url-encoded first half of SHA-256(access_token)
		atHash := hashHalf(accessToken)
		claims["at_hash"] = atHash
	}

	// Add nonce if present (for authorization code flow)
	// This would come from the stored authorization code

	// Add standard OIDC claims based on scope
	if strings.Contains(scope, "email") {
		// In a real implementation, fetch user email from identity service
		claims["email"] = "user@example.com"
		claims["email_verified"] = true
	}

	if strings.Contains(scope, "profile") {
		// In a real implementation, fetch user profile from identity service
		claims["name"] = "User Name"
		claims["given_name"] = "User"
		claims["family_name"] = "Name"
	}

	// Sign and serialize the JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idToken, err := token.SignedString(f.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return idToken, nil
}

// isScopeSubset checks if requested scope is a subset of allowed scope
func isScopeSubset(requested, allowed string) bool {
	if requested == "" {
		return true
	}
	if allowed == "" {
		return false
	}

	requestedScopes := strings.Split(requested, " ")
	allowedScopes := strings.Split(allowed, " ")

	allowedMap := make(map[string]bool)
	for _, s := range allowedScopes {
		if s != "" {
			allowedMap[s] = true
		}
	}

	for _, req := range requestedScopes {
		if req != "" && !allowedMap[req] {
			return false
		}
	}

	return true
}

// hashHalf computes the first half of a SHA-256 hash (used for at_hash and c_hash)
func hashHalf(data string) string {
	h := jwt.SigningMethodRS256.Hash()
	h.Write([]byte(data))
	hash := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])
}

// GetClientFromStore is a helper to retrieve client by client_id
func (f *TokenFlow) GetClientFromStore(ctx context.Context, clientID string) (*Client, error) {
	return f.clients.GetByClientID(ctx, clientID)
}
