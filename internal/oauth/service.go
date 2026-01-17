// Package oauth provides OAuth 2.0 and OpenID Connect provider functionality
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// OAuthClient represents an OAuth 2.0 client application
type OAuthClient struct {
	ID                  string    `json:"id"`
	ClientID            string    `json:"client_id"`
	ClientSecret        string    `json:"client_secret,omitempty"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	Type                string    `json:"type"` // confidential, public
	RedirectURIs        []string  `json:"redirect_uris"`
	GrantTypes          []string  `json:"grant_types"`
	ResponseTypes       []string  `json:"response_types"`
	Scopes              []string  `json:"scopes"`
	LogoURI             string    `json:"logo_uri,omitempty"`
	PolicyURI           string    `json:"policy_uri,omitempty"`
	TOSUri              string    `json:"tos_uri,omitempty"`
	PKCERequired        bool      `json:"pkce_required"`
	AllowRefreshToken   bool      `json:"allow_refresh_token"`
	AccessTokenLifetime int       `json:"access_token_lifetime"`  // seconds
	RefreshTokenLifetime int      `json:"refresh_token_lifetime"` // seconds
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// AuthorizationCode represents an OAuth authorization code
type AuthorizationCode struct {
	Code              string    `json:"code"`
	ClientID          string    `json:"client_id"`
	UserID            string    `json:"user_id"`
	RedirectURI       string    `json:"redirect_uri"`
	Scope             string    `json:"scope"`
	State             string    `json:"state,omitempty"`
	Nonce             string    `json:"nonce,omitempty"`
	CodeChallenge     string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string  `json:"code_challenge_method,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
	CreatedAt         time.Time `json:"created_at"`
}

// AccessToken represents an OAuth access token
type AccessToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// RefreshToken represents an OAuth refresh token
type RefreshToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// TokenResponse represents an OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// UserInfo represents OIDC UserInfo response
type UserInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

// OIDCDiscovery represents OpenID Connect discovery document
type OIDCDiscovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// JWKS represents JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Service provides OAuth/OIDC operations
type Service struct {
	db         *database.PostgresDB
	redis      *database.RedisClient
	config     *config.Config
	logger     *zap.Logger
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
}

// NewService creates a new OAuth service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) (*Service, error) {
	// Generate RSA key pair for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Use default issuer URL
	issuer := "http://localhost:8006"

	return &Service{
		db:         db,
		redis:      redis,
		config:     cfg,
		logger:     logger.With(zap.String("service", "oauth")),
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		issuer:     issuer,
	}, nil
}

// OAuth Client Management

// CreateClient creates a new OAuth client
func (s *Service) CreateClient(ctx context.Context, client *OAuthClient) error {
	s.logger.Info("Creating OAuth client", zap.String("name", client.Name))

	now := time.Now()
	client.CreatedAt = now
	client.UpdatedAt = now

	// Set defaults
	if client.AccessTokenLifetime == 0 {
		client.AccessTokenLifetime = 3600 // 1 hour
	}
	if client.RefreshTokenLifetime == 0 {
		client.RefreshTokenLifetime = 86400 // 24 hours
	}

	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	grantTypesJSON, _ := json.Marshal(client.GrantTypes)
	responseTypesJSON, _ := json.Marshal(client.ResponseTypes)
	scopesJSON, _ := json.Marshal(client.Scopes)

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_clients (
			id, client_id, client_secret, name, description, type,
			redirect_uris, grant_types, response_types, scopes,
			logo_uri, policy_uri, tos_uri, pkce_required,
			allow_refresh_token, access_token_lifetime, refresh_token_lifetime,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
	`, client.ID, client.ClientID, client.ClientSecret, client.Name, client.Description,
		client.Type, redirectURIsJSON, grantTypesJSON, responseTypesJSON, scopesJSON,
		client.LogoURI, client.PolicyURI, client.TOSUri, client.PKCERequired,
		client.AllowRefreshToken, client.AccessTokenLifetime, client.RefreshTokenLifetime,
		client.CreatedAt, client.UpdatedAt)

	return err
}

// GetClient retrieves an OAuth client by client ID
func (s *Service) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	var client OAuthClient
	var redirectURIsJSON, grantTypesJSON, responseTypesJSON, scopesJSON []byte

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, client_id, client_secret, name, description, type,
		       redirect_uris, grant_types, response_types, scopes,
		       logo_uri, policy_uri, tos_uri, pkce_required,
		       allow_refresh_token, access_token_lifetime, refresh_token_lifetime,
		       created_at, updated_at
		FROM oauth_clients WHERE client_id = $1
	`, clientID).Scan(
		&client.ID, &client.ClientID, &client.ClientSecret, &client.Name, &client.Description,
		&client.Type, &redirectURIsJSON, &grantTypesJSON, &responseTypesJSON, &scopesJSON,
		&client.LogoURI, &client.PolicyURI, &client.TOSUri, &client.PKCERequired,
		&client.AllowRefreshToken, &client.AccessTokenLifetime, &client.RefreshTokenLifetime,
		&client.CreatedAt, &client.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(redirectURIsJSON, &client.RedirectURIs)
	json.Unmarshal(grantTypesJSON, &client.GrantTypes)
	json.Unmarshal(responseTypesJSON, &client.ResponseTypes)
	json.Unmarshal(scopesJSON, &client.Scopes)

	return &client, nil
}

// ListClients retrieves all OAuth clients
func (s *Service) ListClients(ctx context.Context, offset, limit int) ([]OAuthClient, int, error) {
	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM oauth_clients").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, client_id, name, description, type, created_at, updated_at
		FROM oauth_clients
		ORDER BY created_at DESC
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var clients []OAuthClient
	for rows.Next() {
		var c OAuthClient
		if err := rows.Scan(&c.ID, &c.ClientID, &c.Name, &c.Description, &c.Type, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, 0, err
		}
		clients = append(clients, c)
	}

	return clients, total, nil
}

// UpdateClient updates an OAuth client
func (s *Service) UpdateClient(ctx context.Context, clientID string, client *OAuthClient) error {
	s.logger.Info("Updating OAuth client", zap.String("client_id", clientID))

	now := time.Now()
	client.UpdatedAt = now

	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	grantTypesJSON, _ := json.Marshal(client.GrantTypes)
	responseTypesJSON, _ := json.Marshal(client.ResponseTypes)
	scopesJSON, _ := json.Marshal(client.Scopes)

	_, err := s.db.Pool.Exec(ctx, `
		UPDATE oauth_clients
		SET name = $2, description = $3, redirect_uris = $4, grant_types = $5,
		    response_types = $6, scopes = $7, pkce_required = $8,
		    allow_refresh_token = $9, access_token_lifetime = $10,
		    refresh_token_lifetime = $11, updated_at = $12
		WHERE client_id = $1
	`, clientID, client.Name, client.Description, redirectURIsJSON, grantTypesJSON,
		responseTypesJSON, scopesJSON, client.PKCERequired, client.AllowRefreshToken,
		client.AccessTokenLifetime, client.RefreshTokenLifetime, now)

	return err
}

// DeleteClient deletes an OAuth client
func (s *Service) DeleteClient(ctx context.Context, clientID string) error {
	s.logger.Info("Deleting OAuth client", zap.String("client_id", clientID))

	_, err := s.db.Pool.Exec(ctx, "DELETE FROM oauth_clients WHERE client_id = $1", clientID)
	return err
}

// Authorization Flow

// CreateAuthorizationCode creates an authorization code
func (s *Service) CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
	code.ExpiresAt = time.Now().Add(10 * time.Minute)
	code.CreatedAt = time.Now()

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_authorization_codes (
			code, client_id, user_id, redirect_uri, scope, state, nonce,
			code_challenge, code_challenge_method, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, code.Code, code.ClientID, code.UserID, code.RedirectURI, code.Scope,
		code.State, code.Nonce, code.CodeChallenge, code.CodeChallengeMethod,
		code.ExpiresAt, code.CreatedAt)

	return err
}

// GetAuthorizationCode retrieves and validates an authorization code
func (s *Service) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	var authCode AuthorizationCode

	err := s.db.Pool.QueryRow(ctx, `
		SELECT code, client_id, user_id, redirect_uri, scope, state, nonce,
		       code_challenge, code_challenge_method, expires_at, created_at
		FROM oauth_authorization_codes WHERE code = $1
	`, code).Scan(
		&authCode.Code, &authCode.ClientID, &authCode.UserID, &authCode.RedirectURI,
		&authCode.Scope, &authCode.State, &authCode.Nonce, &authCode.CodeChallenge,
		&authCode.CodeChallengeMethod, &authCode.ExpiresAt, &authCode.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Check if expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}

	return &authCode, nil
}

// DeleteAuthorizationCode deletes an authorization code (single use)
func (s *Service) DeleteAuthorizationCode(ctx context.Context, code string) error {
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM oauth_authorization_codes WHERE code = $1", code)
	return err
}

// Token Management

// CreateAccessToken creates a new access token
func (s *Service) CreateAccessToken(ctx context.Context, token *AccessToken) error {
	token.CreatedAt = time.Now()

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_access_tokens (token, client_id, user_id, scope, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, token.Token, token.ClientID, token.UserID, token.Scope, token.ExpiresAt, token.CreatedAt)

	return err
}

// CreateRefreshToken creates a new refresh token
func (s *Service) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	token.CreatedAt = time.Now()

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens (token, client_id, user_id, scope, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, token.Token, token.ClientID, token.UserID, token.Scope, token.ExpiresAt, token.CreatedAt)

	return err
}

// GetRefreshToken retrieves a refresh token
func (s *Service) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	var refreshToken RefreshToken

	err := s.db.Pool.QueryRow(ctx, `
		SELECT token, client_id, user_id, scope, expires_at, created_at
		FROM oauth_refresh_tokens WHERE token = $1
	`, token).Scan(
		&refreshToken.Token, &refreshToken.ClientID, &refreshToken.UserID,
		&refreshToken.Scope, &refreshToken.ExpiresAt, &refreshToken.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expired")
	}

	return &refreshToken, nil
}

// RevokeRefreshToken revokes a refresh token
func (s *Service) RevokeRefreshToken(ctx context.Context, token string) error {
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM oauth_refresh_tokens WHERE token = $1", token)
	return err
}

// JWT Token Generation

// GenerateJWT generates a signed JWT access token
func (s *Service) GenerateJWT(userID, clientID, scope string, expiresIn int) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       userID,
		"client_id": clientID,
		"scope":     scope,
		"iss":       s.issuer,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(expiresIn) * time.Second).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

// GenerateIDToken generates an OIDC ID token
func (s *Service) GenerateIDToken(userID, clientID, nonce string, expiresIn int) (string, error) {
	now := time.Now()

	// Get user info
	var email, firstName, lastName string
	_ = s.db.Pool.QueryRow(context.Background(), `
		SELECT email, first_name, last_name FROM users WHERE id = $1
	`, userID).Scan(&email, &firstName, &lastName)

	name := firstName
	if lastName != "" {
		name = firstName + " " + lastName
	}

	claims := jwt.MapClaims{
		"sub":        userID,
		"aud":        clientID,
		"iss":        s.issuer,
		"iat":        now.Unix(),
		"exp":        now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"email":      email,
		"name":       name,
		"given_name": firstName,
		"family_name": lastName,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

// GetUserInfo retrieves user information for UserInfo endpoint
func (s *Service) GetUserInfo(ctx context.Context, userID string) (*UserInfo, error) {
	var email, firstName, lastName string
	var emailVerified bool

	err := s.db.Pool.QueryRow(ctx, `
		SELECT email, first_name, last_name, email_verified
		FROM users WHERE id = $1
	`, userID).Scan(&email, &firstName, &lastName, &emailVerified)

	if err != nil {
		return nil, err
	}

	name := firstName
	if lastName != "" {
		name = firstName + " " + lastName
	}

	return &UserInfo{
		Sub:           userID,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		GivenName:     firstName,
		FamilyName:    lastName,
		PreferredUsername: email,
	}, nil
}

// Utility Functions

// GenerateRandomToken generates a cryptographically secure random token
func GenerateRandomToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// VerifyPKCE verifies PKCE code challenge
func VerifyPKCE(codeVerifier, codeChallenge, method string) bool {
	if method == "S256" {
		hash := sha256.Sum256([]byte(codeVerifier))
		computed := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
		return computed == codeChallenge
	}
	// Plain method
	return codeVerifier == codeChallenge
}

// HTTP Handlers

// RegisterRoutes registers OAuth/OIDC routes
func RegisterRoutes(router *gin.Engine, svc *Service) {
	// OIDC Discovery
	router.GET("/.well-known/openid-configuration", svc.handleDiscovery)
	router.GET("/.well-known/jwks.json", svc.handleJWKS)

	oauth := router.Group("/oauth")
	{
		// Authorization endpoint
		oauth.GET("/authorize", svc.handleAuthorize)
		oauth.POST("/authorize", svc.handleAuthorizeConsent)

		// Token endpoint
		oauth.POST("/token", svc.handleToken)

		// Token introspection & revocation
		oauth.POST("/introspect", svc.handleIntrospect)
		oauth.POST("/revoke", svc.handleRevoke)

		// UserInfo endpoint
		oauth.GET("/userinfo", svc.handleUserInfo)
		oauth.POST("/userinfo", svc.handleUserInfo)
	}

	// Client management API
	clients := router.Group("/api/v1/oauth/clients")
	{
		clients.GET("", svc.handleListClients)
		clients.POST("", svc.handleCreateClient)
		clients.GET("/:id", svc.handleGetClient)
		clients.PUT("/:id", svc.handleUpdateClient)
		clients.DELETE("/:id", svc.handleDeleteClient)
	}
}

func (s *Service) handleDiscovery(c *gin.Context) {
	discovery := OIDCDiscovery{
		Issuer:                s.issuer,
		AuthorizationEndpoint: s.issuer + "/oauth/authorize",
		TokenEndpoint:         s.issuer + "/oauth/token",
		UserInfoEndpoint:      s.issuer + "/oauth/userinfo",
		JwksURI:               s.issuer + "/.well-known/jwks.json",
		ScopesSupported:       []string{"openid", "profile", "email", "offline_access"},
		ResponseTypesSupported: []string{"code", "id_token", "token id_token", "code id_token"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:  []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		ClaimsSupported: []string{"sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name", "given_name", "family_name"},
		CodeChallengeMethodsSupported: []string{"S256", "plain"},
	}

	c.JSON(200, discovery)
}

func (s *Service) handleJWKS(c *gin.Context) {
	// Convert RSA public key to JWK
	n := base64.URLEncoding.EncodeToString(s.publicKey.N.Bytes())
	e := base64.URLEncoding.EncodeToString([]byte{byte(s.publicKey.E >> 16), byte(s.publicKey.E >> 8), byte(s.publicKey.E)})

	jwks := JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: "openidx-key-1",
				Alg: "RS256",
				N:   n,
				E:   e,
			},
		},
	}

	c.JSON(200, jwks)
}

func (s *Service) handleAuthorize(c *gin.Context) {
	// This would show a consent screen in a real implementation
	// For now, return the parameters needed for consent
	c.JSON(200, gin.H{
		"client_id":             c.Query("client_id"),
		"redirect_uri":          c.Query("redirect_uri"),
		"response_type":         c.Query("response_type"),
		"scope":                 c.Query("scope"),
		"state":                 c.Query("state"),
		"nonce":                 c.Query("nonce"),
		"code_challenge":        c.Query("code_challenge"),
		"code_challenge_method": c.Query("code_challenge_method"),
	})
}

func (s *Service) handleAuthorizeConsent(c *gin.Context) {
	var req struct {
		ClientID            string `json:"client_id"`
		RedirectURI         string `json:"redirect_uri"`
		ResponseType        string `json:"response_type"`
		Scope               string `json:"scope"`
		State               string `json:"state"`
		Nonce               string `json:"nonce"`
		CodeChallenge       string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
		UserID              string `json:"user_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}

	// Generate authorization code
	code := GenerateRandomToken(32)

	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		UserID:              req.UserID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}

	if err := s.CreateAuthorizationCode(c.Request.Context(), authCode); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// Build redirect URL
	redirectURL, _ := url.Parse(req.RedirectURI)
	query := redirectURL.Query()
	query.Set("code", code)
	if req.State != "" {
		query.Set("state", req.State)
	}
	redirectURL.RawQuery = query.Encode()

	c.JSON(200, gin.H{
		"redirect_url": redirectURL.String(),
	})
}

func (s *Service) handleToken(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(c)
	case "refresh_token":
		s.handleRefreshTokenGrant(c)
	case "client_credentials":
		s.handleClientCredentialsGrant(c)
	default:
		c.JSON(400, gin.H{"error": "unsupported_grant_type"})
	}
}

func (s *Service) handleAuthorizationCodeGrant(c *gin.Context) {
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	// Get authorization code
	authCode, err := s.GetAuthorizationCode(c.Request.Context(), code)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	// Verify client
	client, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil || client.ClientSecret != clientSecret {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	// Verify redirect URI
	if authCode.RedirectURI != redirectURI {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	// Verify PKCE if required
	if authCode.CodeChallenge != "" {
		if !VerifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			c.JSON(400, gin.H{"error": "invalid_grant"})
			return
		}
	}

	// Delete authorization code (single use)
	s.DeleteAuthorizationCode(c.Request.Context(), code)

	// Generate tokens
	accessToken, _ := s.GenerateJWT(authCode.UserID, clientID, authCode.Scope, client.AccessTokenLifetime)

	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   client.AccessTokenLifetime,
		Scope:       authCode.Scope,
	}

	// Generate ID token if openid scope is requested
	if strings.Contains(authCode.Scope, "openid") {
		idToken, _ := s.GenerateIDToken(authCode.UserID, clientID, authCode.Nonce, client.AccessTokenLifetime)
		response.IDToken = idToken
	}

	// Generate refresh token if allowed
	if client.AllowRefreshToken && strings.Contains(authCode.Scope, "offline_access") {
		refreshToken := GenerateRandomToken(32)
		s.CreateRefreshToken(c.Request.Context(), &RefreshToken{
			Token:     refreshToken,
			ClientID:  clientID,
			UserID:    authCode.UserID,
			Scope:     authCode.Scope,
			ExpiresAt: time.Now().Add(time.Duration(client.RefreshTokenLifetime) * time.Second),
		})
		response.RefreshToken = refreshToken
	}

	c.JSON(200, response)
}

func (s *Service) handleRefreshTokenGrant(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	// Verify client
	client, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil || client.ClientSecret != clientSecret {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	// Get refresh token
	token, err := s.GetRefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	// Generate new access token
	accessToken, _ := s.GenerateJWT(token.UserID, clientID, token.Scope, client.AccessTokenLifetime)

	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   client.AccessTokenLifetime,
		Scope:       token.Scope,
	}

	c.JSON(200, response)
}

func (s *Service) handleClientCredentialsGrant(c *gin.Context) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	scope := c.PostForm("scope")

	// Verify client
	client, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil || client.ClientSecret != clientSecret {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	// Generate access token (no user context)
	accessToken, _ := s.GenerateJWT("", clientID, scope, client.AccessTokenLifetime)

	c.JSON(200, TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   client.AccessTokenLifetime,
		Scope:       scope,
	})
}

func (s *Service) handleIntrospect(c *gin.Context) {
	// Token introspection endpoint
	c.JSON(200, gin.H{"active": false})
}

func (s *Service) handleRevoke(c *gin.Context) {
	token := c.PostForm("token")

	// Revoke refresh token if it exists
	s.RevokeRefreshToken(c.Request.Context(), token)

	c.JSON(200, gin.H{"status": "revoked"})
}

func (s *Service) handleUserInfo(c *gin.Context) {
	// Extract access token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}

	userID, _ := claims["sub"].(string)

	// Get user info
	userInfo, err := s.GetUserInfo(c.Request.Context(), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	c.JSON(200, userInfo)
}

// Client management handlers

func (s *Service) handleListClients(c *gin.Context) {
	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}

	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	clients, total, err := s.ListClients(c.Request.Context(), offset, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, clients)
}

func (s *Service) handleCreateClient(c *gin.Context) {
	var client OAuthClient
	if err := c.ShouldBindJSON(&client); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Generate client ID and secret
	client.ClientID = "client_" + GenerateRandomToken(16)
	client.ClientSecret = GenerateRandomToken(32)

	if err := s.CreateClient(c.Request.Context(), &client); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, client)
}

func (s *Service) handleGetClient(c *gin.Context) {
	client, err := s.GetClient(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "client not found"})
		return
	}

	// Don't expose client secret in GET
	client.ClientSecret = ""
	c.JSON(200, client)
}

func (s *Service) handleUpdateClient(c *gin.Context) {
	var client OAuthClient
	if err := c.ShouldBindJSON(&client); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateClient(c.Request.Context(), c.Param("id"), &client); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, client)
}

func (s *Service) handleDeleteClient(c *gin.Context) {
	if err := s.DeleteClient(c.Request.Context(), c.Param("id")); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(204, nil)
}
