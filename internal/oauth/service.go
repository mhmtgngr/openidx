// Package oauth provides OAuth 2.0 and OpenID Connect provider functionality
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/risk"
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
	identityService *identity.Service
	riskService     *risk.Service
	webhookService  WebhookPublisher
}

// WebhookPublisher defines the interface for publishing webhook events
type WebhookPublisher interface {
	Publish(ctx context.Context, eventType string, payload interface{}) error
}

// SetRiskService sets the risk service for conditional access
func (s *Service) SetRiskService(rs *risk.Service) {
	s.riskService = rs
}

// SetWebhookService sets the webhook service for event publishing
func (s *Service) SetWebhookService(ws WebhookPublisher) {
	s.webhookService = ws
}

// NewService creates a new OAuth service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger, idSvc *identity.Service) (*Service, error) {
	// Try to load RSA key from database, generate if not found
	var privateKey *rsa.PrivateKey
	var keyPEMStr string
	err := db.Pool.QueryRow(context.Background(),
		"SELECT value::text FROM system_settings WHERE key = 'oauth_rsa_private_key'").Scan(&keyPEMStr)
	if err == nil && len(keyPEMStr) > 0 {
		// value is stored as a JSON string, strip quotes
		keyPEMStr = strings.Trim(keyPEMStr, "\"")
		keyPEMStr = strings.ReplaceAll(keyPEMStr, "\\n", "\n")
		block, _ := pem.Decode([]byte(keyPEMStr))
		if block != nil {
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				logger.Warn("Failed to parse stored RSA key, generating new one", zap.Error(err))
				privateKey = nil
			}
		}
	}
	if privateKey == nil {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		// Store the key as JSON string in jsonb column
		keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
		pemBytes := pem.EncodeToMemory(keyBlock)
		pemJSON, _ := json.Marshal(string(pemBytes))
		db.Pool.Exec(context.Background(),
			"INSERT INTO system_settings (key, value) VALUES ('oauth_rsa_private_key', $1::jsonb) ON CONFLICT (key) DO UPDATE SET value = $1::jsonb",
			string(pemJSON))
		logger.Info("RSA signing key generated and persisted to database")
	} else {
		logger.Info("RSA signing key loaded from database")
	}

	// Use configured issuer URL or fall back to default
	issuer := cfg.OAuthIssuer
	if issuer == "" {
		issuer = "http://localhost:8006"
	}

	return &Service{
		db:         db,
		redis:      redis,
		config:     cfg,
		logger:     logger.With(zap.String("service", "oauth")),
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		issuer:     issuer,
		identityService: idSvc,
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
	// Use pointers to handle NULL values
	var clientSecret, description, logoURI, policyURI, tosURI *string
	var redirectURIsJSON, grantTypesJSON, responseTypesJSON, scopesJSON []byte

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, client_id, client_secret, name, description, type,
		       redirect_uris, grant_types, response_types, scopes,
		       logo_uri, policy_uri, tos_uri, pkce_required,
		       allow_refresh_token, access_token_lifetime, refresh_token_lifetime,
		       created_at, updated_at
		FROM oauth_clients WHERE client_id = $1
	`, clientID).Scan(
		&client.ID, &client.ClientID, &clientSecret, &client.Name, &description,
		&client.Type, &redirectURIsJSON, &grantTypesJSON, &responseTypesJSON, &scopesJSON,
		&logoURI, &policyURI, &tosURI, &client.PKCERequired,
		&client.AllowRefreshToken, &client.AccessTokenLifetime, &client.RefreshTokenLifetime,
		&client.CreatedAt, &client.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle NULL values
	if clientSecret != nil {
		client.ClientSecret = *clientSecret
	}
	if description != nil {
		client.Description = *description
	}
	if logoURI != nil {
		client.LogoURI = *logoURI
	}
	if policyURI != nil {
		client.PolicyURI = *policyURI
	}
	if tosURI != nil {
		client.TOSUri = *tosURI
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
		var desc *string
		if err := rows.Scan(&c.ID, &c.ClientID, &c.Name, &desc, &c.Type, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, 0, err
		}
		if desc != nil {
			c.Description = *desc
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
func (s *Service) GenerateJWT(ctx context.Context, userID, clientID, scope string, expiresIn int) (string, error) {
	now := time.Now()

	// Get user info for access token
	var email, firstName, lastName string
	if userID != "" {
		_ = s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(email, ''), COALESCE(first_name, ''), COALESCE(last_name, '')
			FROM users WHERE id = $1
		`, userID).Scan(&email, &firstName, &lastName)
	}

	name := firstName
	if lastName != "" {
		name = firstName + " " + lastName
	}

	// Get user roles (initialize as empty slice so JSON serializes as [] not null)
	roleNames := make([]string, 0)
	if userID != "" {
		rows, err := s.db.Pool.Query(ctx, `
			SELECT r.name
			FROM roles r
			JOIN user_roles ur ON r.id = ur.role_id
			WHERE ur.user_id = $1
		`, userID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var roleName string
				if err := rows.Scan(&roleName); err == nil {
					roleNames = append(roleNames, roleName)
				}
			}
		}
	}

	claims := jwt.MapClaims{
		"sub":       userID,
		"aud":       clientID,
		"client_id": clientID,
		"scope":     scope,
		"iss":       s.issuer,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"email":     email,
		"name":      name,
		"roles":     roleNames,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "openidx-key-1"
	return token.SignedString(s.privateKey)
}

// GenerateIDToken generates an OIDC ID token
func (s *Service) GenerateIDToken(ctx context.Context, userID, clientID, nonce string, expiresIn int) (string, error) {
	now := time.Now()

	// Get user info
	var email, firstName, lastName string
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT email, first_name, last_name FROM users WHERE id = $1
	`, userID).Scan(&email, &firstName, &lastName)

	name := firstName
	if lastName != "" {
		name = firstName + " " + lastName
	}

	// Get user roles (initialize as empty slice so JSON serializes as [] not null)
	roleNames := make([]string, 0)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`, userID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var roleName string
			if err := rows.Scan(&roleName); err == nil {
				roleNames = append(roleNames, roleName)
			}
		}
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
		"roles":      roleNames,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "openidx-key-1"
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

// RegisterRoutes registers OAuth/OIDC routes.
// authMiddleware is optional; when provided it protects the client management API and consent endpoint.
func RegisterRoutes(router *gin.Engine, svc *Service, authMiddleware ...gin.HandlerFunc) {
	// OIDC Discovery - include OPTIONS for CORS preflight (required for BrowZer and browser-based OIDC clients)
	router.GET("/.well-known/openid-configuration", svc.handleDiscovery)
	router.OPTIONS("/.well-known/openid-configuration", svc.handleDiscovery)
	router.GET("/.well-known/jwks.json", svc.handleJWKS)
	router.OPTIONS("/.well-known/jwks.json", svc.handleJWKS)

	oauth := router.Group("/oauth")
	{
		// Authorization endpoint
		oauth.GET("/authorize", svc.handleAuthorize)

		// Consent endpoint (requires authentication)
		if len(authMiddleware) > 0 {
			oauth.POST("/authorize", append(authMiddleware, svc.handleAuthorizeConsent)...)
		} else {
			oauth.POST("/authorize", svc.handleAuthorizeConsent)
		}

		// Server-rendered login form callback (for standard OIDC clients)
		oauth.POST("/authorize/callback", svc.handleAuthorizeCallback)

		// Login endpoint for direct authentication (SPA flow)
		oauth.POST("/login", svc.handleLogin)

		// MFA verification endpoint
		oauth.POST("/mfa-verify", svc.handleMFAVerify)

		// Step-up MFA endpoints (mid-session re-auth)
		oauth.POST("/stepup-challenge", svc.handleStepUpChallenge)
		oauth.POST("/stepup-verify", svc.handleStepUpVerify)

		// SSO callback endpoint
		oauth.GET("/callback", svc.handleCallback)

		// Token endpoint (with OPTIONS for CORS preflight)
		oauth.POST("/token", svc.handleToken)
		oauth.OPTIONS("/token", svc.handleToken)

		// Token introspection & revocation
		oauth.POST("/introspect", svc.handleIntrospect)
		oauth.POST("/revoke", svc.handleRevoke)

		// UserInfo endpoint (with OPTIONS for CORS preflight)
		oauth.GET("/userinfo", svc.handleUserInfo)
		oauth.POST("/userinfo", svc.handleUserInfo)
		oauth.OPTIONS("/userinfo", svc.handleUserInfo)
	}

	// Client management API (protected by auth middleware when available)
	clients := router.Group("/api/v1/oauth/clients")
	if len(authMiddleware) > 0 {
		clients.Use(authMiddleware...)
	}
	{
		clients.GET("", svc.handleListClients)
		clients.POST("", svc.handleCreateClient)
		clients.GET("/:id", svc.handleGetClient)
		clients.PUT("/:id", svc.handleUpdateClient)
		clients.DELETE("/:id", svc.handleDeleteClient)
		clients.POST("/:id/regenerate-secret", svc.handleRegenerateClientSecret)
	}

	// SAML Service Provider endpoints
	svc.RegisterSAMLRoutes(router)
}

func (s *Service) handleDiscovery(c *gin.Context) {
	// CORS headers for BrowZer and other browser-based clients
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
	c.Header("Cache-Control", "public, max-age=3600")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

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
	// CORS headers for BrowZer and other browser-based clients
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
	c.Header("Cache-Control", "public, max-age=3600")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	// Convert RSA public key to JWK (base64url without padding per RFC 7517)
	n := base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{byte(s.publicKey.E >> 16), byte(s.publicKey.E >> 8), byte(s.publicKey.E)})

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
	idpHint := c.Query("idp_hint")

	if idpHint != "" {
		// SSO flow with external IdP
		s.handleSSOAuthorize(c, idpHint)
		return
	}

	// Direct OpenIDX login flow
	// Store OAuth parameters in Redis and redirect to login page
	loginSession := GenerateRandomToken(32)
	oauthParams := map[string]string{
		"client_id":             c.Query("client_id"),
		"redirect_uri":          c.Query("redirect_uri"),
		"response_type":         c.Query("response_type"),
		"scope":                 c.Query("scope"),
		"state":                 c.Query("state"),
		"nonce":                 c.Query("nonce"),
		"code_challenge":        c.Query("code_challenge"),
		"code_challenge_method": c.Query("code_challenge_method"),
	}
	// Validate redirect_uri against registered client
	clientID := oauthParams["client_id"]
	var client *OAuthClient
	if clientID != "" {
		var err error
		client, err = s.GetClient(c.Request.Context(), clientID)
		if err != nil {
			c.JSON(400, gin.H{"error": "invalid_client"})
			return
		}
		validRedirect := false
		for _, uri := range client.RedirectURIs {
			if uri == oauthParams["redirect_uri"] {
				validRedirect = true
				break
			}
		}
		if !validRedirect {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": "redirect_uri not registered for client"})
			return
		}
	}

	paramsJSON, _ := json.Marshal(oauthParams)
	s.redis.Client.Set(c.Request.Context(), "login_session:"+loginSession, string(paramsJSON), 10*time.Minute)

	// For public OIDC clients (like BrowZer), serve a server-rendered login page
	// instead of redirecting back to the client with login_session
	if client != nil && client.Type == "public" && c.GetHeader("Accept") != "application/json" {
		s.renderLoginPage(c, loginSession, "")
		return
	}

	// SPA flow: redirect back to the client's login page with the login_session parameter
	redirectURI := oauthParams["redirect_uri"]
	if redirectURI == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "redirect_uri is required"})
		return
	}

	// Parse redirect URI to add login_session parameter
	loginURL, err := url.Parse(redirectURI)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid redirect_uri"})
		return
	}
	query := loginURL.Query()
	query.Set("login_session", loginSession)
	loginURL.RawQuery = query.Encode()

	c.Redirect(302, loginURL.String())
}

// renderLoginPage serves a minimal HTML login form for standard OIDC clients
func (s *Service) renderLoginPage(c *gin.Context, loginSession, errorMsg string) {
	errHTML := ""
	if errorMsg != "" {
		errHTML = `<div style="color:#ef4444;background:#fef2f2;border:1px solid #fecaca;padding:12px;border-radius:8px;margin-bottom:16px;font-size:14px">` + errorMsg + `</div>`
	}
	html := `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In — OpenIDX</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:40px;width:100%;max-width:400px;box-shadow:0 25px 50px rgba(0,0,0,.25)}
h1{font-size:24px;font-weight:700;margin-bottom:8px;color:#f8fafc}
.sub{color:#94a3b8;margin-bottom:24px;font-size:14px}
label{display:block;font-size:13px;font-weight:500;color:#94a3b8;margin-bottom:6px}
input{width:100%;padding:10px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#f8fafc;font-size:15px;outline:none;transition:border .2s}
input:focus{border-color:#3b82f6}
.field{margin-bottom:16px}
button{width:100%;padding:12px;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
button:hover{background:#2563eb}
</style></head><body>
<div class="card">
<h1>Sign In</h1>
<p class="sub">OpenIDX Zero Trust Platform</p>
` + errHTML + `
<form method="POST" action="/oauth/authorize/callback">
<input type="hidden" name="login_session" value="` + loginSession + `">
<div class="field"><label>Username</label><input type="text" name="username" required autofocus></div>
<div class="field"><label>Password</label><input type="password" name="password" required></div>
<button type="submit">Sign In</button>
</form>
</div></body></html>`
	c.Data(200, "text/html; charset=utf-8", []byte(html))
}

// handleAuthorizeCallback handles the server-rendered login form submission for standard OIDC clients
func (s *Service) handleAuthorizeCallback(c *gin.Context) {
	loginSession := c.PostForm("login_session")
	username := c.PostForm("username")
	password := c.PostForm("password")

	if loginSession == "" || username == "" || password == "" {
		s.renderLoginPage(c, loginSession, "All fields are required.")
		return
	}

	// Get OAuth parameters from Redis
	paramsJSON, err := s.redis.Client.Get(c.Request.Context(), "login_session:"+loginSession).Result()
	if err != nil {
		s.renderLoginPage(c, loginSession, "Login session expired. Please try again.")
		return
	}

	var oauthParams map[string]string
	if err := json.Unmarshal([]byte(paramsJSON), &oauthParams); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// Authenticate user
	user, err := s.identityService.AuthenticateUser(c.Request.Context(), username, password)
	if err != nil {
		errorMsg := "Invalid username or password."
		if err.Error() == "account is locked" {
			errorMsg = "Account is locked. Please try again later."
		} else if err.Error() == "account is disabled" {
			errorMsg = "Account is disabled. Contact your administrator."
		}
		s.renderLoginPage(c, loginSession, errorMsg)
		return
	}

	// Clean up login session
	s.redis.Client.Del(c.Request.Context(), "login_session:"+loginSession)

	// Generate authorization code
	code := GenerateRandomToken(32)
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            oauthParams["client_id"],
		UserID:              user.ID,
		RedirectURI:         oauthParams["redirect_uri"],
		Scope:               oauthParams["scope"],
		State:               oauthParams["state"],
		Nonce:               oauthParams["nonce"],
		CodeChallenge:       oauthParams["code_challenge"],
		CodeChallengeMethod: oauthParams["code_challenge_method"],
	}

	if err := s.CreateAuthorizationCode(c.Request.Context(), authCode); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// 302 redirect to client with auth code (standard OIDC flow)
	redirectURL, _ := url.Parse(oauthParams["redirect_uri"])
	query := redirectURL.Query()
	query.Set("code", code)
	if oauthParams["state"] != "" {
		query.Set("state", oauthParams["state"])
	}
	redirectURL.RawQuery = query.Encode()

	c.Redirect(302, redirectURL.String())
}

// handleLogin handles username/password login for direct OpenIDX authentication
func (s *Service) handleLogin(c *gin.Context) {
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		LoginSession string `json:"login_session"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}

	// Validate login session
	if req.LoginSession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "login_session is required"})
		return
	}

	// Get OAuth parameters from Redis
	paramsJSON, err := s.redis.Client.Get(c.Request.Context(), "login_session:"+req.LoginSession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired login session"})
		return
	}

	var oauthParams map[string]string
	if err := json.Unmarshal([]byte(paramsJSON), &oauthParams); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// Authenticate user
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	user, err := s.identityService.AuthenticateUser(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		// Log failed login audit event
		go s.logAuditEvent(context.Background(), "authentication", "security", "login_failed", "failure",
			req.Username, clientIP, "", "user",
			map[string]interface{}{"reason": err.Error(), "user_agent": userAgent})

		// Return appropriate error message
		errorMsg := "Invalid username or password"
		if err.Error() == "account is locked" {
			errorMsg = "Account is locked. Please try again later."
		} else if err.Error() == "account is disabled" {
			errorMsg = "Account is disabled. Please contact your administrator."
		}
		c.JSON(401, gin.H{"error": "invalid_credentials", "error_description": errorMsg})
		return
	}

	// Log successful login audit event
	go s.logAuditEvent(context.Background(), "authentication", "security", "login", "success",
		user.ID, clientIP, user.ID, "user",
		map[string]interface{}{"username": user.Username, "email": user.Email, "user_agent": userAgent})

	// Risk assessment (conditional access)
	var riskScore int
	var riskFactors []string
	var fingerprint, location string
	var deviceTrusted bool
	authMethods := []string{"password"}

	if s.riskService != nil {
		fingerprint = s.riskService.ComputeDeviceFingerprint(clientIP, userAgent)

		// Geo-IP lookup
		geo, _ := s.riskService.GeoIPLookup(c.Request.Context(), clientIP)
		var lat, lon float64
		if geo != nil {
			location = geo.City + ", " + geo.Country
			lat = geo.Lat
			lon = geo.Lon
		}

		// Register device
		_, _, _ = s.riskService.RegisterDevice(c.Request.Context(), user.ID, fingerprint, clientIP, userAgent, location)

		// Check device trust
		deviceTrusted = s.riskService.IsDeviceTrusted(c.Request.Context(), user.ID, fingerprint)

		// Calculate risk score
		riskScore, riskFactors = s.riskService.CalculateRiskScore(c.Request.Context(), user.ID, clientIP, userAgent, fingerprint, location, lat, lon)

		// Record login
		s.riskService.RecordLogin(c.Request.Context(), user.ID, clientIP, userAgent, location, lat, lon, fingerprint, true, authMethods, riskScore)

		s.logger.Info("Login risk assessment",
			zap.String("user_id", user.ID),
			zap.Int("risk_score", riskScore),
			zap.Strings("factors", riskFactors),
			zap.Bool("device_trusted", deviceTrusted),
			zap.String("location", location),
		)

		// Publish webhook event for login
		if s.webhookService != nil {
			eventType := "login.success"
			if riskScore >= 70 {
				eventType = "login.high_risk"
			}
			s.webhookService.Publish(c.Request.Context(), eventType, map[string]interface{}{
				"user_id": user.ID, "ip": clientIP, "location": location,
				"risk_score": riskScore, "device_trusted": deviceTrusted,
			})
		}
	}

	// Check if user has MFA enabled and get available methods
	totpStatus, _ := s.identityService.GetTOTPStatus(c.Request.Context(), user.ID)
	mfaEnabled := totpStatus != nil && totpStatus.Enabled

	// Gather available MFA methods
	var availableMFAMethods []string
	if totpStatus != nil && totpStatus.Enabled {
		availableMFAMethods = append(availableMFAMethods, "totp")
	}
	// Check for backup codes
	backupCount, _ := s.identityService.GetBackupCodeCount(c.Request.Context(), user.ID)
	if backupCount > 0 {
		availableMFAMethods = append(availableMFAMethods, "backup")
	}
	// Check for active bypass codes (admin-generated)
	hasActiveBypass, _ := s.identityService.HasActiveBypassCode(c.Request.Context(), user.ID)
	if hasActiveBypass {
		availableMFAMethods = append(availableMFAMethods, "bypass")
	}
	// Check for WebAuthn credentials
	webauthnCreds, _ := s.identityService.GetWebAuthnCredentials(c.Request.Context(), user.ID)
	if len(webauthnCreds) > 0 {
		availableMFAMethods = append(availableMFAMethods, "webauthn")
	}
	// Check for push MFA devices
	pushDevices, _ := s.identityService.GetPushDevices(c.Request.Context(), user.ID)
	if len(pushDevices) > 0 {
		availableMFAMethods = append(availableMFAMethods, "push")
	}

	// Check for trusted browser — skip MFA if browser is trusted
	var browserTrusted bool
	if fingerprint != "" && s.identityService != nil {
		tb, _ := s.identityService.IsTrustedBrowser(c.Request.Context(), user.ID, fingerprint)
		browserTrusted = tb != nil
	}

	// Force MFA if risk score is high (>= 70) and MFA is available, unless browser is trusted
	forceMFA := riskScore >= 70 && mfaEnabled && !browserTrusted

	// Skip MFA if browser is trusted (unless high risk)
	skipMFA := browserTrusted && riskScore < 70

	if mfaEnabled && !skipMFA && (forceMFA || (totpStatus != nil && totpStatus.Enabled)) {
		// MFA required — store partial auth in Redis and return MFA challenge
		mfaSession := GenerateRandomToken(32)
		mfaData := map[string]string{
			"user_id":     user.ID,
			"risk_score":  fmt.Sprintf("%d", riskScore),
			"fingerprint": fingerprint,
			"location":    location,
		}
		for k, v := range oauthParams {
			mfaData[k] = v
		}
		mfaDataJSON, _ := json.Marshal(mfaData)
		s.redis.Client.Set(c.Request.Context(), "mfa_session:"+mfaSession, string(mfaDataJSON), 5*time.Minute)

		// Delete the login session from Redis (password step is done)
		s.redis.Client.Del(c.Request.Context(), "login_session:"+req.LoginSession)

		c.JSON(200, gin.H{
			"mfa_required":   true,
			"mfa_session":    mfaSession,
			"mfa_methods":    availableMFAMethods,
			"risk_score":     riskScore,
			"risk_factors":   riskFactors,
			"device_trusted": deviceTrusted,
			"can_trust_browser": !browserTrusted, // Offer to trust if not already trusted
		})
		return
	}

	// Log if MFA was skipped due to trusted browser
	if skipMFA && mfaEnabled {
		s.logger.Info("MFA skipped due to trusted browser",
			zap.String("user_id", user.ID),
			zap.String("fingerprint", fingerprint),
		)
		go s.logAuditEvent(context.Background(), "authentication", "security", "mfa_skipped", "success",
			user.ID, clientIP, user.ID, "user",
			map[string]interface{}{"reason": "trusted_browser", "fingerprint": fingerprint})
	}

	// High risk but no MFA available — deny access
	if riskScore >= 70 && !mfaEnabled {
		s.logger.Warn("High risk login denied — no MFA available",
			zap.String("user_id", user.ID),
			zap.Int("risk_score", riskScore),
		)
		c.JSON(403, gin.H{
			"error":             "high_risk_login",
			"error_description": "Login from an unrecognized device or location. Please enable MFA to continue.",
			"risk_score":        riskScore,
			"risk_factors":      riskFactors,
		})
		return
	}

	// No MFA required — proceed with authorization code
	s.redis.Client.Del(c.Request.Context(), "login_session:"+req.LoginSession)
	s.issueAuthorizationCode(c, oauthParams, user.ID)
}

// issueAuthorizationCode generates an auth code and returns the redirect URL
func (s *Service) issueAuthorizationCode(c *gin.Context, oauthParams map[string]string, userID string) {
	code := GenerateRandomToken(32)
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            oauthParams["client_id"],
		UserID:              userID,
		RedirectURI:         oauthParams["redirect_uri"],
		Scope:               oauthParams["scope"],
		State:               oauthParams["state"],
		Nonce:               oauthParams["nonce"],
		CodeChallenge:       oauthParams["code_challenge"],
		CodeChallengeMethod: oauthParams["code_challenge_method"],
	}

	if err := s.CreateAuthorizationCode(c.Request.Context(), authCode); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	redirectURL, _ := url.Parse(oauthParams["redirect_uri"])
	query := redirectURL.Query()
	query.Set("code", code)
	if oauthParams["state"] != "" {
		query.Set("state", oauthParams["state"])
	}
	redirectURL.RawQuery = query.Encode()

	c.JSON(200, gin.H{
		"redirect_url": redirectURL.String(),
	})
}

// handleMFAVerify handles MFA verification after password authentication
// Supports TOTP, backup codes, bypass codes, and trusted browser option
func (s *Service) handleMFAVerify(c *gin.Context) {
	var req struct {
		MFASession   string `json:"mfa_session"`
		Code         string `json:"code"`
		Method       string `json:"method"`        // "totp", "backup", "bypass"
		TrustBrowser bool   `json:"trust_browser"` // Request to trust this browser
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}

	if req.MFASession == "" || req.Code == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "mfa_session and code are required"})
		return
	}

	// Default method is TOTP
	if req.Method == "" {
		req.Method = "totp"
	}

	// Retrieve MFA session from Redis
	mfaDataJSON, err := s.redis.Client.Get(c.Request.Context(), "mfa_session:"+req.MFASession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired MFA session"})
		return
	}

	var mfaData map[string]string
	if err := json.Unmarshal([]byte(mfaDataJSON), &mfaData); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	userID := mfaData["user_id"]
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	var valid bool
	var verifyErr error

	switch req.Method {
	case "totp":
		// Verify TOTP code
		valid, verifyErr = s.identityService.VerifyTOTP(c.Request.Context(), userID, req.Code)

	case "backup":
		// Verify backup code
		valid, verifyErr = s.identityService.VerifyBackupCode(c.Request.Context(), userID, req.Code)

	case "bypass":
		// Verify admin-generated bypass code
		valid, verifyErr = s.identityService.VerifyBypassCode(c.Request.Context(), userID, req.Code, clientIP, userAgent)

	default:
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "unsupported MFA method"})
		return
	}

	if verifyErr != nil || !valid {
		// Log failed MFA attempt
		go s.logAuditEvent(context.Background(), "authentication", "security", "mfa_failed", "failure",
			userID, clientIP, userID, "user",
			map[string]interface{}{"method": req.Method, "error": verifyErr})

		c.JSON(401, gin.H{"error": "invalid_mfa_code", "error_description": "Invalid verification code"})
		return
	}

	// MFA verified — delete session
	s.redis.Client.Del(c.Request.Context(), "mfa_session:"+req.MFASession)

	// Log MFA verification audit event
	go s.logAuditEvent(context.Background(), "authentication", "security", "mfa_verified", "success",
		userID, clientIP, userID, "user",
		map[string]interface{}{"method": req.Method, "trust_browser": req.TrustBrowser})

	// Handle trusted browser request
	var trustedBrowserID string
	if req.TrustBrowser {
		browserHash := ""
		if s.riskService != nil {
			browserHash = s.riskService.ComputeDeviceFingerprint(clientIP, userAgent)
		}
		browserName := parseBrowserNameFromUA(userAgent)

		tb, err := s.identityService.TrustBrowser(c.Request.Context(), userID, browserHash, browserName, clientIP, userAgent)
		if err == nil && tb != nil {
			trustedBrowserID = tb.ID
			s.logger.Info("Browser trusted after MFA",
				zap.String("user_id", userID),
				zap.String("browser_id", tb.ID))
		}
	}

	oauthParams := make(map[string]string)
	for k, v := range mfaData {
		if k != "user_id" && k != "risk_score" && k != "fingerprint" && k != "location" {
			oauthParams[k] = v
		}
	}

	// Issue authorization code with optional trusted browser info
	s.issueAuthorizationCodeWithTrust(c, oauthParams, userID, trustedBrowserID)
}

// issueAuthorizationCodeWithTrust issues auth code and includes trusted browser info
func (s *Service) issueAuthorizationCodeWithTrust(c *gin.Context, params map[string]string, userID, trustedBrowserID string) {
	// Generate authorization code
	authCode := GenerateRandomToken(32)

	// Store code in Redis with user info
	codeData := map[string]string{
		"user_id":      userID,
		"client_id":    params["client_id"],
		"redirect_uri": params["redirect_uri"],
		"scope":        params["scope"],
		"nonce":        params["nonce"],
	}
	if params["code_challenge"] != "" {
		codeData["code_challenge"] = params["code_challenge"]
		codeData["code_challenge_method"] = params["code_challenge_method"]
	}

	codeDataJSON, _ := json.Marshal(codeData)
	s.redis.Client.Set(c.Request.Context(), "auth_code:"+authCode, string(codeDataJSON), 10*time.Minute)

	response := gin.H{
		"code":  authCode,
		"state": params["state"],
	}

	if trustedBrowserID != "" {
		response["trusted_browser_id"] = trustedBrowserID
	}

	c.JSON(200, response)
}

// parseBrowserNameFromUA extracts browser name from user agent
func parseBrowserNameFromUA(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "edg"):
		return "Microsoft Edge"
	case strings.Contains(ua, "chrome"):
		return "Google Chrome"
	case strings.Contains(ua, "firefox"):
		return "Mozilla Firefox"
	case strings.Contains(ua, "safari"):
		return "Apple Safari"
	default:
		return "Unknown Browser"
	}
}

func (s *Service) handleSSOAuthorize(c *gin.Context, idpID string) {
	// 1. Get IdP from identity service
	idp, err := s.identityService.GetIdentityProvider(c.Request.Context(), idpID)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_idp"})
		return
	}

	// 2. Store original request parameters in Redis
	state := GenerateRandomToken(32)
	originalParams := map[string]string{
		"client_id":       c.Query("client_id"),
		"redirect_uri":    c.Query("redirect_uri"),
		"response_type":   c.Query("response_type"),
		"scope":           c.Query("scope"),
		"state":           c.Query("state"),
		"nonce":           c.Query("nonce"),
		"code_challenge":  c.Query("code_challenge"),
		"code_challenge_method": c.Query("code_challenge_method"),
	}
	paramsJSON, _ := json.Marshal(originalParams)
	s.redis.Client.Set(c.Request.Context(), "sso_state:"+state, string(paramsJSON), 10*time.Minute)

	// 3. Build external IdP authorization URL
	authURL, _ := url.Parse(idp.IssuerURL + "/protocol/openid-connect/auth")
	query := authURL.Query()
	query.Set("client_id", idp.ClientID)
	query.Set("redirect_uri", s.issuer+"/oauth/callback")
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(idp.Scopes, " "))
	query.Set("state", state)
	authURL.RawQuery = query.Encode()

	// 4. Redirect user to external IdP
	c.Redirect(302, authURL.String())
}

func (s *Service) handleCallback(c *gin.Context) {
	// 1. Get state and code from callback request
	state := c.Query("state")
	code := c.Query("code")

	// 2. Retrieve original request parameters from Redis
	paramsJSON, err := s.redis.Client.Get(c.Request.Context(), "sso_state:"+state).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_state"})
		return
	}
	var originalParams map[string]string
	json.Unmarshal([]byte(paramsJSON), &originalParams)

	// 3. Get IdP from identity service (we need to store idp_id in the state)
	// For now, let's assume we have only one IdP for simplicity
	idps, _, err := s.identityService.ListIdentityProviders(c.Request.Context(), 0, 1)
	if err != nil || len(idps) == 0 {
		c.JSON(500, gin.H{"error": "no identity provider configured"})
		return
	}
	idp := idps[0]

	// 4. Exchange code for tokens
	oauth2Config := &oauth2.Config{
		ClientID:     idp.ClientID,
		ClientSecret: idp.ClientSecret,
		RedirectURL:  s.issuer + "/oauth/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  idp.IssuerURL + "/protocol/openid-connect/auth",
			TokenURL: idp.IssuerURL + "/protocol/openid-connect/token",
		},
		Scopes: idp.Scopes,
	}
	token, err := oauth2Config.Exchange(c.Request.Context(), code)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to exchange token"})
		return
	}

	// 5. a new user is created with the information from the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.JSON(500, gin.H{"error": "id_token not found"})
		return
	}

	// 6. JIT Provisioning & Session Management
	// For simplicity, we'll just create a new user and a new session, and then generate a new authorization code
	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
		Name  string `json:"name"`
	}
	// Verify the ID token signature using the IdP's JWKS
	verifiedToken, err := jwt.Parse(rawIDToken, func(t *jwt.Token) (interface{}, error) {
		// Fetch JWKS from the IdP
		jwksURL := idp.IssuerURL + "/protocol/openid-connect/certs"
		return middleware.FetchJWKS(jwksURL, t)
	})
	if err != nil {
		s.logger.Error("Failed to verify ID token", zap.Error(err))
		c.JSON(401, gin.H{"error": "invalid_id_token", "error_description": "ID token signature verification failed"})
		return
	}
	if mapClaims, ok := verifiedToken.Claims.(jwt.MapClaims); ok {
		if email, ok := mapClaims["email"].(string); ok {
			claims.Email = email
		}
		if sub, ok := mapClaims["sub"].(string); ok {
			claims.Sub = sub
		}
		if name, ok := mapClaims["name"].(string); ok {
			claims.Name = name
		}
	}

	if claims.Email == "" {
		c.JSON(400, gin.H{"error": "invalid_claims", "error_description": "email claim is required"})
		return
	}

	// Check if user already exists (JIT provisioning)
	existingUsers, _, _ := s.identityService.ListUsers(c.Request.Context(), 0, 1, claims.Email)
	var user *identity.User
	if len(existingUsers) > 0 {
		user = &existingUsers[0]
	} else {
		user = &identity.User{
			Username:      claims.Email,
			Email:         claims.Email,
			FirstName:     claims.Name,
			Enabled:       true,
			EmailVerified: true,
		}
		if err := s.identityService.CreateUser(c.Request.Context(), user); err != nil {
			s.logger.Error("Failed to create SSO user", zap.Error(err))
			c.JSON(500, gin.H{"error": "failed to provision user"})
			return
		}
	}

	authCode := &AuthorizationCode{
		Code:        GenerateRandomToken(32),
		ClientID:    originalParams["client_id"],
		UserID:      user.ID,
		RedirectURI: originalParams["redirect_uri"],
		Scope:       originalParams["scope"],
		State:       originalParams["state"],
		Nonce:       originalParams["nonce"],
	}
	s.CreateAuthorizationCode(c.Request.Context(), authCode)

	// 7. Redirect back to the original client
	redirectURL, _ := url.Parse(originalParams["redirect_uri"])
	query := redirectURL.Query()
	query.Set("code", authCode.Code)
	if authCode.State != "" {
		query.Set("state", authCode.State)
	}
	redirectURL.RawQuery = query.Encode()

	c.Redirect(302, redirectURL.String())
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
	// CORS headers for BrowZer and other browser-based clients
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

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

	s.logger.Debug("Token request received",
		zap.String("client_id", clientID),
		zap.String("redirect_uri", redirectURI),
		zap.Bool("has_code", code != ""),
		zap.Bool("has_verifier", codeVerifier != ""))

	// Get authorization code
	authCode, err := s.GetAuthorizationCode(c.Request.Context(), code)
	if err != nil {
		s.logger.Debug("Failed to get authorization code", zap.Error(err))
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	// Verify client
	client, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil {
		s.logger.Debug("Failed to get client", zap.String("client_id", clientID), zap.Error(err))
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	// For confidential clients, verify client_secret
	// For public clients, skip secret verification (use PKCE instead)
	if client.Type == "confidential" && subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	// Verify redirect URI
	if authCode.RedirectURI != redirectURI {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	// Verify PKCE - required for public clients, optional for confidential
	if authCode.CodeChallenge != "" {
		if !VerifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
	} else if client.Type == "public" {
		// Public clients MUST use PKCE
		c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "PKCE required for public clients"})
		return
	}

	// Delete authorization code (single use)
	s.DeleteAuthorizationCode(c.Request.Context(), code)

	// Generate tokens
	accessToken, _ := s.GenerateJWT(c.Request.Context(), authCode.UserID, clientID, authCode.Scope, client.AccessTokenLifetime)

	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   client.AccessTokenLifetime,
		Scope:       authCode.Scope,
	}

	// Generate ID token if openid scope is requested
	if strings.Contains(authCode.Scope, "openid") {
		idToken, _ := s.GenerateIDToken(c.Request.Context(), authCode.UserID, clientID, authCode.Nonce, client.AccessTokenLifetime)
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
	if err != nil || subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
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
	accessToken, _ := s.GenerateJWT(c.Request.Context(), token.UserID, clientID, token.Scope, client.AccessTokenLifetime)

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
	if err != nil || subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	// Generate access token (no user context)
	accessToken, _ := s.GenerateJWT(c.Request.Context(), "", clientID, scope, client.AccessTokenLifetime)

	c.JSON(200, TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   client.AccessTokenLifetime,
		Scope:       scope,
	})
}

func (s *Service) handleIntrospect(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(200, gin.H{"active": false})
		return
	}

	// Try to parse as JWT
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	})
	if err != nil || !parsed.Valid {
		// Check if it's a refresh token
		var userID, clientID, scope string
		err := s.db.Pool.QueryRow(c.Request.Context(), `
			SELECT user_id, client_id, scope FROM oauth_refresh_tokens
			WHERE token = $1 AND expires_at > NOW()
		`, token).Scan(&userID, &clientID, &scope)
		if err != nil {
			c.JSON(200, gin.H{"active": false})
			return
		}
		c.JSON(200, gin.H{
			"active":     true,
			"token_type": "refresh_token",
			"client_id":  clientID,
			"sub":        userID,
			"scope":      scope,
		})
		return
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(200, gin.H{"active": false})
		return
	}

	response := gin.H{
		"active":     true,
		"token_type": "access_token",
	}
	if sub, ok := claims["sub"].(string); ok {
		response["sub"] = sub
	}
	if clientID, ok := claims["client_id"].(string); ok {
		response["client_id"] = clientID
	}
	if scope, ok := claims["scope"].(string); ok {
		response["scope"] = scope
	}
	if exp, ok := claims["exp"].(float64); ok {
		response["exp"] = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		response["iat"] = int64(iat)
	}
	if iss, ok := claims["iss"].(string); ok {
		response["iss"] = iss
	}

	c.JSON(200, response)
}

func (s *Service) handleRevoke(c *gin.Context) {
	token := c.PostForm("token")

	// Revoke refresh token if it exists
	s.RevokeRefreshToken(c.Request.Context(), token)

	c.JSON(200, gin.H{"status": "revoked"})
}

func (s *Service) handleUserInfo(c *gin.Context) {
	// CORS headers for BrowZer and other browser-based clients
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

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

func (s *Service) RegenerateClientSecret(ctx context.Context, clientID string) (string, error) {
	newSecret := GenerateRandomToken(32)
	_, err := s.db.Pool.Exec(ctx, "UPDATE oauth_clients SET client_secret = $2, updated_at = NOW() WHERE client_id = $1", clientID, newSecret)
	if err != nil {
		return "", err
	}
	return newSecret, nil
}

func (s *Service) handleRegenerateClientSecret(c *gin.Context) {
	secret, err := s.RegenerateClientSecret(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"client_secret": secret})
}

// handleStepUpChallenge creates a step-up MFA challenge for an active session
func (s *Service) handleStepUpChallenge(c *gin.Context) {
	var req struct {
		SessionID string `json:"session_id"`
		UserID    string `json:"user_id"`
		Reason    string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}

	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	challengeID, err := s.riskService.CreateStepUpChallenge(c.Request.Context(), req.UserID, req.SessionID, req.Reason)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to create challenge", "error_description": err.Error()})
		return
	}

	// Check what MFA methods are available
	mfaMethods := []string{}
	totpStatus, _ := s.identityService.GetTOTPStatus(c.Request.Context(), req.UserID)
	if totpStatus != nil && totpStatus.Enabled {
		mfaMethods = append(mfaMethods, "totp")
	}

	c.JSON(200, gin.H{
		"challenge_id": challengeID,
		"mfa_methods":  mfaMethods,
		"expires_in":   300, // 5 minutes
	})
}

// handleStepUpVerify verifies a step-up MFA challenge
func (s *Service) handleStepUpVerify(c *gin.Context) {
	var req struct {
		ChallengeID string `json:"challenge_id"`
		UserID      string `json:"user_id"`
		TOTPCode    string `json:"totp_code"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}

	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	// Verify TOTP code
	valid, err := s.identityService.VerifyTOTP(c.Request.Context(), req.UserID, req.TOTPCode)
	if err != nil || !valid {
		c.JSON(401, gin.H{"error": "invalid_code", "error_description": "Invalid TOTP code"})
		return
	}

	// Complete the challenge
	if err := s.riskService.CompleteStepUpChallenge(c.Request.Context(), req.ChallengeID, req.UserID); err != nil {
		c.JSON(400, gin.H{"error": "challenge_failed", "error_description": err.Error()})
		return
	}

	// Update proxy session auth_methods if possible
	s.db.Pool.Exec(c.Request.Context(),
		`UPDATE proxy_sessions SET auth_methods = array_append(COALESCE(auth_methods, '{}'), 'step_up_mfa')
		 WHERE user_id = $1 AND revoked = false AND expires_at > NOW()`, req.UserID)

	go s.logAuditEvent(context.Background(), "authentication", "security", "step_up_mfa", "success",
		req.UserID, c.ClientIP(), req.UserID, "user",
		map[string]interface{}{"challenge_id": req.ChallengeID})

	c.JSON(200, gin.H{"status": "verified"})
}

// logAuditEvent writes an audit event directly to the audit_events table
func (s *Service) logAuditEvent(ctx context.Context, eventType, category, action, outcome, actorID, actorIP, targetID, targetType string, details map[string]interface{}) {
	detailsJSON, _ := json.Marshal(details)
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome,
		                          actor_id, actor_type, actor_ip, target_id, target_type,
		                          resource_id, details)
		VALUES (gen_random_uuid(), NOW(), $1, $2, $3, $4, $5, 'user', $6, $7, $8, $7, $9)
	`, eventType, category, action, outcome, actorID, actorIP, targetID, targetType, detailsJSON)
	if err != nil {
		s.logger.Error("Failed to log audit event", zap.Error(err))
	}
}
