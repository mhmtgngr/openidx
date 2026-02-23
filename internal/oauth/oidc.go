// Package oauth provides OpenID Connect (OIDC) functionality
package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/identity"
)

var (
	// ErrInvalidAccessToken is returned when the access token is invalid
	ErrInvalidAccessToken = errors.New("invalid_access_token")
	// ErrMissingBearerToken is returned when Bearer token is missing
	ErrMissingBearerToken = errors.New("missing_bearer_token")
	// ErrIDTokenGeneration is returned when ID token generation fails
	ErrIDTokenGeneration = errors.New("id_token_generation_failed")
	// ErrScopeMissingOpenID is returned when openid scope is missing
	ErrScopeMissingOpenID = errors.New("openid_scope_required")
)

// IDTokenClaims represents the standard OIDC ID token claims per OpenID Connect Core 1.0
type IDTokenClaims struct {
	Issuer                            string   `json:"iss"`                                 // Issuer
	Subject                           string   `json:"sub"`                                  // Subject (user ID)
	Audience                          string   `json:"aud"`                                  // Audience (client ID)
	Expiration                        int64    `json:"exp"`                                  // Expiration time
	IssuedAt                          int64    `json:"iat"`                                  // Issued at
	AuthTime                          int64    `json:"auth_time,omitempty"`                  // Authentication time
	Nonce                             string   `json:"nonce,omitempty"`                      // Nonce from auth request
	AccessTokenHash                   string   `json:"at_hash,omitempty"`                    // Access token hash
	AuthorizationCodeHash             string   `json:"c_hash,omitempty"`                     // Authorization code hash
	SessionID                         string   `json:"sid,omitempty"`                        // Session ID
	Email                             string   `json:"email,omitempty"`                      // User email
	EmailVerified                     bool     `json:"email_verified,omitempty"`              // Email verification status
	Name                              string   `json:"name,omitempty"`                       // User's full name
	GivenName                         string   `json:"given_name,omitempty"`                 // User's given name
	FamilyName                        string   `json:"family_name,omitempty"`                // User's family name
	MiddleName                        string   `json:"middle_name,omitempty"`                // User's middle name
	Nickname                          string   `json:"nickname,omitempty"`                   // User's nickname
	PreferredUsername                 string   `json:"preferred_username,omitempty"`         // Preferred username
	Profile                           string   `json:"profile,omitempty"`                     // Profile URL
	Picture                           string   `json:"picture,omitempty"`                    // Picture URL
	Website                           string   `json:"website,omitempty"`                    // Website URL
	Gender                            string   `json:"gender,omitempty"`                     // Gender
	Birthdate                         string   `json:"birthdate,omitempty"`                  // Birthdate
	ZoneInfo                          string   `json:"zoneinfo,omitempty"`                   // Timezone info
	Locale                            string   `json:"locale,omitempty"`                     // Locale
	PhoneNumber                       string   `json:"phone_number,omitempty"`                // Phone number
	PhoneNumberVerified               bool     `json:"phone_number_verified,omitempty"`       // Phone verification status
	Address                           *Address `json:"address,omitempty"`                    // Address
	UpdatedAt                         int64    `json:"updated_at,omitempty"`                  // Last update time
	Roles                             []string `json:"roles,omitempty"`                      // User roles
	Groups                            []string `json:"groups,omitempty"`                     // User groups
}

// Address represents a postal address per OIDC spec
type Address struct {
	Formatted   string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality    string `json:"locality,omitempty"`
	Region      string `json:"region,omitempty"`
	PostalCode  string `json:"postal_code,omitempty"`
	Country     string `json:"country,omitempty"`
}

// OIDCProvider provides OpenID Connect functionality
type OIDCProvider struct {
	service          *Service
	identityService  *identity.Service
	logger           *zap.Logger
	issuer           string
}

// NewOIDCProvider creates a new OIDC provider
func NewOIDCProvider(service *Service, identitySvc *identity.Service, logger *zap.Logger, issuer string) *OIDCProvider {
	return &OIDCProvider{
		service:         service,
		identityService: identitySvc,
		logger:          logger.With(zap.String("component", "oidc")),
		issuer:          issuer,
	}
}

// GenerateIDToken creates an OpenID Connect ID token (JWT) with proper claims
// Implements OpenID Connect Core 1.0 §2
func (p *OIDCProvider) GenerateIDToken(ctx context.Context, req *IDTokenRequest) (string, error) {
	now := time.Now()

	// Validate that openid scope is present
	if !strings.Contains(req.Scope, "openid") {
		return "", ErrScopeMissingOpenID
	}

	// Fetch user information to populate claims
	user, err := p.identityService.GetUser(ctx, req.UserID)
	if err != nil {
		p.logger.Error("Failed to fetch user for ID token",
			zap.String("user_id", req.UserID),
			zap.Error(err))
		return "", fmt.Errorf("failed to fetch user: %w", err)
	}

	// Build standard OIDC claims
	claims := jwt.MapClaims{
		"iss": p.issuer,                          // Issuer
		"sub": p.generateSubject(user.ID),        // Subject - pairwise or public identifier
		"aud": req.ClientID,                      // Audience - client_id
		"exp": now.Add(time.Duration(req.ExpiresIn) * time.Second).Unix(), // Expiration
		"iat": now.Unix(),                        // Issued At
	}

	// Add authentication time if provided
	if req.AuthTime > 0 {
		claims["auth_time"] = req.AuthTime
	} else {
		claims["auth_time"] = now.Unix()
	}

	// Add nonce if present (prevents token replay attacks)
	if req.Nonce != "" {
		claims["nonce"] = req.Nonce
	}

	// Add at_hash (access token hash) if access token is present
	if req.AccessToken != "" {
		atHash := p.hashHalf(req.AccessToken)
		claims["at_hash"] = atHash
	}

	// Add c_hash (authorization code hash) if code is present
	if req.Code != "" {
		cHash := p.hashHalf(req.Code)
		claims["c_hash"] = cHash
	}

	// Add session ID if present
	if req.SessionID != "" {
		claims["sid"] = req.SessionID
	}

	// Add profile claims based on scope
	if strings.Contains(req.Scope, "profile") {
		if user.DisplayName != nil && *user.DisplayName != "" {
			claims["name"] = *user.DisplayName
		} else {
			// Build name from given name and family name
			claims["name"] = p.buildFullName(user)
		}

		if user.Name != nil {
			if user.Name.GivenName != nil {
				claims["given_name"] = *user.Name.GivenName
			}
			if user.Name.FamilyName != nil {
				claims["family_name"] = *user.Name.FamilyName
			}
			if user.Name.MiddleName != nil {
				claims["middle_name"] = *user.Name.MiddleName
			}
		}

		claims["preferred_username"] = user.UserName
	}

	// Add email claims based on scope
	if strings.Contains(req.Scope, "email") {
		email := user.GetPrimaryEmail()
		if email != "" {
			claims["email"] = email
			claims["email_verified"] = user.EmailVerified
		}
	}

	// Add phone claims based on scope
	if strings.Contains(req.Scope, "phone") {
		phone := user.GetPrimaryPhoneNumber()
		if phone != "" {
			claims["phone_number"] = phone
			claims["phone_number_verified"] = true // Default to verified
		}
	}

	// Add address claim based on scope
	if strings.Contains(req.Scope, "address") && len(user.Addresses) > 0 {
		addr := user.Addresses[0]
		oidcAddr := &Address{
			Formatted:     addr.Formatted != nil,
			StreetAddress: addr.StreetAddress != nil,
			Locality:      addr.Locality != nil,
			Region:        addr.Region != nil,
			PostalCode:    addr.PostalCode != nil,
			Country:       addr.Country != nil,
		}
		if addr.Formatted != nil {
			oidcAddr.Formatted = *addr.Formatted
		}
		if addr.StreetAddress != nil {
			oidcAddr.StreetAddress = *addr.StreetAddress
		}
		if addr.Locality != nil {
			oidcAddr.Locality = *addr.Locality
		}
		if addr.Region != nil {
			oidcAddr.Region = *addr.Region
		}
		if addr.PostalCode != nil {
			oidcAddr.PostalCode = *addr.PostalCode
		}
		if addr.Country != nil {
			oidcAddr.Country = *addr.Country
		}
		claims["address"] = oidcAddr
	}

	// Add custom claims: roles and groups
	if len(user.Roles) > 0 {
		claims["roles"] = user.Roles
	}
	if len(user.Groups) > 0 {
		claims["groups"] = user.Groups
	}

	// Create and sign the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "openidx-key-1" // Key identifier for JWKS

	idToken, err := token.SignedString(p.service.privateKey)
	if err != nil {
		p.logger.Error("Failed to sign ID token", zap.Error(err))
		return "", ErrIDTokenGeneration
	}

	p.logger.Debug("Generated ID token",
		zap.String("user_id", user.ID),
		zap.String("client_id", req.ClientID),
		zap.String("sub", claims["sub"].(string)))

	return idToken, nil
}

// generateSubject generates a subject identifier for the user
// Supports both public and pairwise subject types per OIDC §8
func (p *OIDCProvider) generateSubject(userID string) string {
	// For now, use public subject type (same user ID for all clients)
	// In production, you'd want to support pairwise subject type for privacy
	return userID
}

// generatePairwiseSubject generates a pairwise subject identifier for a specific client
// This provides privacy by using different subject values for different clients
func (p *OIDCProvider) generatePairwiseSubject(userID, clientID, sectorIdentifier string) string {
	// Calculate SHA-256 hash of sector identifier + user ID
	// This generates a unique subject per client/sector
	h := sha256.New()
	h.Write([]byte(sectorIdentifier + userID))
	hash := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hash)
}

// hashHalf computes the first half of a SHA-256 hash (used for at_hash and c_hash)
// Implements OpenID Connect Core 1.0 §3.2.2.1
func (p *OIDCProvider) hashHalf(data string) string {
	h := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])
}

// buildFullName builds a full name from user's name components
func (p *OIDCProvider) buildFullName(user *identity.User) string {
	parts := []string{}
	if user.Name != nil {
		if user.Name.GivenName != nil {
			parts = append(parts, *user.Name.GivenName)
		}
		if user.Name.FamilyName != nil {
			parts = append(parts, *user.Name.FamilyName)
		}
	}
	if len(parts) == 0 {
		return user.UserName
	}
	return strings.Join(parts, " ")
}

// IDTokenRequest represents parameters for ID token generation
type IDTokenRequest struct {
	UserID     string
	ClientID   string
	Scope      string
	Nonce      string
	ExpiresIn  int // Token lifetime in seconds
	AuthTime   int64
	AccessToken string
	Code       string
	SessionID  string
}

// UserInfoRequest represents parameters for UserInfo endpoint
type UserInfoRequest struct {
	AccessToken string
	Scope       string
}

// UserInfoResponse represents the UserInfo response per OpenID Connect Core 1.0 §5.3.1
type UserInfoResponse struct {
	Sub               string   `json:"sub"`                                   // Required
	Name              string   `json:"name,omitempty"`                        // User's full name
	GivenName         string   `json:"given_name,omitempty"`                  // Given name
	FamilyName        string   `json:"family_name,omitempty"`                 // Family name
	MiddleName        string   `json:"middle_name,omitempty"`                 // Middle name
	Nickname          string   `json:"nickname,omitempty"`                    // Nickname
	PreferredUsername string   `json:"preferred_username,omitempty"`          // Preferred username
	Profile           string   `json:"profile,omitempty"`                     // Profile URL
	Picture           string   `json:"picture,omitempty"`                     // Picture URL
	Website           string   `json:"website,omitempty"`                     // Website URL
	Email             string   `json:"email,omitempty"`                       // Email
	EmailVerified     bool     `json:"email_verified,omitempty"`              // Email verified status
	Gender            string   `json:"gender,omitempty"`                      // Gender
	Birthdate         string   `json:"birthdate,omitempty"`                   // Birthdate
	ZoneInfo          string   `json:"zoneinfo,omitempty"`                    // Timezone
	Locale            string   `json:"locale,omitempty"`                      // Locale
	PhoneNumber       string   `json:"phone_number,omitempty"`                // Phone number
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`       // Phone verified
	Address           *Address `json:"address,omitempty"`                     // Address
	UpdatedAt         int64    `json:"updated_at,omitempty"`                 // Last update
	Roles             []string `json:"roles,omitempty"`                       // User roles
	Groups            []string `json:"groups,omitempty"`                      // User groups
}

// GetUserInfo retrieves user information for the UserInfo endpoint
// Implements OpenID Connect Core 1.0 §5.3.1
func (p *OIDCProvider) GetUserInfo(ctx context.Context, req *UserInfoRequest) (*UserInfoResponse, error) {
	// Validate access token and extract user ID
	userID, scope, err := p.validateAccessToken(ctx, req.AccessToken)
	if err != nil {
		return nil, err
	}

	// If scope was not provided in request, use the scope from access token
	if req.Scope == "" {
		req.Scope = scope
	}

	// Fetch user information
	user, err := p.identityService.GetUser(ctx, userID)
	if err != nil {
		p.logger.Error("Failed to fetch user for UserInfo",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to fetch user: %w", err)
	}

	// Build UserInfo response
	response := &UserInfoResponse{
		Sub: p.generateSubject(user.ID), // Required
	}

	// Add profile claims based on scope
	if strings.Contains(req.Scope, "profile") {
		if user.DisplayName != nil && *user.DisplayName != "" {
			response.Name = *user.DisplayName
		} else {
			response.Name = p.buildFullName(user)
		}
		response.PreferredUsername = user.UserName

		if user.Name != nil {
			if user.Name.GivenName != nil {
				response.GivenName = *user.Name.GivenName
			}
			if user.Name.FamilyName != nil {
				response.FamilyName = *user.Name.FamilyName
			}
			if user.Name.MiddleName != nil {
				response.MiddleName = *user.Name.MiddleName
			}
		}
	}

	// Add email claims based on scope
	if strings.Contains(req.Scope, "email") {
		response.Email = user.GetPrimaryEmail()
		response.EmailVerified = user.EmailVerified
	}

	// Add phone claims based on scope
	if strings.Contains(req.Scope, "phone") {
		response.PhoneNumber = user.GetPrimaryPhoneNumber()
		response.PhoneNumberVerified = true // Default to verified
	}

	// Add address claim based on scope
	if strings.Contains(req.Scope, "address") && len(user.Addresses) > 0 {
		addr := user.Addresses[0]
		response.Address = &Address{}
		if addr.Formatted != nil {
			response.Address.Formatted = *addr.Formatted
		}
		if addr.StreetAddress != nil {
			response.Address.StreetAddress = *addr.StreetAddress
		}
		if addr.Locality != nil {
			response.Address.Locality = *addr.Locality
		}
		if addr.Region != nil {
			response.Address.Region = *addr.Region
		}
		if addr.PostalCode != nil {
			response.Address.PostalCode = *addr.PostalCode
		}
		if addr.Country != nil {
			response.Address.Country = *addr.Country
		}
	}

	// Add custom claims: roles and groups
	if len(user.Roles) > 0 {
		response.Roles = user.Roles
	}
	if len(user.Groups) > 0 {
		response.Groups = user.Groups
	}

	p.logger.Debug("Retrieved UserInfo",
		zap.String("user_id", user.ID),
		zap.String("sub", response.Sub),
		zap.String("scope", req.Scope))

	return response, nil
}

// validateAccessToken validates the access token and returns the user ID and scope
func (p *OIDCProvider) validateAccessToken(ctx context.Context, accessToken string) (string, string, error) {
	if accessToken == "" {
		return "", "", ErrMissingBearerToken
	}

	// Try to get the access token from store
	tokenData, err := p.service.store.GetAccessToken(ctx, accessToken)
	if err != nil {
		p.logger.Warn("Invalid access token in UserInfo request", zap.Error(err))
		return "", "", ErrInvalidAccessToken
	}

	return tokenData.UserID, tokenData.Scope, nil
}

// ExtractBearerToken extracts the Bearer token from the Authorization header
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrMissingBearerToken
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", errors.New("invalid_authorization_header_format")
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)
	if token == "" {
		return "", ErrMissingBearerToken
	}

	return token, nil
}

// HandleUserInfo handles the UserInfo endpoint
// Implements OpenID Connect Core 1.0 §5.3
func (p *OIDCProvider) HandleUserInfo(c *gin.Context) {
	ctx := c.Request.Context()

	// Extract Bearer token from Authorization header
	authHeader := c.GetHeader("Authorization")
	accessToken, err := ExtractBearerToken(authHeader)
	if err != nil {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="Invalid Bearer token"`)
		c.JSON(401, gin.H{"error": "invalid_token", "error_description": "Missing or invalid Bearer token"})
		return
	}

	// Get UserInfo
	userInfo, err := p.GetUserInfo(ctx, &UserInfoRequest{
		AccessToken: accessToken,
	})
	if err != nil {
		p.logger.Error("Failed to get UserInfo", zap.Error(err))
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}

	// Return JSON response (default) or JWT based on authorization header
	// Check if client requested JWT response
	accept := c.GetHeader("Accept")
	if strings.Contains(accept, "application/jwt") {
		// Return signed JWT UserInfo response
		claims := jwt.MapClaims{
			"sub": userInfo.Sub,
		}
		// Add all non-zero claims
		if userInfo.Name != "" {
			claims["name"] = userInfo.Name
		}
		if userInfo.Email != "" {
			claims["email"] = userInfo.Email
			claims["email_verified"] = userInfo.EmailVerified
		}
		// Add other claims...

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "openidx-key-1"
		jwtResponse, err := token.SignedString(p.service.privateKey)
		if err != nil {
			c.JSON(500, gin.H{"error": "server_error"})
			return
		}
		c.Header("Content-Type", "application/jwt")
		c.String(200, jwtResponse)
		return
	}

	// Return standard JSON response
	c.JSON(200, userInfo)
}

// hashHalfSHA512 computes the first half of a SHA-512 hash (for RS512)
func hashHalfSHA512(data string) string {
	h := sha512.Sum512([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h[:len(h)/2])
}
