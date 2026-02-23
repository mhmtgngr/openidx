// Package middleware provides authentication and authorization middleware for the gateway
package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openidx/openidx/internal/gateway"
)

// JWTAuthMiddleware provides JWT authentication using JWKS
type JWTAuthMiddleware struct {
	jwksURL    string
	logger     gateway.Logger
	cache      *jwksCache
	httpClient *http.Client
}

// jwksCache caches RSA public keys from JWKS endpoint
type jwksCache struct {
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
	mu        sync.RWMutex
}

// JWKSResponse represents the JWKS endpoint response
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewJWTAuthMiddleware creates a new JWT authentication middleware
func NewJWTAuthMiddleware(jwksURL string, logger gateway.Logger) *JWTAuthMiddleware {
	return &JWTAuthMiddleware{
		jwksURL: jwksURL,
		logger:  logger,
		cache: &jwksCache{
			keys: make(map[string]*rsa.PublicKey),
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Authenticate creates a Gin middleware for JWT authentication
func (m *JWTAuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		tokenString, err := m.extractToken(c)
		if err != nil {
			m.respondWithError(c, http.StatusUnauthorized, err.Error())
			return
		}

		// Parse and validate token
		claims, err := m.validateToken(tokenString)
		if err != nil {
			m.respondWithError(c, http.StatusUnauthorized, fmt.Sprintf("Invalid token: %v", err))
			return
		}

		// Set user context from claims
		m.setUserContext(c, claims)

		c.Next()
	}
}

// OptionalAuthenticate parses JWT if present but doesn't require it
func (m *JWTAuthMiddleware) OptionalAuthenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := m.extractToken(c)
		if err != nil {
			// No token provided, continue without authentication
			c.Next()
			return
		}

		claims, err := m.validateToken(tokenString)
		if err != nil {
			// Invalid token, continue without authentication
			c.Next()
			return
		}

		m.setUserContext(c, claims)
		c.Next()
	}
}

// extractToken extracts the bearer token from the request
func (m *JWTAuthMiddleware) extractToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid authorization header format")
	}

	if strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("authorization header must use Bearer scheme")
	}

	if parts[1] == "" {
		return "", fmt.Errorf("token cannot be empty")
	}

	return parts[1], nil
}

// validateToken parses and validates the JWT token
func (m *JWTAuthMiddleware) validateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing kid header")
		}

		// Get signing key from JWKS
		return m.getSigningKey(kid)
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("token has expired")
		}
	}

	// Check not before
	if nbf, ok := claims["nbf"].(float64); ok {
		if time.Now().Unix() < int64(nbf) {
			return nil, fmt.Errorf("token not yet valid")
		}
	}

	return claims, nil
}

// setUserContext sets user information in the Gin context from JWT claims
func (m *JWTAuthMiddleware) setUserContext(c *gin.Context, claims jwt.MapClaims) {
	// Standard claims
	if sub, ok := claims["sub"].(string); ok {
		c.Set("user_id", sub)
	}

	if email, ok := claims["email"].(string); ok {
		c.Set("email", email)
	}

	if name, ok := claims["name"].(string); ok {
		c.Set("name", name)
	}

	// Session ID
	if sid, ok := claims["sid"].(string); ok {
		c.Set("session_id", sid)
	}

	// Organization ID
	if orgID, ok := claims["org_id"].(string); ok && orgID != "" {
		c.Set("org_id", orgID)
	} else {
		c.Set("org_id", "00000000-0000-0000-0000-000000000010")
	}

	// Roles
	if roles, ok := claims["roles"].([]interface{}); ok {
		roleStrings := make([]string, len(roles))
		for i, role := range roles {
			roleStrings[i] = fmt.Sprint(role)
		}
		c.Set("roles", roleStrings)
	}

	// Token expiry for refresh decisions
	if exp, ok := claims["exp"].(float64); ok {
		c.Set("token_expires_at", time.Unix(int64(exp), 0))
	}

	// Issuer
	if iss, ok := claims["iss"].(string); ok {
		c.Set("issuer", iss)
	}

	// Store full claims for advanced use cases
	c.Set("jwt_claims", claims)
}

// respondWithError sends an error response
func (m *JWTAuthMiddleware) respondWithError(c *gin.Context, status int, message string) {
	c.AbortWithStatusJSON(status, gin.H{
		"error": message,
	})
}

// getSigningKey retrieves an RSA public key from the JWKS cache
func (m *JWTAuthMiddleware) getSigningKey(kid string) (*rsa.PublicKey, error) {
	// Try cache first
	m.cache.mu.RLock()
	if time.Now().Before(m.cache.expiresAt) {
		if key, ok := m.cache.keys[kid]; ok {
			m.cache.mu.RUnlock()
			return key, nil
		}
	}
	m.cache.mu.RUnlock()

	// Cache miss or expired, fetch JWKS
	m.cache.mu.Lock()
	defer m.cache.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Now().Before(m.cache.expiresAt) {
		if key, ok := m.cache.keys[kid]; ok {
			return key, nil
		}
	}

	// Fetch from JWKS endpoint
	keys, err := m.fetchJWKS()
	if err != nil {
		return nil, err
	}

	m.cache.keys = keys
	m.cache.expiresAt = time.Now().Add(1 * time.Hour)

	if key, ok := keys[kid]; ok {
		return key, nil
	}

	return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
}

// fetchJWKS fetches and parses the JWKS from the configured URL
func (m *JWTAuthMiddleware) fetchJWKS() (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", m.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}

		pubKey, err := m.parseRSAPublicKey(key.N, key.E)
		if err != nil {
			// Log but continue - skip invalid keys
			m.logger.Warn("Failed to parse RSA key from JWKS",
				"kid", key.Kid,
				"error", err.Error())
			continue
		}

		keys[key.Kid] = pubKey
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid RSA signing keys found in JWKS")
	}

	return keys, nil
}

// parseRSAPublicKey parses an RSA public key from base64url-encoded modulus and exponent
func (m *JWTAuthMiddleware) parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// Decode modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// RequireRoles creates middleware that requires specific roles
func RequireRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "no roles found for user",
			})
			return
		}

		userRolesList, ok := userRoles.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "invalid roles format",
			})
			return
		}

		// Check if user has any of the required roles
		for _, required := range roles {
			for _, userRole := range userRolesList {
				if userRole == required {
					c.Next()
					return
				}
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "insufficient permissions",
		})
	}
}

// RequirePermission creates middleware that checks for specific permissions
func RequirePermission(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("permissions")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("missing permission: %s:%s", resource, action),
			})
			return
		}

		perms, ok := permissions.([]gateway.PermissionEntry)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "invalid permissions format",
			})
			return
		}

		for _, p := range perms {
			if p.Resource == resource && p.Action == action {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": fmt.Sprintf("missing permission: %s:%s", resource, action),
		})
	}
}
