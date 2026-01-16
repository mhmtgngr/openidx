// Package middleware provides HTTP middleware for OpenIDX services
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
	"github.com/google/uuid"
)

// JWKSKey represents a single key from the JWKS endpoint
type JWKSKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents the JSON Web Key Set from Keycloak
type JWKS struct {
	Keys []JWKSKey `json:"keys"`
}

// jwksKeyCache stores parsed RSA public keys
type jwksKeyCache struct {
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
	mu        sync.RWMutex
}

// Global JWKS cache with 1 hour TTL
var globalJWKSCache = &jwksKeyCache{
	keys: make(map[string]*rsa.PublicKey),
}

// fetchJWKS fetches and parses JWKS from Keycloak
func fetchJWKS(keycloakURL, realm string) (map[string]*rsa.PublicKey, error) {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", keycloakURL, realm)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}

		pubKey, err := parseRSAPublicKey(key.N, key.E)
		if err != nil {
			continue // Skip invalid keys
		}
		keys[key.Kid] = pubKey
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid RSA signing keys found in JWKS")
	}

	return keys, nil
}

// parseRSAPublicKey parses RSA public key from base64url encoded n and e
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// Decode n (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode e (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// getSigningKey retrieves the RSA public key for token validation
func getSigningKey(keycloakURL, realm, kid string) (*rsa.PublicKey, error) {
	globalJWKSCache.mu.RLock()
	if time.Now().Before(globalJWKSCache.expiresAt) {
		if key, ok := globalJWKSCache.keys[kid]; ok {
			globalJWKSCache.mu.RUnlock()
			return key, nil
		}
	}
	globalJWKSCache.mu.RUnlock()

	// Cache miss or expired, fetch new JWKS
	globalJWKSCache.mu.Lock()
	defer globalJWKSCache.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Now().Before(globalJWKSCache.expiresAt) {
		if key, ok := globalJWKSCache.keys[kid]; ok {
			return key, nil
		}
	}

	keys, err := fetchJWKS(keycloakURL, realm)
	if err != nil {
		return nil, err
	}

	globalJWKSCache.keys = keys
	globalJWKSCache.expiresAt = time.Now().Add(1 * time.Hour)

	if key, ok := keys[kid]; ok {
		return key, nil
	}

	return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
}

// CORS returns a middleware that handles CORS headers
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Request-ID")
		c.Header("Access-Control-Expose-Headers", "X-Request-ID, X-Total-Count")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RequestID adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// Auth validates JWT tokens from Keycloak
func Auth(keycloakURL, realm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header format",
			})
			return
		}

		tokenString := parts[1]

		// Parse the token with key function that fetches from JWKS
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method is RSA
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Get the key ID from token header
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("token missing kid header")
			}

			// Fetch the signing key from JWKS
			return getSigningKey(keycloakURL, realm, kid)
		})

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": fmt.Sprintf("invalid token: %v", err),
			})
			return
		}

		// Validate token
		if token == nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token claims",
			})
			return
		}

		// Validate expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "token expired",
				})
				return
			}
		}

		// Set user context
		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
		}
		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}
		if name, ok := claims["name"].(string); ok {
			c.Set("name", name)
		}

		// Extract roles
		if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
			if roles, ok := realmAccess["roles"].([]interface{}); ok {
				roleStrings := make([]string, len(roles))
				for i, role := range roles {
					roleStrings[i] = fmt.Sprint(role)
				}
				c.Set("roles", roleStrings)
			}
		}

		c.Next()
	}
}

// RequireRoles ensures the user has at least one of the specified roles
func RequireRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "no roles found",
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

// RateLimit implements a simple rate limiter
func RateLimit(requests int, window time.Duration) gin.HandlerFunc {
	// In production, use Redis for distributed rate limiting
	// This is a simple in-memory implementation for development
	type clientInfo struct {
		count     int
		resetTime time.Time
	}
	var mu sync.RWMutex
	clients := make(map[string]*clientInfo)

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()

		mu.RLock()
		info, exists := clients[clientIP]
		mu.RUnlock()

		if !exists || now.After(info.resetTime) {
			mu.Lock()
			clients[clientIP] = &clientInfo{
				count:     1,
				resetTime: now.Add(window),
			}
			mu.Unlock()
			c.Next()
			return
		}

		mu.RLock()
		if info.count >= requests {
			retryAfter := int(info.resetTime.Sub(now).Seconds())
			mu.RUnlock()
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}
		mu.RUnlock()

		mu.Lock()
		info.count++
		mu.Unlock()
		c.Next()
	}
}

// Timeout adds a timeout to the request context
func Timeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		done := make(chan struct{})
		go func() {
			c.Next()
			close(done)
		}()

		select {
		case <-done:
			return
		case <-ctx.Done():
			c.AbortWithStatusJSON(http.StatusGatewayTimeout, gin.H{
				"error": "request timeout",
			})
		}
	}
}

// Recovery returns a middleware that recovers from panics
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "internal server error",
				})
			}
		}()
		c.Next()
	}
}
