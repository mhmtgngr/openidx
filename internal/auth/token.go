// Package auth provides JWT token generation, validation, and revocation for OpenIDX
package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var (
	// ErrTokenInvalid is returned when a token is malformed or signature verification fails
	ErrTokenInvalid = errors.New("token is invalid")

	// ErrTokenExpired is returned when a token has passed its expiration time
	ErrTokenExpired = errors.New("token is expired")

	// ErrTokenRevoked is returned when a token has been explicitly revoked
	ErrTokenRevoked = errors.New("token has been revoked")

	// ErrMissingPrivateKey is returned when no private key is configured for signing
	ErrMissingPrivateKey = errors.New("private key is required for signing tokens")

	// ErrMissingPublicKey is returned when no public key is configured for verification
	ErrMissingPublicKey = errors.New("public key is required for verifying tokens")
)

// Claims represents the JWT claims structure for OpenIDX tokens
type Claims struct {
	Subject   string   `json:"sub"`              // User ID
	TenantID  string   `json:"tid,omitempty"`   // Tenant ID (multi-tenant)
	Roles     []string `json:"roles,omitempty"` // User roles
	TokenType string   `json:"token_type"`      // "access" or "refresh"
	jwt.RegisteredClaims
}

// TokenType represents the type of JWT token
type TokenType string

const (
	AccessTokenType  TokenType = "access"
	RefreshTokenType TokenType = "refresh"
)

// TokenConfig holds configuration for token generation
type TokenConfig struct {
	AccessTokenDuration  time.Duration // Default: 15 minutes
	RefreshTokenDuration time.Duration // Default: 7 days
	Issuer               string        // Issuer identifier (e.g., "openidx")
}

// DefaultTokenConfig returns sensible defaults for token configuration
func DefaultTokenConfig() TokenConfig {
	return TokenConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		Issuer:               "openidx",
	}
}

// TokenService handles JWT token generation, validation, and revocation
type TokenService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	redis      *redis.Client
	config     TokenConfig
	logger     *zap.Logger
}

// NewTokenService creates a new TokenService with the given RSA keys and Redis client
func NewTokenService(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, redisClient *redis.Client, logger *zap.Logger) *TokenService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &TokenService{
		privateKey: privateKey,
		publicKey:  publicKey,
		redis:      redisClient,
		config:     DefaultTokenConfig(),
		logger:     logger,
	}
}

// WithConfig sets a custom token configuration
func (ts *TokenService) WithConfig(config TokenConfig) *TokenService {
	ts.config = config
	return ts
}

// GenerateAccessToken creates a new JWT access token for the given subject
func (ts *TokenService) GenerateAccessToken(ctx context.Context, subject string, tenantID string, roles []string) (string, error) {
	return ts.generateToken(ctx, subject, tenantID, roles, AccessTokenType, ts.config.AccessTokenDuration)
}

// GenerateRefreshToken creates a new JWT refresh token for the given subject
func (ts *TokenService) GenerateRefreshToken(ctx context.Context, subject string, tenantID string) (string, error) {
	return ts.generateToken(ctx, subject, tenantID, nil, RefreshTokenType, ts.config.RefreshTokenDuration)
}

// GenerateTokenPair creates both access and refresh tokens for the given subject
func (ts *TokenService) GenerateTokenPair(ctx context.Context, subject string, tenantID string, roles []string) (accessToken, refreshToken string, err error) {
	accessToken, err = ts.GenerateAccessToken(ctx, subject, tenantID, roles)
	if err != nil {
		return "", "", fmt.Errorf("generate access token: %w", err)
	}

	refreshToken, err = ts.GenerateRefreshToken(ctx, subject, tenantID)
	if err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// generateToken creates a JWT token with the specified parameters
func (ts *TokenService) generateToken(ctx context.Context, subject, tenantID string, roles []string, tokenType TokenType, duration time.Duration) (string, error) {
	if ts.privateKey == nil {
		return "", ErrMissingPrivateKey
	}

	now := time.Now()
	claims := Claims{
		Subject:   subject,
		TenantID:  tenantID,
		Roles:     roles,
		TokenType: string(tokenType),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.config.Issuer,
			Subject:   subject,
			Audience:  []string{"openidx"},
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(ts.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	ts.logger.Debug("generated token",
		zap.String("subject", subject),
		zap.String("type", string(tokenType)),
		zap.Duration("duration", duration),
	)

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the claims if valid
func (ts *TokenService) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	if ts.publicKey == nil {
		return nil, ErrMissingPublicKey
	}

	// First check if token is revoked
	if ts.redis != nil {
		revoked, err := ts.isTokenRevoked(ctx, tokenString)
		if err != nil {
			ts.logger.Warn("failed to check token revocation status", zap.Error(err))
			// Continue with validation even if Redis check fails
		} else if revoked {
			return nil, ErrTokenRevoked
		}
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ts.publicKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	return claims, nil
}

// ValidateAccessToken validates an access token and returns the claims
func (ts *TokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := ts.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != string(AccessTokenType) {
		return nil, ErrTokenInvalid
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token and returns the claims
func (ts *TokenService) ValidateRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := ts.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != string(RefreshTokenType) {
		return nil, ErrTokenInvalid
	}

	return claims, nil
}

// RevokeToken adds a token to the Redis blacklist
func (ts *TokenService) RevokeToken(ctx context.Context, tokenString string) error {
	if ts.redis == nil {
		return errors.New("redis client not configured")
	}

	// Parse token without validation to get expiration time
	parser := jwt.Parser{}
	claims := &Claims{}
	token, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		// Invalid token - can't be used anyway, so return success
		return nil
	}

	// Calculate TTL until token expires
	var ttl time.Duration
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
		if ttl <= 0 {
			// Token already expired, no need to revoke
			return nil
		}
	} else {
		// No expiration, use default TTL of 24 hours
		ttl = 24 * time.Hour
	}

	// Store in Redis with TTL
	key := ts.blacklistKey(tokenString)
	if err := ts.redis.Set(ctx, key, "1", ttl).Err(); err != nil {
		return fmt.Errorf("set token in blacklist: %w", err)
	}

	ts.logger.Debug("revoked token",
		zap.Any("jti", token.Header["kid"]),
		zap.Duration("ttl", ttl),
	)

	return nil
}

// RevokeUserTokens revokes all tokens for a specific user
func (ts *TokenService) RevokeUserTokens(ctx context.Context, userID string) error {
	if ts.redis == nil {
		return errors.New("redis client not configured")
	}

	// Store a revocation marker for the user
	// Tokens will be checked against this during validation
	key := ts.userRevocationKey(userID)
	if err := ts.redis.Set(ctx, key, time.Now().Unix(), 24*time.Hour).Err(); err != nil {
		return fmt.Errorf("set user revocation marker: %w", err)
	}

	ts.logger.Debug("revoked all tokens for user", zap.String("user_id", userID))
	return nil
}

// IsTokenRevoked checks if a token has been revoked
func (ts *TokenService) IsTokenRevoked(ctx context.Context, tokenString string) (bool, error) {
	if ts.redis == nil {
		return false, nil
	}
	return ts.isTokenRevoked(ctx, tokenString)
}

// isTokenRevoked internal method to check revocation status
func (ts *TokenService) isTokenRevoked(ctx context.Context, tokenString string) (bool, error) {
	key := ts.blacklistKey(tokenString)
	exists, err := ts.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// RefreshAccessToken generates a new access token using a valid refresh token
func (ts *TokenService) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	claims, err := ts.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return "", fmt.Errorf("validate refresh token: %w", err)
	}

	// Generate new access token
	newAccessToken, err := ts.GenerateAccessToken(ctx, claims.Subject, claims.TenantID, claims.Roles)
	if err != nil {
		return "", fmt.Errorf("generate access token: %w", err)
	}

	return newAccessToken, nil
}

// blacklistKey returns the Redis key for a revoked token
func (ts *TokenService) blacklistKey(tokenString string) string {
	return fmt.Sprintf("auth:revoked:%s", tokenString)
}

// userRevocationKey returns the Redis key for a user revocation marker
func (ts *TokenService) userRevocationKey(userID string) string {
	return fmt.Sprintf("auth:user_revoked:%s", userID)
}

// ExtractSubject extracts the subject (user ID) from a token without validating signature
// Useful for logging and debugging purposes only
func ExtractSubject(tokenString string) (string, error) {
	parser := jwt.Parser{}
	claims := &Claims{}
	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}
