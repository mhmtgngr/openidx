// Package oauth provides Redis-backed storage for OAuth 2.0 tokens
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

var (
	// ErrCodeNotFound is returned when an authorization code is not found
	ErrCodeNotFound = errors.New("authorization_code_not_found")
	// ErrCodeExpired is returned when an authorization code has expired
	ErrCodeExpired = errors.New("authorization_code_expired")
	// ErrCodeAlreadyUsed is returned when an authorization code has been used
	ErrCodeAlreadyUsed = errors.New("authorization_code_already_used")
	// ErrRefreshTokenNotFound is returned when a refresh token is not found
	ErrRefreshTokenNotFound = errors.New("refresh_token_not_found")
	// ErrRefreshTokenExpired is returned when a refresh token has expired
	ErrRefreshTokenExpired = errors.New("refresh_token_expired")
	// ErrTokenInvalidated is returned when a token family has been invalidated
	ErrTokenInvalidated = errors.New("token_invalidated")
)

const (
	// DefaultAuthCodeTTL is the default lifetime of an authorization code (10 minutes)
	DefaultAuthCodeTTL = 10 * time.Minute
	// DefaultRefreshTokenTTL is the default lifetime of a refresh token (30 days)
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
	// DefaultAccessTokenTTL is the default lifetime of an access token (1 hour)
	DefaultAccessTokenTTL = time.Hour
)

// StoredAuthorizationCode represents a stored authorization code with its metadata
type StoredAuthorizationCode struct {
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
	Used              bool      `json:"used"`
}

// RefreshTokenFamily tracks a family of refresh tokens for rotation
type RefreshTokenFamily struct {
	FamilyID     string    `json:"family_id"`
	ClientID     string    `json:"client_id"`
	UserID       string    `json:"user_id"`
	Scope        string    `json:"scope"`
	CreatedAt    time.Time `json:"created_at"`
	LastRotated  time.Time `json:"last_rotated"`
	TokenCount   int       `json:"token_count"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// StoredRefreshToken represents a stored refresh token
type StoredRefreshToken struct {
	Token      string    `json:"token"`
	FamilyID   string    `json:"family_id"`
	ClientID   string    `json:"client_id"`
	UserID     string    `json:"user_id"`
	Scope      string    `json:"scope"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	Revoked    bool      `json:"revoked"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// AccessTokenData represents stored access token metadata
type AccessTokenData struct {
	Token      string    `json:"token"`
	ClientID   string    `json:"client_id"`
	UserID     string    `json:"user_id"`
	Scope      string    `json:"scope"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// Store provides Redis-backed storage for OAuth 2.0 tokens
type Store struct {
	redis  *database.RedisClient
	logger *zap.Logger
}

// NewStore creates a new OAuth token store
func NewStore(redis *database.RedisClient, logger *zap.Logger) *Store {
	return &Store{
		redis:  redis,
		logger: logger.With(zap.String("component", "oauth_store")),
	}
}

// GenerateToken generates a cryptographically random token string
func (s *Store) GenerateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		s.logger.Error("Failed to generate random token", zap.Error(err))
		// Fallback to time-based generation (less secure but functional)
		return fmt.Sprintf("%d-%s", time.Now().UnixNano(), generateUUID())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// StoreAuthorizationCode stores an authorization code in Redis
func (s *Store) StoreAuthorizationCode(ctx context.Context, code *StoredAuthorizationCode, ttl time.Duration) error {
	if ttl == 0 {
		ttl = DefaultAuthCodeTTL
	}

	key := s.authCodeKey(code.Code)

	data, err := json.Marshal(code)
	if err != nil {
		return fmt.Errorf("failed to marshal auth code: %w", err)
	}

	// Store with TTL
	err = s.redis.Client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		s.logger.Error("Failed to store authorization code",
			zap.String("code", code.Code),
			zap.Error(err))
		return fmt.Errorf("failed to store auth code: %w", err)
	}

	s.logger.Debug("Stored authorization code",
		zap.String("code", code.Code),
		zap.String("client_id", code.ClientID),
		zap.Duration("ttl", ttl))

	return nil
}

// GetAuthorizationCode retrieves an authorization code from Redis
func (s *Store) GetAuthorizationCode(ctx context.Context, code string) (*StoredAuthorizationCode, error) {
	key := s.authCodeKey(code)

	data, err := s.redis.Client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrCodeNotFound
		}
		return nil, fmt.Errorf("failed to get auth code: %w", err)
	}

	var storedCode StoredAuthorizationCode
	if err := json.Unmarshal([]byte(data), &storedCode); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth code: %w", err)
	}

	// Check if expired
	if time.Now().After(storedCode.ExpiresAt) {
		s.DeleteAuthorizationCode(ctx, code)
		return nil, ErrCodeExpired
	}

	// Check if already used (replay attack detection)
	if storedCode.Used {
		s.DeleteAuthorizationCode(ctx, code)
		return nil, ErrCodeAlreadyUsed
	}

	return &storedCode, nil
}

// ConsumeAuthorizationCode marks an authorization code as used and removes it
// This is used during token exchange to ensure single-use (replay protection)
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, code string) error {
	// Get the code first to check if it exists and is valid
	storedCode, err := s.GetAuthorizationCode(ctx, code)
	if err != nil {
		return err
	}

	// Mark as used
	storedCode.Used = true

	// Store the updated code (immediately expired)
	key := s.authCodeKey(code)
	data, err := json.Marshal(storedCode)
	if err != nil {
		return fmt.Errorf("failed to marshal auth code: %w", err)
	}

	// Set with a short TTL for audit purposes
	err = s.redis.Client.Set(ctx, key, data, 5*time.Minute).Err()
	if err != nil {
		return fmt.Errorf("failed to mark auth code as used: %w", err)
	}

	// Delete immediately for single-use semantics
	s.DeleteAuthorizationCode(ctx, code)

	s.logger.Debug("Consumed authorization code",
		zap.String("code", code),
		zap.String("client_id", storedCode.ClientID),
		zap.String("user_id", storedCode.UserID))

	return nil
}

// DeleteAuthorizationCode removes an authorization code from Redis
func (s *Store) DeleteAuthorizationCode(ctx context.Context, code string) error {
	key := s.authCodeKey(code)
	err := s.redis.Client.Del(ctx, key).Err()
	if err != nil {
		s.logger.Warn("Failed to delete authorization code",
			zap.String("code", code),
			zap.Error(err))
	}
	return err
}

// StoreRefreshToken stores a refresh token and creates/updates its token family
func (s *Store) StoreRefreshToken(ctx context.Context, token *StoredRefreshToken, familyID string, ttl time.Duration) error {
	if ttl == 0 {
		ttl = DefaultRefreshTokenTTL
	}

	// Get or create the token family
	var family *RefreshTokenFamily
	if familyID != "" {
		family = s.getOrCreateFamily(ctx, token.ClientID, token.UserID, token.Scope, familyID, ttl)
	} else {
		family = s.createFamily(ctx, token.ClientID, token.UserID, token.Scope, ttl)
	}

	token.FamilyID = family.FamilyID

	// Store the token
	tokenKey := s.refreshTokenKey(token.Token)
	tokenData, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}

	err = s.redis.Client.Set(ctx, tokenKey, tokenData, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Update family
	family.TokenCount++
	family.LastRotated = time.Now()
	familyData, _ := json.Marshal(family)
	familyKey := s.tokenFamilyKey(family.FamilyID)
	s.redis.Client.Set(ctx, familyKey, familyData, ttl)

	s.logger.Debug("Stored refresh token",
		zap.String("family_id", family.FamilyID),
		zap.String("client_id", token.ClientID),
		zap.Duration("ttl", ttl))

	return nil
}

// GetRefreshToken retrieves a refresh token from Redis
func (s *Store) GetRefreshToken(ctx context.Context, token string) (*StoredRefreshToken, error) {
	tokenKey := s.refreshTokenKey(token)

	data, err := s.redis.Client.Get(ctx, tokenKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	var storedToken StoredRefreshToken
	if err := json.Unmarshal([]byte(data), &storedToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}

	// Check if expired
	if time.Now().After(storedToken.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}

	// Check if revoked
	if storedToken.Revoked {
		return nil, ErrTokenInvalidated
	}

	return &storedToken, nil
}

// RotateRefreshToken rotates a refresh token as per RFC 6819
// The old token is revoked and a new one is issued
func (s *Store) RotateRefreshToken(ctx context.Context, oldToken string, newToken *StoredRefreshToken, ttl time.Duration) error {
	oldTokenKey := s.refreshTokenKey(oldToken)

	// Get the old token to validate it and get the family ID
	oldTokenData, err := s.redis.Client.Get(ctx, oldTokenKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrRefreshTokenNotFound
		}
		return fmt.Errorf("failed to get old refresh token: %w", err)
	}

	var storedOldToken StoredRefreshToken
	if err := json.Unmarshal([]byte(oldTokenData), &storedOldToken); err != nil {
		return fmt.Errorf("failed to unmarshal old refresh token: %w", err)
	}

	// Check if the old token was already revoked (replay detection)
	if storedOldToken.Revoked {
		// Potential token leak - revoke entire family
		s.RevokeTokenFamily(ctx, storedOldToken.FamilyID)
		return ErrTokenInvalidated
	}

	// Mark the old token as revoked
	now := time.Now()
	storedOldToken.Revoked = true
	storedOldToken.RevokedAt = &now

	oldTokenDataUpdated, _ := json.Marshal(storedOldToken)
	s.redis.Client.Set(ctx, oldTokenKey, oldTokenDataUpdated, 5*time.Minute)

	// Store the new token with the same family ID
	newToken.FamilyID = storedOldToken.FamilyID
	newTokenKey := s.refreshTokenKey(newToken.Token)

	newTokenData, err := json.Marshal(newToken)
	if err != nil {
		return fmt.Errorf("failed to marshal new refresh token: %w", err)
	}

	err = s.redis.Client.Set(ctx, newTokenKey, newTokenData, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store new refresh token: %w", err)
	}

	// Update the token family
	familyKey := s.tokenFamilyKey(storedOldToken.FamilyID)
	familyData, err := s.redis.Client.Get(ctx, familyKey).Result()
	if err == nil {
		var family RefreshTokenFamily
		if json.Unmarshal([]byte(familyData), &family) == nil {
			family.TokenCount++
			family.LastRotated = now
			family.ExpiresAt = newToken.ExpiresAt
			familyDataUpdated, _ := json.Marshal(family)
			s.redis.Client.Set(ctx, familyKey, familyDataUpdated, ttl)
		}
	}

	s.logger.Debug("Rotated refresh token",
		zap.String("family_id", storedOldToken.FamilyID),
		zap.String("client_id", newToken.ClientID))

	return nil
}

// RevokeRefreshToken revokes a refresh token
func (s *Store) RevokeRefreshToken(ctx context.Context, token string) error {
	tokenKey := s.refreshTokenKey(token)

	data, err := s.redis.Client.Get(ctx, tokenKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrRefreshTokenNotFound
		}
		return fmt.Errorf("failed to get refresh token: %w", err)
	}

	var storedToken StoredRefreshToken
	if err := json.Unmarshal([]byte(data), &storedToken); err != nil {
		return fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}

	// Mark as revoked
	now := time.Now()
	storedToken.Revoked = true
	storedToken.RevokedAt = &now

	tokenData, _ := json.Marshal(storedToken)
	err = s.redis.Client.Set(ctx, tokenKey, tokenData, 24*time.Hour).Err() // Keep for 24h for audit
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	s.logger.Debug("Revoked refresh token",
		zap.String("token", token),
		zap.String("client_id", storedToken.ClientID))

	return nil
}

// RevokeTokenFamily revokes all tokens in a token family
// This is used when token theft is suspected
func (s *Store) RevokeTokenFamily(ctx context.Context, familyID string) error {
	familyKey := s.tokenFamilyKey(familyID)

	// Get the family to find all tokens
	// Note: In production, you'd want to maintain a set of token IDs per family
	// For now, we'll mark the family as revoked

	familyData, err := s.redis.Client.Get(ctx, familyKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil // Family doesn't exist, nothing to revoke
		}
		return fmt.Errorf("failed to get token family: %w", err)
	}

	var family RefreshTokenFamily
	if err := json.Unmarshal([]byte(familyData), &family); err != nil {
		return fmt.Errorf("failed to unmarshal token family: %w", err)
	}

	// Mark family as revoked by updating with a special flag
	family.ExpiresAt = time.Now() // Expire the family

	familyDataUpdated, _ := json.Marshal(family)
	s.redis.Client.Set(ctx, familyKey, familyDataUpdated, time.Hour)

	s.logger.Warn("Revoked token family due to security event",
		zap.String("family_id", familyID),
		zap.String("client_id", family.ClientID),
		zap.String("user_id", family.UserID))

	return nil
}

// GetTokenFamily retrieves a token family by ID
func (s *Store) GetTokenFamily(ctx context.Context, familyID string) (*RefreshTokenFamily, error) {
	familyKey := s.tokenFamilyKey(familyID)

	data, err := s.redis.Client.Get(ctx, familyKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get token family: %w", err)
	}

	var family RefreshTokenFamily
	if err := json.Unmarshal([]byte(data), &family); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token family: %w", err)
	}

	return &family, nil
}

// StoreAccessToken stores access token metadata in Redis
func (s *Store) StoreAccessToken(ctx context.Context, token *AccessTokenData, ttl time.Duration) error {
	if ttl == 0 {
		ttl = DefaultAccessTokenTTL
	}

	key := s.accessTokenKey(token.Token)

	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal access token: %w", err)
	}

	err = s.redis.Client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}

	return nil
}

// GetAccessToken retrieves access token metadata
func (s *Store) GetAccessToken(ctx context.Context, token string) (*AccessTokenData, error) {
	key := s.accessTokenKey(token)

	data, err := s.redis.Client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	var tokenData AccessTokenData
	if err := json.Unmarshal([]byte(data), &tokenData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal access token: %w", err)
	}

	// Check if expired
	if time.Now().After(tokenData.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}

	return &tokenData, nil
}

// RevokeAccessToken revokes an access token
func (s *Store) RevokeAccessToken(ctx context.Context, token string) error {
	key := s.accessTokenKey(token)
	return s.redis.Client.Del(ctx, key).Err()
}

// RevokeUserTokens revokes all tokens for a specific user
func (s *Store) RevokeUserTokens(ctx context.Context, userID string) error {
	// Scan for all keys matching the user's tokens
	pattern := fmt.Sprintf("oauth:token:*:%s", userID)
	iter := s.redis.Client.Scan(ctx, 0, pattern, 100).Iterator()

	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan for user tokens: %w", err)
	}

	if len(keys) > 0 {
		err := s.redis.Client.Del(ctx, keys...).Err()
		if err != nil {
			return fmt.Errorf("failed to delete user tokens: %w", err)
		}

		s.logger.Info("Revoked all user tokens",
			zap.String("user_id", userID),
			zap.Int("count", len(keys)))
	}

	return nil
}

// Helper methods for key generation

func (s *Store) authCodeKey(code string) string {
	return fmt.Sprintf("oauth:auth_code:%s", code)
}

func (s *Store) refreshTokenKey(token string) string {
	return fmt.Sprintf("oauth:refresh_token:%s", token)
}

func (s *Store) accessTokenKey(token string) string {
	return fmt.Sprintf("oauth:access_token:%s", token)
}

func (s *Store) tokenFamilyKey(familyID string) string {
	return fmt.Sprintf("oauth:token_family:%s", familyID)
}

func (s *Store) createFamily(ctx context.Context, clientID, userID, scope string, ttl time.Duration) *RefreshTokenFamily {
	family := &RefreshTokenFamily{
		FamilyID:    s.GenerateToken()[:16], // Shorter family ID
		ClientID:    clientID,
		UserID:      userID,
		Scope:       scope,
		CreatedAt:   time.Now(),
		LastRotated: time.Now(),
		TokenCount:  1,
		ExpiresAt:   time.Now().Add(ttl),
	}

	familyKey := s.tokenFamilyKey(family.FamilyID)
	familyData, _ := json.Marshal(family)
	s.redis.Client.Set(ctx, familyKey, familyData, ttl)

	return family
}

func (s *Store) getOrCreateFamily(ctx context.Context, clientID, userID, scope, familyID string, ttl time.Duration) *RefreshTokenFamily {
	familyKey := s.tokenFamilyKey(familyID)
	data, err := s.redis.Client.Get(ctx, familyKey).Result()

	if err == nil {
		var family RefreshTokenFamily
		if json.Unmarshal([]byte(data), &family) == nil {
			return &family
		}
	}

	// Family doesn't exist, create a new one
	return s.createFamily(ctx, clientID, userID, scope, ttl)
}
