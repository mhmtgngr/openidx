// Package mfa provides Multi-Factor Authentication functionality for OpenIDX
package mfa

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// DefaultTOTP_ISSUER is the default issuer name for TOTP
	DefaultTOTPIssuer = "OpenIDX"

	// DefaultTOTPPeriod is the default time step in seconds (RFC 6238 recommends 30)
	DefaultTOTPPeriod = 30

	// DefaultTOTPDigits is the default number of digits (6 or 8)
	DefaultTOTPDigits = 6

	// DefaultTOTPAlgorithm is the default algorithm (SHA1, SHA256, SHA512)
	DefaultTOTPAlgorithm = totp.AlgorithmSHA1

	// DefaultTOTPWindow is the default time window for validation (allows clock skew)
	// Window of 1 means +/-1 time step, allowing for clock drift tolerance
	DefaultTOTPWindow = 1

	// DefaultSecretLength is the default length for TOTP secrets in bytes (RFC 6238 recommends 20)
	DefaultSecretLength = 20

	// Redis key prefix for used code tracking (replay attack prevention)
	redisUsedCodePrefix = "mfa:totp:used:"

	// Redis key TTL for used codes (slightly longer than the window * period)
	redisUsedCodeTTL = 5 * time.Minute

	// Redis key prefix for rate limiting TOTP verification attempts
	redisRateLimitPrefix = "mfa:totp:ratelimit:"

	// Rate limit window for TOTP verification (5 attempts per minute)
	rateLimitWindow = time.Minute

	// Max verification attempts per rate limit window
	rateLimitMaxAttempts = 5
)

// TOTPSecret represents a TOTP secret with its QR code URL
type TOTPSecret struct {
	Secret     string `json:"secret"`      // Base32-encoded secret
	AccountName string `json:"account_name"` // Account name (typically username or email)
	Issuer      string `json:"issuer"`      // Issuer name (e.g., "OpenIDX")
	QRCodeURL   string `json:"qr_code_url"` // URL for QR code generation
	CreatedAt   time.Time `json:"created_at"`
}

// TOTPConfig holds configuration for TOTP generation and validation
type TOTPConfig struct {
	Issuer   string        // Issuer name for TOTP
	Period   uint          // Time step period in seconds
	Digits   totp.Digits   // Number of digits (6 or 8)
	Algorithm totp.Algorithm // Hash algorithm
	SecretLength int       // Length of generated secret in bytes
}

// DefaultTOTPConfig returns the default TOTP configuration
func DefaultTOTPConfig() *TOTPConfig {
	return &TOTPConfig{
		Issuer:     DefaultTOTPIssuer,
		Period:    DefaultTOTPPeriod,
		Digits:    totp.Digits(DefaultTOTPDigits),
		Algorithm: DefaultTOTPAlgorithm,
		SecretLength: DefaultSecretLength,
	}
}

// Service provides TOTP functionality
type Service struct {
	config     *TOTPConfig
	logger     *zap.Logger
	redis      RedisClient
	encrypter  SecretEncrypter
}

// RedisClient defines the interface for Redis operations (for replay attack prevention)
type RedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
}

// SecretEncrypter defines the interface for encrypting TOTP secrets at rest
type SecretEncrypter interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// NewService creates a new TOTP service
func NewService(logger *zap.Logger, redis RedisClient, encrypter SecretEncrypter) *Service {
	return &Service{
		config:    DefaultTOTPConfig(),
		logger:    logger,
		redis:     redis,
		encrypter: encrypter,
	}
}

// NewServiceWithConfig creates a new TOTP service with custom configuration
func NewServiceWithConfig(logger *zap.Logger, redis RedisClient, encrypter SecretEncrypter, config *TOTPConfig) *Service {
	return &Service{
		config:    config,
		logger:    logger,
		redis:     redis,
		encrypter: encrypter,
	}
}

// GenerateSecret generates a new TOTP secret for a user
func (s *Service) GenerateSecret(userID, accountName string) (*TOTPSecret, error) {
	if accountName == "" {
		accountName = userID
	}

	// Generate a new TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.config.Issuer,
		AccountName: accountName,
		Period:      s.config.Period,
		Digits:      s.config.Digits,
		Algorithm:   s.config.Algorithm,
		SecretSize:  s.config.SecretLength,
	})
	if err != nil {
		s.logger.Error("Failed to generate TOTP secret",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	secret := &TOTPSecret{
		Secret:      key.Secret(),
		AccountName: accountName,
		Issuer:      s.config.Issuer,
		QRCodeURL:   key.URL(),
		CreatedAt:   time.Now(),
	}

	s.logger.Info("Generated TOTP secret",
		zap.String("user_id", userID),
		zap.String("account_name", accountName),
	)

	return secret, nil
}

// ValidateCode validates a TOTP code with configurable time step window
// Uses constant-time comparison to prevent timing attacks
func (s *Service) ValidateCode(secret, code string, window int) (bool, error) {
	if secret == "" {
		return false, fmt.Errorf("secret cannot be empty")
	}
	if code == "" {
		return false, fmt.Errorf("code cannot be empty")
	}

	// Validate the TOTP code with configurable window
	valid, err := totp.ValidateCustom(
		code,
		secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    s.config.Period,
			Digits:    s.config.Digits,
			Algorithm: s.config.Algorithm,
		},
	)
	if err != nil {
		s.logger.Error("TOTP validation error",
			zap.Error(err),
		)
		return false, fmt.Errorf("validation error: %w", err)
	}

	if !valid {
		// Try with the configured window
		if window > 0 {
			// Manually check adjacent time steps
			for i := -window; i <= window; i++ {
				if i == 0 {
					continue // Already checked
				}

				valid, err = totp.ValidateCustom(
					code,
					secret,
					time.Now().Add(time.Duration(i)*time.Duration(s.config.Period)*time.Second),
					totp.ValidateOpts{
						Period:    s.config.Period,
						Digits:    s.config.Digits,
						Algorithm: s.config.Algorithm,
					},
				)
				if err != nil {
					continue
				}
				if valid {
					s.logger.Debug("TOTP code validated with window",
						zap.Int("window_offset", i),
					)
					return true, nil
				}
			}
		}
		return false, nil
	}

	return true, nil
}

// ValidateCodeConstantTime validates a TOTP code using constant-time comparison
// This is more secure than ValidateCode as it prevents timing attacks
func (s *Service) ValidateCodeConstantTime(secret, code string, window int) (bool, error) {
	if secret == "" {
		return false, fmt.Errorf("secret cannot be empty")
	}
	if code == "" {
		return false, fmt.Errorf("code cannot be empty")
	}

	// Generate the expected code for current time
	expectedCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return false, fmt.Errorf("failed to generate expected code: %w", err)
	}

	// Use constant-time comparison to prevent timing attacks
	// This is important for TOTP validation
	if subtle.ConstantTimeCompare([]byte(code), []byte(expectedCode)) == 1 {
		return true, nil
	}

	// If window is configured, check adjacent time steps with constant-time comparison
	if window > 0 {
		for i := -window; i <= window; i++ {
			if i == 0 {
				continue
			}

			expectedCode, err := totp.GenerateCodeCustom(
				secret,
				time.Now().Add(time.Duration(i)*time.Duration(s.config.Period)*time.Second),
				totp.ValidateOpts{
					Period:    s.config.Period,
					Digits:    s.config.Digits,
					Algorithm: s.config.Algorithm,
				},
			)
			if err != nil {
				continue
			}

			if subtle.ConstantTimeCompare([]byte(code), []byte(expectedCode)) == 1 {
				s.logger.Debug("TOTP code validated with window using constant-time comparison",
					zap.Int("window_offset", i),
				)
				return true, nil
			}
		}
	}

	return false, nil
}

// EnrollTOTP handles the enrollment flow for TOTP
// It generates a secret, stores it encrypted, and returns the enrollment details
func (s *Service) EnrollTOTP(ctx context.Context, userID, accountName string) (*TOTPSecret, string, error) {
	// Generate the TOTP secret
	secret, err := s.GenerateSecret(userID, accountName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate secret: %w", err)
	}

	// Encrypt the secret for storage
	encryptedSecret, err := s.encrypter.Encrypt(secret.Secret)
	if err != nil {
		s.logger.Error("Failed to encrypt TOTP secret",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return nil, "", fmt.Errorf("failed to encrypt secret: %w", err)
	}

	s.logger.Info("TOTP enrollment initiated",
		zap.String("user_id", userID),
		zap.String("account_name", accountName),
	)

	return secret, encryptedSecret, nil
}

// VerifyTOTP validates a TOTP code during authentication or enrollment verification
// It includes replay attack prevention using Redis and rate limiting (5 attempts per minute)
func (s *Service) VerifyTOTP(ctx context.Context, userID, secret, code string) (bool, error) {
	if secret == "" {
		return false, fmt.Errorf("secret not found for user")
	}
	if code == "" {
		return false, fmt.Errorf("code cannot be empty")
	}

	// Check rate limit before proceeding
	rateLimitKey := s.buildRateLimitKey(userID)
	if err := s.checkRateLimit(ctx, rateLimitKey); err != nil {
		s.logger.Warn("TOTP verification rate limit exceeded",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return false, fmt.Errorf("rate limit exceeded: %w", err)
	}

	// Increment rate limit counter
	if err := s.incrementRateLimit(ctx, rateLimitKey); err != nil {
		s.logger.Error("Failed to increment rate limit",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		// Don't fail verification if we can't track rate limit
	}

	// Check for replay attacks - verify the code hasn't been used before
	usedCodeKey := s.buildUsedCodeKey(userID, code)

	// Check if this code was already used
	wasUsed, err := s.checkCodeUsed(ctx, usedCodeKey)
	if err != nil {
		s.logger.Error("Failed to check used code",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return false, fmt.Errorf("failed to check code usage: %w", err)
	}

	if wasUsed {
		s.logger.Warn("TOTP code already used (replay attack prevented)",
			zap.String("user_id", userID),
		)
		return false, nil // Code was already used, don't reveal if it was valid
	}

	// Validate the code using constant-time comparison with +/-1 window drift tolerance
	valid, err := s.ValidateCodeConstantTime(secret, code, DefaultTOTPWindow)
	if err != nil {
		return false, fmt.Errorf("validation failed: %w", err)
	}

	if valid {
		// Mark the code as used to prevent replay attacks
		if err := s.markCodeUsed(ctx, usedCodeKey); err != nil {
			s.logger.Error("Failed to mark code as used",
				zap.String("user_id", userID),
				zap.Error(err),
			)
			// Don't fail the authentication if we can't mark as used,
			// but log the error for monitoring
		}

		s.logger.Info("TOTP code validated successfully",
			zap.String("user_id", userID),
		)
		return true, nil
	}

	s.logger.Warn("TOTP code validation failed",
		zap.String("user_id", userID),
	)
	return false, nil
}

// buildUsedCodeKey creates a Redis key for tracking used codes
func (s *Service) buildUsedCodeKey(userID, code string) string {
	return fmt.Sprintf("%s%s:%s", redisUsedCodePrefix, userID, code)
}

// buildRateLimitKey creates a Redis key for rate limiting verification attempts
func (s *Service) buildRateLimitKey(userID string) string {
	return fmt.Sprintf("%s%s", redisRateLimitPrefix, userID)
}

// checkRateLimit checks if the user has exceeded the rate limit (5 attempts per minute)
func (s *Service) checkRateLimit(ctx context.Context, key string) error {
	result := s.redis.Get(ctx, key)
	if result.Err() == redis.Nil {
		return nil // No rate limit hit yet
	}
	if result.Err() != nil {
		return fmt.Errorf("redis error: %w", result.Err())
	}

	countStr := result.Val()
	if countStr == "" {
		return nil
	}

	var count int64
	if _, err := fmt.Sscanf(countStr, "%d", &count); err != nil {
		return nil
	}

	if count >= rateLimitMaxAttempts {
		return fmt.Errorf("rate limit exceeded")
	}

	return nil
}

// incrementRateLimit increments the rate limit counter for a user
func (s *Service) incrementRateLimit(ctx context.Context, key string) error {
	// Use Redis INCR with expiration
	result := s.redis.Get(ctx, key)
	count := int64(0)

	if result.Err() == nil {
		if countStr := result.Val(); countStr != "" {
			fmt.Sscanf(countStr, "%d", &count)
		}
	}

	count++

	// Store the updated count with expiration
	if err := s.redis.Set(ctx, key, fmt.Sprintf("%d", count), rateLimitWindow).Err(); err != nil {
		return fmt.Errorf("failed to set rate limit: %w", err)
	}

	return nil
}

// checkCodeUsed checks if a code has been used before (replay attack prevention)
func (s *Service) checkCodeUsed(ctx context.Context, key string) (bool, error) {
	result := s.redis.Get(ctx, key)
	if result.Err() == redis.Nil {
		return false, nil // Key doesn't exist, code hasn't been used
	}
	if result.Err() != nil {
		return false, fmt.Errorf("redis error: %w", result.Err())
	}
	return true, nil // Key exists, code was already used
}

// markCodeUsed marks a code as used to prevent replay attacks
func (s *Service) markCodeUsed(ctx context.Context, key string) error {
	return s.redis.Set(ctx, key, "1", redisUsedCodeTTL).Err()
}

// GenerateCode generates a TOTP code for a given secret (useful for testing)
func (s *Service) GenerateCode(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}

// GenerateCodeCustom generates a TOTP code for a given time (useful for testing)
func (s *Service) GenerateCodeCustom(secret string, t time.Time) (string, error) {
	return totp.GenerateCodeCustom(
		secret,
		t,
		totp.ValidateOpts{
			Period:    s.config.Period,
			Digits:    s.config.Digits,
			Algorithm: s.config.Algorithm,
		},
	)
}

// ValidateWithWindow validates a TOTP code with a custom time window
func (s *Service) ValidateWithWindow(secret, code string, window int) (bool, error) {
	return s.ValidateCodeConstantTime(secret, code, window)
}
