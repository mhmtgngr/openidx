// Package mfa provides Multi-Factor Authentication functionality for OpenIDX
package mfa

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// Redis key prefixes for OTP tracking
	redisOTPPrefix        = "mfa:otp:"
	redisOTPRateLimitPrefix = "mfa:otp:ratelimit:"
	redisOTPAttemptsPrefix  = "mfa:otp:attempts:"

	// Default OTP configuration
	DefaultOTPLength  = 6                 // 6-digit code
	DefaultOTPExpiry  = 5 * time.Minute   // 5 minutes
	DefaultMaxAttempts = 3                // Max verification attempts
	OTPRateLimitWindow = 60 * time.Second // 1 OTP per 60 seconds
)

// OTPRedisClient extends the base RedisClient with TTL support
type OTPRedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	TTL(ctx context.Context, key string) *redis.DurationCmd
}

// OTPType represents the type of OTP delivery
type OTPType string

const (
	OTPTypeEmail OTPType = "EMAIL"
	OTPTypeSMS   OTPType = "SMS"
)

// OTPConfig holds configuration for OTP generation and validation
type OTPConfig struct {
	Length    int           // Number of digits (default: 6)
	Expiry    time.Duration // TTL in seconds (default: 300)
	MaxAttempts int         // Max verification attempts (default: 3)
	RateLimit time.Duration // Min time between OTPs (default: 60s)
}

// DefaultOTPConfig returns the default OTP configuration
func DefaultOTPConfig() *OTPConfig {
	return &OTPConfig{
		Length:     DefaultOTPLength,
		Expiry:     DefaultOTPExpiry,
		MaxAttempts: DefaultMaxAttempts,
		RateLimit:  OTPRateLimitWindow,
	}
}

// OTPCode represents a generated OTP code
type OTPCode struct {
	Code      string    `json:"code"`       // The OTP code (only exposed during generation)
	UserID    uuid.UUID `json:"user_id"`
	Type      OTPType   `json:"type"`       // EMAIL or SMS
	Destination string  `json:"destination"` // Email address or phone number
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// OTPService provides one-time password functionality for email and SMS
type OTPService struct {
	config       *OTPConfig
	redis        OTPRedisClient
	logger       *zap.Logger
	provider     Provider
	messagePrefix string
}

// NewOTPService creates a new OTP service
func NewOTPService(logger *zap.Logger, redis OTPRedisClient, provider Provider, config *OTPConfig) *OTPService {
	if config == nil {
		config = DefaultOTPConfig()
	}

	return &OTPService{
		config:        config,
		redis:         redis,
		logger:        logger,
		provider:      provider,
		messagePrefix: "OpenIDX", // Default prefix
	}
}

// NewOTPServiceWithPrefix creates a new OTP service with a custom message prefix
func NewOTPServiceWithPrefix(logger *zap.Logger, redis OTPRedisClient, provider Provider, config *OTPConfig, prefix string) *OTPService {
	service := NewOTPService(logger, redis, provider, config)
	service.messagePrefix = prefix
	return service
}

// GenerateOTP generates a new OTP code for a user
// Returns the generated code (for sending) and any error
func (s *OTPService) GenerateOTP(ctx context.Context, userID uuid.UUID, otpType OTPType, destination string) (*OTPCode, error) {
	// Check rate limit - user can only request 1 OTP per rate limit window
	rateLimitKey := s.buildRateLimitKey(userID, otpType)
	if err := s.checkRateLimit(ctx, rateLimitKey); err != nil {
		s.logger.Warn("OTP generation rate limit exceeded",
			zap.String("user_id", userID.String()),
			zap.String("type", string(otpType)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("rate limit exceeded: %w", err)
	}

	// Generate a cryptographically random 6-digit code
	code, err := s.generateCode()
	if err != nil {
		s.logger.Error("Failed to generate OTP code",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to generate code: %w", err)
	}

	now := time.Now()
	otp := &OTPCode{
		Code:        code,
		UserID:      userID,
		Type:        otpType,
		Destination: destination,
		ExpiresAt:   now.Add(s.config.Expiry),
		CreatedAt:   now,
	}

	// Store the OTP in Redis with TTL
	otpKey := s.buildOTPKey(userID, otpType)
	if err := s.storeOTP(ctx, otpKey, code); err != nil {
		s.logger.Error("Failed to store OTP",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to store OTP: %w", err)
	}

	// Reset attempt counter
	attemptsKey := s.buildAttemptsKey(userID, otpType)
	_ = s.redis.Del(ctx, attemptsKey)

	// Set rate limit
	if err := s.setRateLimit(ctx, rateLimitKey); err != nil {
		s.logger.Error("Failed to set rate limit",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		// Don't fail if we can't set rate limit
	}

	s.logger.Info("OTP generated",
		zap.String("user_id", userID.String()),
		zap.String("type", string(otpType)),
		zap.String("destination", maskDestination(destination, otpType)),
	)

	return otp, nil
}

// VerifyOTP verifies an OTP code for a user
// Returns true if valid, false otherwise
func (s *OTPService) VerifyOTP(ctx context.Context, userID uuid.UUID, otpType OTPType, code string) (bool, error) {
	// Check attempt counter
	attemptsKey := s.buildAttemptsKey(userID, otpType)
	attempts, err := s.getAttemptCount(ctx, attemptsKey)
	if err != nil {
		s.logger.Error("Failed to get attempt count",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		// Continue anyway - don't block on error
	}

	if attempts >= s.config.MaxAttempts {
		s.logger.Warn("OTP verification max attempts exceeded",
			zap.String("user_id", userID.String()),
			zap.Int("attempts", attempts),
		)
		// Delete the OTP to prevent further attempts
		otpKey := s.buildOTPKey(userID, otpType)
		_ = s.redis.Del(ctx, otpKey)
		return false, fmt.Errorf("max verification attempts exceeded")
	}

	// Get the stored OTP
	otpKey := s.buildOTPKey(userID, otpType)
	storedCode, err := s.getOTP(ctx, otpKey)
	if err != nil {
		if err == redis.Nil {
			// OTP doesn't exist or expired
			s.logger.Warn("OTP not found or expired",
				zap.String("user_id", userID.String()),
			)
			return false, fmt.Errorf("OTP not found or expired")
		}
		s.logger.Error("Failed to get OTP",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return false, fmt.Errorf("failed to retrieve OTP: %w", err)
	}

	// Normalize both codes for comparison
	normalizedInput := strings.TrimSpace(code)
	normalizedStored := strings.TrimSpace(storedCode)

	// Compare codes
	if normalizedInput != normalizedStored {
		// Increment attempt counter
		attempts++
		_ = s.setAttemptCount(ctx, attemptsKey, attempts)

		s.logger.Warn("OTP verification failed",
			zap.String("user_id", userID.String()),
			zap.Int("attempt", attempts),
			zap.Int("max_attempts", s.config.MaxAttempts),
		)

		return false, nil
	}

	// OTP is valid - delete it to prevent reuse
	_ = s.redis.Del(ctx, otpKey)
	_ = s.redis.Del(ctx, attemptsKey)

	s.logger.Info("OTP verified successfully",
		zap.String("user_id", userID.String()),
		zap.String("type", string(otpType)),
	)

	return true, nil
}

// SendOTP sends an OTP code via the configured provider
func (s *OTPService) SendOTP(ctx context.Context, otp *OTPCode) error {
	var message string

	switch otp.Type {
	case OTPTypeEmail:
		message = s.formatEmailMessage(otp)
		return s.provider.SendEmail(ctx, otp.Destination, "Your Verification Code", message)
	case OTPTypeSMS:
		message = s.formatSMSMessage(otp)
		return s.provider.SendSMS(ctx, otp.Destination, message)
	default:
		return fmt.Errorf("unsupported OTP type: %s", otp.Type)
	}
}

// GenerateAndSendOTP generates and sends an OTP code in one operation
func (s *OTPService) GenerateAndSendOTP(ctx context.Context, userID uuid.UUID, otpType OTPType, destination string) error {
	otp, err := s.GenerateOTP(ctx, userID, otpType, destination)
	if err != nil {
		return err
	}

	return s.SendOTP(ctx, otp)
}

// generateCode generates a cryptographically random numeric code
func (s *OTPService) generateCode() (string, error) {
	max := big.NewInt(1000000) // 10^6 for 6 digits
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate random number: %w", err)
	}

	// Format as 6-digit with leading zeros
	code := fmt.Sprintf("%0*d", s.config.Length, n)
	return code, nil
}

// storeOTP stores an OTP code in Redis with TTL
func (s *OTPService) storeOTP(ctx context.Context, key, code string) error {
	return s.redis.Set(ctx, key, code, s.config.Expiry).Err()
}

// getOTP retrieves an OTP code from Redis
func (s *OTPService) getOTP(ctx context.Context, key string) (string, error) {
	result := s.redis.Get(ctx, key)
	return result.Result()
}

// checkRateLimit checks if the user can generate a new OTP
func (s *OTPService) checkRateLimit(ctx context.Context, key string) error {
	result := s.redis.Get(ctx, key)
	if result.Err() == redis.Nil {
		return nil // No rate limit hit yet
	}
	if result.Err() != nil {
		return fmt.Errorf("redis error: %w", result.Err())
	}

	return fmt.Errorf("rate limit: please wait before requesting another code")
}

// setRateLimit sets a rate limit key
func (s *OTPService) setRateLimit(ctx context.Context, key string) error {
	return s.redis.Set(ctx, key, "1", s.config.RateLimit).Err()
}

// getAttemptCount gets the current attempt count
func (s *OTPService) getAttemptCount(ctx context.Context, key string) (int, error) {
	result := s.redis.Get(ctx, key)
	if result.Err() == redis.Nil {
		return 0, nil
	}
	if result.Err() != nil {
		return 0, result.Err()
	}

	var count int
	if _, err := fmt.Sscanf(result.Val(), "%d", &count); err != nil {
		return 0, nil
	}

	return count, nil
}

// setAttemptCount sets the attempt count
func (s *OTPService) setAttemptCount(ctx context.Context, key string, count int) error {
	return s.redis.Set(ctx, key, fmt.Sprintf("%d", count), s.config.Expiry).Err()
}

// formatEmailMessage formats an email message with the OTP code
func (s *OTPService) formatEmailMessage(otp *OTPCode) string {
	return fmt.Sprintf(`Your %s verification code is: %s

This code will expire in %d minutes.

If you did not request this code, please ignore this email.`,
		s.messagePrefix,
		otp.Code,
		int(s.config.Expiry.Minutes()),
	)
}

// formatSMSMessage formats an SMS message with the OTP code
func (s *OTPService) formatSMSMessage(otp *OTPCode) string {
	return fmt.Sprintf("%s: Your verification code is %s. Valid for %d minutes.",
		s.messagePrefix,
		otp.Code,
		int(s.config.Expiry.Minutes()),
	)
}

// maskDestination masks a destination (email or phone) for logging
func maskDestination(dest string, otpType OTPType) string {
	if dest == "" {
		return ""
	}

	switch otpType {
	case OTPTypeEmail:
		// Mask email: user***@domain.com
		parts := strings.Split(dest, "@")
		if len(parts) != 2 {
			return "***"
		}
		username := parts[0]
		domain := parts[1]
		if len(username) > 3 {
			username = username[:3] + "***"
		} else {
			username = "***"
		}
		return username + "@" + domain

	case OTPTypeSMS:
		// Mask phone: +1******5555
		if len(dest) < 4 {
			return "***"
		}
		return dest[:2] + "***" + dest[len(dest)-4:]

	default:
		return "***"
	}
}

// Redis key builders
func (s *OTPService) buildOTPKey(userID uuid.UUID, otpType OTPType) string {
	return fmt.Sprintf("%s%s:%s", redisOTPPrefix, userID.String(), strings.ToLower(string(otpType)))
}

func (s *OTPService) buildRateLimitKey(userID uuid.UUID, otpType OTPType) string {
	return fmt.Sprintf("%s%s:%s", redisOTPRateLimitPrefix, userID.String(), strings.ToLower(string(otpType)))
}

func (s *OTPService) buildAttemptsKey(userID uuid.UUID, otpType OTPType) string {
	return fmt.Sprintf("%s%s:%s", redisOTPAttemptsPrefix, userID.String(), strings.ToLower(string(otpType)))
}

// DeleteOTP removes an OTP from Redis (useful for cancellation)
func (s *OTPService) DeleteOTP(ctx context.Context, userID uuid.UUID, otpType OTPType) error {
	otpKey := s.buildOTPKey(userID, otpType)
	attemptsKey := s.buildAttemptsKey(userID, otpType)

	// Delete both the OTP and attempt counter
	if err := s.redis.Del(ctx, otpKey, attemptsKey).Err(); err != nil {
		return fmt.Errorf("failed to delete OTP: %w", err)
	}

	s.logger.Info("OTP deleted",
		zap.String("user_id", userID.String()),
		zap.String("type", string(otpType)),
	)

	return nil
}

// GetRemainingTime returns the remaining time before an OTP expires
func (s *OTPService) GetRemainingTime(ctx context.Context, userID uuid.UUID, otpType OTPType) (time.Duration, error) {
	otpKey := s.buildOTPKey(userID, otpType)

	result := s.redis.TTL(ctx, otpKey)
	if result.Err() != nil {
		return 0, fmt.Errorf("failed to get TTL: %w", result.Err())
	}

	return result.Val(), nil
}

// GetRemainingAttempts returns the remaining verification attempts
func (s *OTPService) GetRemainingAttempts(ctx context.Context, userID uuid.UUID, otpType OTPType) (int, error) {
	attemptsKey := s.buildAttemptsKey(userID, otpType)

	attempts, err := s.getAttemptCount(ctx, attemptsKey)
	if err != nil {
		return s.config.MaxAttempts, nil
	}

	remaining := s.config.MaxAttempts - attempts
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}
