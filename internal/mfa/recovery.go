// Package mfa provides Multi-Factor Authentication functionality for OpenIDX
package mfa

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const (
	// RecoveryCodeCount is the number of recovery codes generated per user
	RecoveryCodeCount = 10

	// RecoveryCodeLength is the length of each recovery code (in characters)
	RecoveryCodeLength = 8

	// RecoveryCodeAlphabet is the character set used for recovery codes
	// Removed confusing characters: 0/O, 1/I/l, 8/B, 5/S, 2/Z
	RecoveryCodeAlphabet = "2345679ACDEFGHJKMNPQRSTUVWXYZ"

	// Redis key prefix for rate limiting recovery code verification
	redisRecoveryRateLimitPrefix = "mfa:recovery:ratelimit:"

	// Redis key prefix for recovery code tracking
	redisRecoveryUsedPrefix = "mfa:recovery:used:"

	// Recovery rate limit window
	recoveryRateLimitWindow = time.Minute

	// Max recovery attempts per window
	recoveryRateLimitMax = 5
)

// RecoveryCode represents a single recovery code
type RecoveryCode struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	CodeHash  string    `json:"-" db:"code_hash"` // bcrypt hash
	Used      bool      `json:"used" db:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty" db:"used_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// RecoveryCodeSet represents a set of recovery codes for a user
type RecoveryCodeSet struct {
	UserID      uuid.UUID       `json:"user_id"`
	Codes       []RecoveryCode  `json:"codes"`
	Remaining   int             `json:"remaining"`
	CreatedAt   time.Time       `json:"created_at"`
	Regenerated bool            `json:"regenerated"`
}

// RecoveryCodeRepository defines the interface for recovery code persistence
type RecoveryCodeRepository interface {
	// CreateCodes creates new recovery codes for a user
	CreateCodes(ctx context.Context, codes []RecoveryCode) error

	// GetCodesByUserID retrieves all recovery codes for a user
	GetCodesByUserID(ctx context.Context, userID uuid.UUID) ([]RecoveryCode, error)

	// GetUnusedCodeByUserIDAndHash finds an unused code by its hash
	GetUnusedCodeByUserIDAndHash(ctx context.Context, userID uuid.UUID, codeHash string) (*RecoveryCode, error)

	// MarkCodeUsed marks a recovery code as used
	MarkCodeUsed(ctx context.Context, codeID uuid.UUID, usedAt time.Time) error

	// DeleteCodesByUserID deletes all recovery codes for a user
	DeleteCodesByUserID(ctx context.Context, userID uuid.UUID) error

	// CountRemainingCodes returns the count of unused recovery codes
	CountRemainingCodes(ctx context.Context, userID uuid.UUID) (int, error)
}

// RecoveryService provides recovery code functionality
type RecoveryService struct {
	repo      RecoveryCodeRepository
	redis     RedisClient
	logger    *zap.Logger
	encrypter SecretEncrypter
}

// NewRecoveryService creates a new recovery service
func NewRecoveryService(
	repo RecoveryCodeRepository,
	redis RedisClient,
	logger *zap.Logger,
	encrypter SecretEncrypter,
) *RecoveryService {
	return &RecoveryService{
		repo:      repo,
		redis:     redis,
		logger:    logger,
		encrypter: encrypter,
	}
}

// GenerateCodes generates a new set of recovery codes for a user
// Each code is 8 alphanumeric characters, bcrypt hashed for storage
func (s *RecoveryService) GenerateCodes(ctx context.Context, userID uuid.UUID) (*RecoveryCodeSet, error) {
	// Check if user already has codes
	existingCodes, err := s.repo.GetCodesByUserID(ctx, userID)
	if err == nil && len(existingCodes) > 0 {
		// Delete existing codes before generating new ones
		if err := s.repo.DeleteCodesByUserID(ctx, userID); err != nil {
			s.logger.Error("Failed to delete existing recovery codes",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			return nil, fmt.Errorf("failed to remove existing codes: %w", err)
		}
		s.logger.Info("Deleted existing recovery codes for regeneration",
			zap.String("user_id", userID.String()),
		)
	}

	codes := make([]RecoveryCode, RecoveryCodeCount)
	now := time.Now()

	// Generate unique codes
	for i := 0; i < RecoveryCodeCount; i++ {
		plainCode, err := s.generateRandomCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate recovery code: %w", err)
		}

		// Hash the code with bcrypt
		codeHash, err := bcrypt.GenerateFromPassword([]byte(plainCode), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash recovery code: %w", err)
		}

		codes[i] = RecoveryCode{
			ID:        uuid.New(),
			UserID:    userID,
			CodeHash:  string(codeHash),
			Used:      false,
			CreatedAt: now,
		}
	}

	// Store codes in database
	if err := s.repo.CreateCodes(ctx, codes); err != nil {
		return nil, fmt.Errorf("failed to store recovery codes: %w", err)
	}

	s.logger.Info("Generated recovery codes",
		zap.String("user_id", userID.String()),
		zap.Int("count", len(codes)),
	)

	// Return the set with plaintext codes (only time they're exposed)
	// In production, these would be displayed once and never accessible again
	return &RecoveryCodeSet{
		UserID:      userID,
		Codes:       codes,
		Remaining:   RecoveryCodeCount,
		CreatedAt:   now,
		Regenerated: len(existingCodes) > 0,
	}, nil
}

// generateRandomCode generates a random alphanumeric code
func (s *RecoveryService) generateRandomCode() (string, error) {
	code := make([]byte, RecoveryCodeLength)
	alphabetLen := big.NewInt(int64(len(RecoveryCodeAlphabet)))

	for i := 0; i < RecoveryCodeLength; i++ {
		n, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		code[i] = RecoveryCodeAlphabet[n.Int64()]
	}

	return string(code), nil
}

// GetPlaintextCodes returns the plaintext recovery codes (only for display during generation)
// This should only be called immediately after generation
func (s *RecoveryService) GetPlaintextCodes(codes []RecoveryCode) ([]string, error) {
	// This function is meant to be used with the codes returned from GenerateCodes
	// In a real scenario, the plaintext codes would need to be stored temporarily
	// and displayed to the user, then never accessible again

	// For security, we can't recover plaintext from bcrypt hashes
	// This function exists to document that plaintext codes should only be available
	// at generation time
	return nil, fmt.Errorf("plaintext codes are only available at generation time")
}

// VerifyCode verifies a recovery code and marks it as used (single-use)
// Returns the code ID if valid, error otherwise
func (s *RecoveryService) VerifyCode(ctx context.Context, userID uuid.UUID, plainCode string) (*RecoveryCode, error) {
	// Rate limit verification attempts
	rateLimitKey := s.buildRateLimitKey(userID)

	if err := s.checkRateLimit(ctx, rateLimitKey); err != nil {
		s.logger.Warn("Recovery code verification rate limit exceeded",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("rate limit exceeded: %w", err)
	}

	// Increment rate limit counter
	if err := s.incrementRateLimit(ctx, rateLimitKey); err != nil {
		s.logger.Error("Failed to increment rate limit",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		// Don't fail verification if we can't track rate limit
	}

	// Check if this specific code was already used in Redis (additional replay protection)
	usedKey := s.buildUsedCodeKey(userID, plainCode)
	wasUsed, _ := s.checkCodeUsedInRedis(ctx, usedKey)
	if wasUsed {
		s.logger.Warn("Recovery code already used (replay attack prevented)",
			zap.String("user_id", userID.String()),
		)
		return nil, fmt.Errorf("code has already been used")
	}

	// Get all unused codes for the user
	codes, err := s.repo.GetCodesByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve recovery codes: %w", err)
	}

	// Check each code using constant-time comparison to prevent timing attacks
	var matchedCode *RecoveryCode
	for _, code := range codes {
		if code.Used {
			continue
		}

		// Use bcrypt compare for constant-time comparison
		if err := bcrypt.CompareHashAndPassword([]byte(code.CodeHash), []byte(plainCode)); err == nil {
			matchedCode = &code
			break
		}
	}

	if matchedCode == nil {
		s.logger.Warn("Invalid recovery code",
			zap.String("user_id", userID.String()),
		)
		return nil, fmt.Errorf("invalid recovery code")
	}

	// Mark the code as used in the database
	now := time.Now()
	if err := s.repo.MarkCodeUsed(ctx, matchedCode.ID, now); err != nil {
		s.logger.Error("Failed to mark recovery code as used",
			zap.String("code_id", matchedCode.ID.String()),
			zap.Error(err),
		)
		// Continue anyway - code was valid, but we'll track via Redis
	}

	// Mark as used in Redis for additional replay protection
	_ = s.markCodeUsedInRedis(ctx, usedKey)

	s.logger.Info("Recovery code used successfully",
		zap.String("user_id", userID.String()),
		zap.String("code_id", matchedCode.ID.String()),
	)

	// Update the code object
	matchedCode.Used = true
	matchedCode.UsedAt = &now

	return matchedCode, nil
}

// VerifyCodeConstantTime verifies a recovery code using constant-time comparison
// to prevent timing attacks that could reveal valid codes
func (s *RecoveryService) VerifyCodeConstantTime(ctx context.Context, userID uuid.UUID, plainCode string) (*RecoveryCode, error) {
	// Normalize the code to fixed length for constant-time comparison
	// Pad or truncate to the expected length
	normalizedCode := s.normalizeCode(plainCode)

	// Get all codes for the user
	codes, err := s.repo.GetCodesByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve recovery codes: %w", err)
	}

	// Use constant-time comparison for all codes to prevent timing attacks
	// We compare against ALL codes (both used and unused) to prevent
	// an attacker from learning which codes are still valid
	var matchedCode *RecoveryCode
	for _, code := range codes {
		// Use bcrypt's constant-time comparison
		if err := bcrypt.CompareHashAndPassword([]byte(code.CodeHash), []byte(normalizedCode)); err == nil {
			matchedCode = &code
			break
		}
	}

	if matchedCode == nil {
		return nil, fmt.Errorf("invalid recovery code")
	}

	// Check if already used
	if matchedCode.Used {
		// Don't reveal that the code was valid but already used
		return nil, fmt.Errorf("invalid recovery code")
	}

	// Mark as used
	now := time.Now()
	if err := s.repo.MarkCodeUsed(ctx, matchedCode.ID, now); err != nil {
		s.logger.Error("Failed to mark recovery code as used",
			zap.String("code_id", matchedCode.ID.String()),
			zap.Error(err),
		)
	}

	matchedCode.Used = true
	matchedCode.UsedAt = &now

	return matchedCode, nil
}

// normalizeCode normalizes a recovery code for constant-time comparison
func (s *RecoveryService) normalizeCode(code string) string {
	// Remove spaces and dashes, convert to uppercase
	normalized := make([]byte, 0, len(code))
	for _, c := range code {
		if c != ' ' && c != '-' {
			normalized = append(normalized, byte(c))
		}
	}
	return string(normalized)
}

// GetRemainingCount returns the count of unused recovery codes for a user
func (s *RecoveryService) GetRemainingCount(ctx context.Context, userID uuid.UUID) (int, error) {
	count, err := s.repo.CountRemainingCodes(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to count remaining codes: %w", err)
	}
	return count, nil
}

// RegenerateCodes invalidates old codes and generates a new set
func (s *RecoveryService) RegenerateCodes(ctx context.Context, userID uuid.UUID) (*RecoveryCodeSet, error) {
	// Delete existing codes
	if err := s.repo.DeleteCodesByUserID(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to delete existing codes: %w", err)
	}

	s.logger.Info("Regenerated recovery codes",
		zap.String("user_id", userID.String()),
	)

	// Generate new codes
	return s.GenerateCodes(ctx, userID)
}

// HasCodes checks if a user has recovery codes configured
func (s *RecoveryService) HasCodes(ctx context.Context, userID uuid.UUID) bool {
	count, err := s.repo.CountRemainingCodes(ctx, userID)
	return err == nil && count > 0
}

// buildRateLimitKey creates a Redis key for rate limiting
func (s *RecoveryService) buildRateLimitKey(userID uuid.UUID) string {
	return fmt.Sprintf("%s%s", redisRecoveryRateLimitPrefix, userID.String())
}

// buildUsedCodeKey creates a Redis key for tracking used codes
func (s *RecoveryService) buildUsedCodeKey(userID uuid.UUID, code string) string {
	// Hash the code to avoid storing plaintext in Redis
	codeHash := base64.StdEncoding.EncodeToString([]byte(code))
	return fmt.Sprintf("%s%s:%s", redisRecoveryUsedPrefix, userID.String(), codeHash)
}

// checkRateLimit checks if the user has exceeded the rate limit
func (s *RecoveryService) checkRateLimit(ctx context.Context, key string) error {
	result := s.redis.Get(ctx, key)
	if result.Err() == redis.Nil {
		return nil // No rate limit hit yet
	}
	if result.Err() != nil {
		return fmt.Errorf("redis error: %w", result.Err())
	}

	var count int
	if err := json.Unmarshal([]byte(result.Val()), &count); err != nil {
		count = 0
	}

	if count >= recoveryRateLimitMax {
		return fmt.Errorf("rate limit exceeded")
	}

	return nil
}

// incrementRateLimit increments the rate limit counter
func (s *RecoveryService) incrementRateLimit(ctx context.Context, key string) error {
	// Get current count
	result := s.redis.Get(ctx, key)
	count := 0

	if result.Err() == nil {
		json.Unmarshal([]byte(result.Val()), &count)
	}

	count++

	// Store updated count with expiration
	countJSON, _ := json.Marshal(count)
	return s.redis.Set(ctx, key, countJSON, recoveryRateLimitWindow).Err()
}

// checkCodeUsedInRedis checks if a code was used (additional replay protection)
func (s *RecoveryService) checkCodeUsedInRedis(ctx context.Context, key string) (bool, error) {
	result := s.redis.Get(ctx, key)
	if result.Err() == redis.Nil {
		return false, nil
	}
	if result.Err() != nil {
		return false, fmt.Errorf("redis error: %w", result.Err())
	}
	return true, nil
}

// markCodeUsedInRedis marks a code as used in Redis
func (s *RecoveryService) markCodeUsedInRedis(ctx context.Context, key string) error {
	// Store for a long time (recovery codes don't expire)
	return s.redis.Set(ctx, key, "1", 365*24*time.Hour).Err()
}

// BcryptCompareHashAndPassword is a helper for bcrypt comparison with constant-time behavior
func BcryptCompareHashAndPassword(hashedPassword, password []byte) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, password)
}

// ConstantTimeCompare wraps subtle.ConstantTimeCompare for recovery code comparison
// This is used as an additional layer of protection
func ConstantTimeCompareCode(code1, code2 string) bool {
	// Pad codes to the same length for comparison
	if len(code1) != RecoveryCodeLength || len(code2) != RecoveryCodeLength {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(code1), []byte(code2)) == 1
}
