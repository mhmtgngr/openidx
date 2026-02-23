// Package mfa provides Multi-Factor Authentication service layer
package mfa

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"github.com/redis/go-redis/v9"
)

// MFAService provides high-level MFA operations combining TOTP logic and persistence
type MFAService struct {
	totp      *Service  // TOTPService from totp.go
	repo      Repository
	logger    *zap.Logger
	redis     *redis.Client
	encrypter SecretEncrypter
}

// NewMFAService creates a new MFA service
func NewMFAService(
	logger *zap.Logger,
	pool *pgxpool.Pool,
	redisClient *redis.Client,
	encrypter SecretEncrypter,
) *MFAService {
	repo := NewPostgreSQLRepository(pool, logger)
	totpService := NewService(logger, redisClient, encrypter)

	return &MFAService{
		totp:      totpService,
		repo:      repo,
		logger:    logger,
		redis:     redisClient,
		encrypter: encrypter,
	}
}

// EnrollTOTP initiates TOTP enrollment for a user
// Returns the enrollment details with QR code URL and stores the encrypted secret
func (s *MFAService) EnrollTOTP(ctx context.Context, userID uuid.UUID, accountName string) (*TOTPSecret, error) {
	// Check if user already has TOTP enrolled
	existing, err := s.repo.GetTOTPByUserID(ctx, userID)
	if err == nil && existing != nil {
		// User already has TOTP - return error or allow re-enrollment?
		// For now, allow re-enrollment by deleting the old one
		if err := s.repo.DeleteTOTP(ctx, userID); err != nil {
			s.logger.Error("Failed to delete existing TOTP enrollment",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			return nil, fmt.Errorf("failed to remove existing enrollment: %w", err)
		}
		s.logger.Info("Removed existing TOTP enrollment for re-enrollment",
			zap.String("user_id", userID.String()),
		)
	}

	// Generate TOTP secret
	secret, encryptedSecret, err := s.totp.EnrollTOTP(ctx, userID.String(), accountName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Store enrollment in database
	enrollment := &TOTPEnrollment{
		ID:          uuid.New(),
		UserID:      userID,
		Secret:      encryptedSecret,
		AccountName: secret.AccountName,
		Verified:    false,
		Enabled:     false,
		CreatedAt:   time.Now(),
	}

	if err := s.repo.CreateTOTP(ctx, enrollment); err != nil {
		s.logger.Error("Failed to store TOTP enrollment",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to store enrollment: %w", err)
	}

	s.logger.Info("TOTP enrollment created",
		zap.String("user_id", userID.String()),
		zap.String("account_name", secret.AccountName),
	)

	return secret, nil
}

// VerifyAndEnableTOTP verifies a TOTP code during enrollment and enables the factor
func (s *MFAService) VerifyAndEnableTOTP(ctx context.Context, userID uuid.UUID, code string) error {
	// Get the enrollment
	enrollment, err := s.repo.GetTOTPByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("totp enrollment not found: %w", err)
	}

	// Decrypt the secret
	secret, err := s.encrypter.Decrypt(enrollment.Secret)
	if err != nil {
		s.logger.Error("Failed to decrypt TOTP secret",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("failed to decrypt secret: %w", err)
	}

	// Verify the code
	valid, err := s.totp.VerifyTOTP(ctx, userID.String(), secret, code)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}

	// Mark as verified and enabled
	if err := s.repo.VerifyTOTP(ctx, userID); err != nil {
		return fmt.Errorf("failed to verify enrollment: %w", err)
	}

	// Enable the factor
	enrollment.Verified = true
	enrollment.Enabled = true
	if err := s.repo.UpdateTOTP(ctx, enrollment); err != nil {
		return fmt.Errorf("failed to enable TOTP: %w", err)
	}

	s.logger.Info("TOTP enrollment verified and enabled",
		zap.String("user_id", userID.String()),
	)

	return nil
}

// AuthenticateTOTP validates a TOTP code during authentication
func (s *MFAService) AuthenticateTOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	// Get the enrollment
	enrollment, err := s.repo.GetTOTPByUserID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("totp enrollment not found: %w", err)
	}

	// Check if TOTP is enabled
	if !enrollment.Enabled {
		return false, fmt.Errorf("totp is not enabled for this user")
	}

	// Decrypt the secret
	secret, err := s.encrypter.Decrypt(enrollment.Secret)
	if err != nil {
		s.logger.Error("Failed to decrypt TOTP secret",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return false, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	// Verify the code
	valid, err := s.totp.VerifyTOTP(ctx, userID.String(), secret, code)
	if err != nil {
		return false, fmt.Errorf("verification failed: %w", err)
	}

	if valid {
		// Update last used timestamp
		if err := s.repo.MarkTOTPUsed(ctx, userID); err != nil {
			s.logger.Error("Failed to mark TOTP as used",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			// Don't fail authentication if we can't update timestamp
		}
	}

	return valid, nil
}

// DisableTOTP disables TOTP for a user
func (s *MFAService) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	enrollment, err := s.repo.GetTOTPByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("totp enrollment not found: %w", err)
	}

	enrollment.Enabled = false
	if err := s.repo.UpdateTOTP(ctx, enrollment); err != nil {
		return fmt.Errorf("failed to disable TOTP: %w", err)
	}

	s.logger.Info("TOTP disabled",
		zap.String("user_id", userID.String()),
	)

	return nil
}

// GetTOTPStatus returns the TOTP enrollment status for a user
func (s *MFAService) GetTOTPStatus(ctx context.Context, userID uuid.UUID) (*TOTPEnrollment, error) {
	enrollment, err := s.repo.GetTOTPByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("totp enrollment not found: %w", err)
	}

	// Don't expose the secret in status responses
	enrollment.Secret = ""
	return enrollment, nil
}

// DeleteTOTP completely removes TOTP enrollment for a user
func (s *MFAService) DeleteTOTP(ctx context.Context, userID uuid.UUID) error {
	if err := s.repo.DeleteTOTP(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete TOTP enrollment: %w", err)
	}

	s.logger.Info("TOTP enrollment deleted",
		zap.String("user_id", userID.String()),
	)

	return nil
}
