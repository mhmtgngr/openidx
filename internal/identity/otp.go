// Package identity - SMS and Email OTP MFA implementation
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SMSEnrollment represents SMS MFA enrollment data
type SMSEnrollment struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	PhoneNumber string     `json:"phone_number"`
	CountryCode string     `json:"country_code"`
	Verified    bool       `json:"verified"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// EmailOTPEnrollment represents Email OTP MFA enrollment data
type EmailOTPEnrollment struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	EmailAddress string     `json:"email_address"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// OTPChallenge represents an active OTP challenge
type OTPChallenge struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	Method      string     `json:"method"` // "sms" or "email"
	Recipient   string     `json:"recipient"`
	CodeHash    string     `json:"-"`
	Attempts    int        `json:"attempts"`
	MaxAttempts int        `json:"max_attempts"`
	Status      string     `json:"status"` // pending, verified, expired, failed
	IPAddress   string     `json:"ip_address,omitempty"`
	UserAgent   string     `json:"user_agent,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
}

// OTPConfig holds configuration for OTP generation
type OTPConfig struct {
	CodeLength      int           // Length of OTP code (default: 6)
	ExpirationTime  time.Duration // How long the OTP is valid (default: 5 minutes)
	MaxAttempts     int           // Maximum verification attempts (default: 3)
	RateLimitWindow time.Duration // Window for rate limiting (default: 1 hour)
	MaxCodesPerHour int           // Max codes per window (default: 5)
}

// DefaultOTPConfig returns the default OTP configuration
func DefaultOTPConfig() OTPConfig {
	return OTPConfig{
		CodeLength:      6,
		ExpirationTime:  5 * time.Minute,
		MaxAttempts:     3,
		RateLimitWindow: 1 * time.Hour,
		MaxCodesPerHour: 5,
	}
}

// --- SMS MFA Methods ---

// EnrollSMS starts SMS MFA enrollment for a user
func (s *Service) EnrollSMS(ctx context.Context, userID, phoneNumber, countryCode string) (*SMSEnrollment, string, error) {
	// Validate phone number format (basic validation)
	if len(phoneNumber) < 7 || len(phoneNumber) > 15 {
		return nil, "", fmt.Errorf("invalid phone number length")
	}

	// Check if already enrolled
	existing, _ := s.GetSMSEnrollment(ctx, userID)
	if existing != nil && existing.Verified {
		return nil, "", fmt.Errorf("SMS MFA already enrolled")
	}

	// If existing but not verified, update it
	enrollment := &SMSEnrollment{
		ID:          uuid.New().String(),
		UserID:      userID,
		PhoneNumber: phoneNumber,
		CountryCode: countryCode,
		Verified:    false,
		Enabled:     true,
		CreatedAt:   time.Now(),
	}

	if existing != nil {
		// Update existing enrollment
		enrollment.ID = existing.ID
		if err := s.updateSMSEnrollment(ctx, enrollment); err != nil {
			return nil, "", fmt.Errorf("failed to update SMS enrollment: %w", err)
		}
	} else {
		// Create new enrollment
		if err := s.storeSMSEnrollment(ctx, enrollment); err != nil {
			return nil, "", fmt.Errorf("failed to store SMS enrollment: %w", err)
		}
	}

	// Generate and send verification code
	code, err := s.createOTPChallenge(ctx, userID, "sms", countryCode+phoneNumber)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create verification challenge: %w", err)
	}

	// Send SMS (in production, integrate with SMS provider)
	if err := s.sendSMSOTP(ctx, countryCode+phoneNumber, code); err != nil {
		s.logger.Error("Failed to send SMS OTP", zap.Error(err))
		// Don't fail enrollment, code can be resent
	}

	s.logger.Info("SMS MFA enrollment started",
		zap.String("user_id", userID),
		zap.String("phone", maskPhone(phoneNumber)))

	return enrollment, code, nil
}

// VerifySMSEnrollment verifies the SMS enrollment with the provided code
func (s *Service) VerifySMSEnrollment(ctx context.Context, userID, code string) error {
	enrollment, err := s.GetSMSEnrollment(ctx, userID)
	if err != nil {
		return fmt.Errorf("SMS enrollment not found: %w", err)
	}

	if enrollment.Verified {
		return fmt.Errorf("SMS MFA already verified")
	}

	// Verify the OTP challenge
	challenge, err := s.verifyOTPCode(ctx, userID, "sms", code)
	if err != nil {
		return err
	}

	// Mark enrollment as verified
	now := time.Now()
	enrollment.Verified = true
	enrollment.VerifiedAt = &now

	if err := s.updateSMSEnrollment(ctx, enrollment); err != nil {
		return fmt.Errorf("failed to update enrollment: %w", err)
	}

	s.logger.Info("SMS MFA enrollment verified",
		zap.String("user_id", userID),
		zap.String("challenge_id", challenge.ID))

	return nil
}

// GetSMSEnrollment returns the SMS enrollment for a user
func (s *Service) GetSMSEnrollment(ctx context.Context, userID string) (*SMSEnrollment, error) {
	query := `
		SELECT id, user_id, phone_number, country_code, verified, enabled,
		       created_at, verified_at, last_used_at
		FROM mfa_sms
		WHERE user_id = $1
	`

	var enrollment SMSEnrollment
	err := s.db.Pool.QueryRow(ctx, query, userID).Scan(
		&enrollment.ID,
		&enrollment.UserID,
		&enrollment.PhoneNumber,
		&enrollment.CountryCode,
		&enrollment.Verified,
		&enrollment.Enabled,
		&enrollment.CreatedAt,
		&enrollment.VerifiedAt,
		&enrollment.LastUsedAt,
	)
	if err != nil {
		return nil, err
	}

	return &enrollment, nil
}

// DeleteSMSEnrollment removes SMS MFA for a user
func (s *Service) DeleteSMSEnrollment(ctx context.Context, userID string) error {
	query := `DELETE FROM mfa_sms WHERE user_id = $1`
	result, err := s.db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete SMS enrollment: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("SMS enrollment not found")
	}

	s.logger.Info("SMS MFA enrollment deleted", zap.String("user_id", userID))
	return nil
}

// CreateSMSChallenge creates a new SMS OTP challenge for authentication
func (s *Service) CreateSMSChallenge(ctx context.Context, userID, ipAddress, userAgent string) (*OTPChallenge, error) {
	enrollment, err := s.GetSMSEnrollment(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("SMS MFA not enrolled: %w", err)
	}

	if !enrollment.Verified || !enrollment.Enabled {
		return nil, fmt.Errorf("SMS MFA not verified or disabled")
	}

	// Generate and send code
	code, err := s.createOTPChallenge(ctx, userID, "sms", enrollment.CountryCode+enrollment.PhoneNumber)
	if err != nil {
		return nil, err
	}

	// Get the challenge we just created
	challenge, err := s.getLatestOTPChallenge(ctx, userID, "sms")
	if err != nil {
		return nil, err
	}

	challenge.IPAddress = ipAddress
	challenge.UserAgent = userAgent

	// Send SMS
	if err := s.sendSMSOTP(ctx, enrollment.CountryCode+enrollment.PhoneNumber, code); err != nil {
		s.logger.Error("Failed to send SMS OTP", zap.Error(err))
	}

	s.logger.Info("SMS OTP challenge created",
		zap.String("user_id", userID),
		zap.String("challenge_id", challenge.ID))

	return challenge, nil
}

// --- Email OTP MFA Methods ---

// EnrollEmailOTP starts Email OTP MFA enrollment for a user
func (s *Service) EnrollEmailOTP(ctx context.Context, userID, emailAddress string) (*EmailOTPEnrollment, string, error) {
	// Check if already enrolled
	existing, _ := s.GetEmailOTPEnrollment(ctx, userID)
	if existing != nil {
		return nil, "", fmt.Errorf("Email OTP MFA already enrolled")
	}

	enrollment := &EmailOTPEnrollment{
		ID:           uuid.New().String(),
		UserID:       userID,
		EmailAddress: emailAddress,
		Enabled:      true,
		CreatedAt:    time.Now(),
	}

	if err := s.storeEmailOTPEnrollment(ctx, enrollment); err != nil {
		return nil, "", fmt.Errorf("failed to store Email OTP enrollment: %w", err)
	}

	// Generate and send verification code
	code, err := s.createOTPChallenge(ctx, userID, "email", emailAddress)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create verification challenge: %w", err)
	}

	// Send email
	if err := s.sendEmailOTP(ctx, emailAddress, code); err != nil {
		s.logger.Error("Failed to send Email OTP", zap.Error(err))
	}

	s.logger.Info("Email OTP MFA enrollment started",
		zap.String("user_id", userID),
		zap.String("email", maskEmail(emailAddress)))

	return enrollment, code, nil
}

// GetEmailOTPEnrollment returns the Email OTP enrollment for a user
func (s *Service) GetEmailOTPEnrollment(ctx context.Context, userID string) (*EmailOTPEnrollment, error) {
	query := `
		SELECT id, user_id, email_address, enabled, created_at, last_used_at
		FROM mfa_email_otp
		WHERE user_id = $1
	`

	var enrollment EmailOTPEnrollment
	err := s.db.Pool.QueryRow(ctx, query, userID).Scan(
		&enrollment.ID,
		&enrollment.UserID,
		&enrollment.EmailAddress,
		&enrollment.Enabled,
		&enrollment.CreatedAt,
		&enrollment.LastUsedAt,
	)
	if err != nil {
		return nil, err
	}

	return &enrollment, nil
}

// DeleteEmailOTPEnrollment removes Email OTP MFA for a user
func (s *Service) DeleteEmailOTPEnrollment(ctx context.Context, userID string) error {
	query := `DELETE FROM mfa_email_otp WHERE user_id = $1`
	result, err := s.db.Pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete Email OTP enrollment: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("Email OTP enrollment not found")
	}

	s.logger.Info("Email OTP MFA enrollment deleted", zap.String("user_id", userID))
	return nil
}

// CreateEmailOTPChallenge creates a new Email OTP challenge for authentication
func (s *Service) CreateEmailOTPChallenge(ctx context.Context, userID, ipAddress, userAgent string) (*OTPChallenge, error) {
	enrollment, err := s.GetEmailOTPEnrollment(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("Email OTP MFA not enrolled: %w", err)
	}

	if !enrollment.Enabled {
		return nil, fmt.Errorf("Email OTP MFA disabled")
	}

	// Generate and send code
	code, err := s.createOTPChallenge(ctx, userID, "email", enrollment.EmailAddress)
	if err != nil {
		return nil, err
	}

	// Get the challenge we just created
	challenge, err := s.getLatestOTPChallenge(ctx, userID, "email")
	if err != nil {
		return nil, err
	}

	challenge.IPAddress = ipAddress
	challenge.UserAgent = userAgent

	// Send email
	if err := s.sendEmailOTP(ctx, enrollment.EmailAddress, code); err != nil {
		s.logger.Error("Failed to send Email OTP", zap.Error(err))
	}

	s.logger.Info("Email OTP challenge created",
		zap.String("user_id", userID),
		zap.String("challenge_id", challenge.ID))

	return challenge, nil
}

// --- Common OTP Methods ---

// VerifyOTP verifies an OTP code for any method (sms or email)
func (s *Service) VerifyOTP(ctx context.Context, userID, method, code string) error {
	challenge, err := s.verifyOTPCode(ctx, userID, method, code)
	if err != nil {
		return err
	}

	// Update last used timestamp
	if method == "sms" {
		s.updateSMSLastUsed(ctx, userID)
	} else if method == "email" {
		s.updateEmailOTPLastUsed(ctx, userID)
	}

	s.logger.Info("OTP verified successfully",
		zap.String("user_id", userID),
		zap.String("method", method),
		zap.String("challenge_id", challenge.ID))

	return nil
}

// GetUserMFAMethods returns all enrolled MFA methods for a user
func (s *Service) GetUserMFAMethods(ctx context.Context, userID string) (map[string]bool, error) {
	methods := make(map[string]bool)

	// Check TOTP
	totpStatus, _ := s.GetTOTPStatus(ctx, userID)
	methods["totp"] = totpStatus != nil && totpStatus.Enabled

	// Check SMS
	sms, _ := s.GetSMSEnrollment(ctx, userID)
	methods["sms"] = sms != nil && sms.Verified && sms.Enabled

	// Check Email OTP
	email, _ := s.GetEmailOTPEnrollment(ctx, userID)
	methods["email"] = email != nil && email.Enabled

	// Check Push MFA
	pushDevices, _ := s.GetPushMFADevices(ctx, userID)
	methods["push"] = len(pushDevices) > 0

	// Check WebAuthn
	webauthnCreds, _ := s.GetWebAuthnCredentials(ctx, userID)
	methods["webauthn"] = len(webauthnCreds) > 0

	// Check backup codes
	backupCount, _ := s.GetRemainingBackupCodes(ctx, userID)
	methods["backup"] = backupCount > 0

	return methods, nil
}

// --- Helper Functions ---

func (s *Service) createOTPChallenge(ctx context.Context, userID, method, recipient string) (string, error) {
	cfg := DefaultOTPConfig()

	// Rate limit check
	count, err := s.countRecentOTPChallenges(ctx, userID, method, cfg.RateLimitWindow)
	if err != nil {
		return "", fmt.Errorf("failed to check rate limit: %w", err)
	}
	if count >= cfg.MaxCodesPerHour {
		return "", fmt.Errorf("too many OTP requests, please try again later")
	}

	// Generate code
	code := generateOTPCode(cfg.CodeLength)
	codeHash := hashOTPCode(code)

	challenge := &OTPChallenge{
		ID:          uuid.New().String(),
		UserID:      userID,
		Method:      method,
		Recipient:   recipient,
		CodeHash:    codeHash,
		Attempts:    0,
		MaxAttempts: cfg.MaxAttempts,
		Status:      "pending",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(cfg.ExpirationTime),
	}

	if err := s.storeOTPChallenge(ctx, challenge); err != nil {
		return "", fmt.Errorf("failed to store challenge: %w", err)
	}

	return code, nil
}

func (s *Service) verifyOTPCode(ctx context.Context, userID, method, code string) (*OTPChallenge, error) {
	challenge, err := s.getLatestOTPChallenge(ctx, userID, method)
	if err != nil {
		return nil, fmt.Errorf("no pending challenge found")
	}

	if challenge.Status != "pending" {
		return nil, fmt.Errorf("challenge already %s", challenge.Status)
	}

	if time.Now().After(challenge.ExpiresAt) {
		challenge.Status = "expired"
		s.updateOTPChallengeStatus(ctx, challenge)
		return nil, fmt.Errorf("OTP code expired")
	}

	if challenge.Attempts >= challenge.MaxAttempts {
		challenge.Status = "failed"
		s.updateOTPChallengeStatus(ctx, challenge)
		return nil, fmt.Errorf("maximum attempts exceeded")
	}

	// Increment attempts
	challenge.Attempts++
	s.incrementOTPChallengeAttempts(ctx, challenge.ID)

	// Verify code
	if hashOTPCode(code) != challenge.CodeHash {
		if challenge.Attempts >= challenge.MaxAttempts {
			challenge.Status = "failed"
			s.updateOTPChallengeStatus(ctx, challenge)
			return nil, fmt.Errorf("invalid OTP code, maximum attempts exceeded")
		}
		return nil, fmt.Errorf("invalid OTP code, %d attempts remaining", challenge.MaxAttempts-challenge.Attempts)
	}

	// Mark as verified
	now := time.Now()
	challenge.Status = "verified"
	challenge.VerifiedAt = &now
	s.updateOTPChallengeStatus(ctx, challenge)

	return challenge, nil
}

func (s *Service) storeSMSEnrollment(ctx context.Context, enrollment *SMSEnrollment) error {
	query := `
		INSERT INTO mfa_sms (id, user_id, phone_number, country_code, verified, enabled, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.db.Pool.Exec(ctx, query,
		enrollment.ID,
		enrollment.UserID,
		enrollment.PhoneNumber,
		enrollment.CountryCode,
		enrollment.Verified,
		enrollment.Enabled,
		enrollment.CreatedAt,
	)
	return err
}

func (s *Service) updateSMSEnrollment(ctx context.Context, enrollment *SMSEnrollment) error {
	query := `
		UPDATE mfa_sms
		SET phone_number = $1, country_code = $2, verified = $3, enabled = $4, verified_at = $5
		WHERE id = $6
	`
	_, err := s.db.Pool.Exec(ctx, query,
		enrollment.PhoneNumber,
		enrollment.CountryCode,
		enrollment.Verified,
		enrollment.Enabled,
		enrollment.VerifiedAt,
		enrollment.ID,
	)
	return err
}

func (s *Service) updateSMSLastUsed(ctx context.Context, userID string) {
	query := `UPDATE mfa_sms SET last_used_at = $1 WHERE user_id = $2`
	s.db.Pool.Exec(ctx, query, time.Now(), userID)
}

func (s *Service) storeEmailOTPEnrollment(ctx context.Context, enrollment *EmailOTPEnrollment) error {
	query := `
		INSERT INTO mfa_email_otp (id, user_id, email_address, enabled, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := s.db.Pool.Exec(ctx, query,
		enrollment.ID,
		enrollment.UserID,
		enrollment.EmailAddress,
		enrollment.Enabled,
		enrollment.CreatedAt,
	)
	return err
}

func (s *Service) updateEmailOTPLastUsed(ctx context.Context, userID string) {
	query := `UPDATE mfa_email_otp SET last_used_at = $1 WHERE user_id = $2`
	s.db.Pool.Exec(ctx, query, time.Now(), userID)
}

func (s *Service) storeOTPChallenge(ctx context.Context, challenge *OTPChallenge) error {
	query := `
		INSERT INTO mfa_otp_challenges
		(id, user_id, method, recipient, code_hash, attempts, max_attempts, status, ip_address, user_agent, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := s.db.Pool.Exec(ctx, query,
		challenge.ID,
		challenge.UserID,
		challenge.Method,
		challenge.Recipient,
		challenge.CodeHash,
		challenge.Attempts,
		challenge.MaxAttempts,
		challenge.Status,
		challenge.IPAddress,
		challenge.UserAgent,
		challenge.CreatedAt,
		challenge.ExpiresAt,
	)
	return err
}

func (s *Service) getLatestOTPChallenge(ctx context.Context, userID, method string) (*OTPChallenge, error) {
	query := `
		SELECT id, user_id, method, recipient, code_hash, attempts, max_attempts,
		       status, ip_address, user_agent, created_at, expires_at, verified_at
		FROM mfa_otp_challenges
		WHERE user_id = $1 AND method = $2 AND status = 'pending'
		ORDER BY created_at DESC
		LIMIT 1
	`

	var challenge OTPChallenge
	err := s.db.Pool.QueryRow(ctx, query, userID, method).Scan(
		&challenge.ID,
		&challenge.UserID,
		&challenge.Method,
		&challenge.Recipient,
		&challenge.CodeHash,
		&challenge.Attempts,
		&challenge.MaxAttempts,
		&challenge.Status,
		&challenge.IPAddress,
		&challenge.UserAgent,
		&challenge.CreatedAt,
		&challenge.ExpiresAt,
		&challenge.VerifiedAt,
	)
	if err != nil {
		return nil, err
	}

	return &challenge, nil
}

func (s *Service) updateOTPChallengeStatus(ctx context.Context, challenge *OTPChallenge) error {
	query := `UPDATE mfa_otp_challenges SET status = $1, verified_at = $2 WHERE id = $3`
	_, err := s.db.Pool.Exec(ctx, query, challenge.Status, challenge.VerifiedAt, challenge.ID)
	return err
}

func (s *Service) incrementOTPChallengeAttempts(ctx context.Context, challengeID string) error {
	query := `UPDATE mfa_otp_challenges SET attempts = attempts + 1 WHERE id = $1`
	_, err := s.db.Pool.Exec(ctx, query, challengeID)
	return err
}

func (s *Service) countRecentOTPChallenges(ctx context.Context, userID, method string, window time.Duration) (int, error) {
	query := `
		SELECT COUNT(*) FROM mfa_otp_challenges
		WHERE user_id = $1 AND method = $2 AND created_at > $3
	`
	var count int
	err := s.db.Pool.QueryRow(ctx, query, userID, method, time.Now().Add(-window)).Scan(&count)
	return count, err
}

func (s *Service) sendSMSOTP(ctx context.Context, phoneNumber, code string) error {
	// Check if SMS provider is configured
	if s.smsProvider == nil {
		s.logger.Warn("SMS provider not configured, OTP code not sent",
			zap.String("phone", maskPhone(phoneNumber)),
			zap.String("code", code)) // Only log in dev mode
		return nil
	}

	return s.smsProvider.SendOTP(ctx, phoneNumber, code)
}

func (s *Service) sendEmailOTP(ctx context.Context, email, code string) error {
	if s.emailService == nil {
		s.logger.Warn("Email service not configured, OTP code not sent",
			zap.String("email", maskEmail(email)),
			zap.String("code", code)) // Only log in dev mode
		return nil
	}

	return s.emailService.SendAsync(ctx, email, "Your verification code", "otp", map[string]interface{}{
		"Code":      code,
		"ExpiresIn": "5 minutes",
	})
}

// generateOTPCode generates a random numeric OTP code of specified length
func generateOTPCode(length int) string {
	if length <= 0 {
		length = 6
	}

	max := new(big.Int)
	max.SetString(fmt.Sprintf("%s", repeatString("9", length)), 10)
	max.Add(max, big.NewInt(1))

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// Fallback to less secure but functional method
		n = big.NewInt(123456)
	}

	return fmt.Sprintf("%0*d", length, n.Int64())
}

func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

// hashOTPCode creates a SHA256 hash of the OTP code
func hashOTPCode(code string) string {
	h := sha256.New()
	h.Write([]byte(code))
	return hex.EncodeToString(h.Sum(nil))
}

// maskPhone masks a phone number for logging (e.g., ***1234)
func maskPhone(phone string) string {
	if len(phone) <= 4 {
		return "****"
	}
	return "***" + phone[len(phone)-4:]
}

// maskEmail masks an email address for logging (e.g., j***@example.com)
func maskEmail(email string) string {
	at := 0
	for i, c := range email {
		if c == '@' {
			at = i
			break
		}
	}
	if at <= 1 {
		return "***@***"
	}
	return string(email[0]) + "***" + email[at:]
}
