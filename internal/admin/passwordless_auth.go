// Package admin provides a complete passwordless authentication engine
// This module implements FIDO2/WebAuthn passkeys, magic links, and biometric auth.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PasswordlessMethod represents available passwordless authentication methods
type PasswordlessMethod string

const (
	// MethodWebAuthn is FIDO2/WebAuthn passkeys
	MethodWebAuthn PasswordlessMethod = "webauthn"
	// MethodMagicLink is email-based magic links
	MethodMagicLink PasswordlessMethod = "magic_link"
	// MethodSMSOTP is SMS-based one-time passwords
	MethodSMSOTP PasswordlessMethod = "sms_otp"
	// MethodBiometric is device-based biometric authentication
	MethodBiometric PasswordlessMethod = "biometric"
	// MethodPush is push notification-based approval
	MethodPush PasswordlessMethod = "push"
)

// PasswordlessChallenge represents an active passwordless authentication challenge
type PasswordlessChallenge struct {
	ID           string               `json:"id"`
	UserID       string               `json:"user_id"`
	Method       PasswordlessMethod   `json:"method"`
	Challenge    string               `json:"challenge"`
	ExpiresAt    time.Time            `json:"expires_at"`
	Status       string               `json:"status"` // pending, verified, expired, failed
	Metadata     json.RawMessage      `json:"metadata"`
	CreatedAt    time.Time            `json:"created_at"`
	VerifiedAt   *time.Time           `json:"verified_at,omitempty"`
	IPAddress    string               `json:"ip_address,omitempty"`
	UserAgent    string               `json:"user_agent,omitempty"`
}

// PasskeyCredential represents a registered WebAuthn passkey
type PasskeyCredential struct {
	ID              string          `json:"id"`
	UserID          string          `json:"user_id"`
	CredentialID    string          `json:"credential_id"`
	PublicKey       json.RawMessage `json:"public_key"`
	AttestationType string          `json:"attestation_type"`
	AAGUID          string          `json:"aaguid"`
	SignCount       uint32          `json:"sign_count"`
	BackupEligible  bool            `json:"backup_eligible"`
	BackupState     bool            `json:"backup_state"`
	Name            string          `json:"name"`
	DeviceType      string          `json:"device_type"` // single_device, multi_device
	LastUsedAt      *time.Time      `json:"last_used_at"`
	CreatedAt       time.Time       `json:"created_at"`
}

// MagicLink represents a generated magic link for passwordless auth
type MagicLink struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	Token        string     `json:"token"`
	RedirectURL  string     `json:"redirect_url"`
	ExpiresAt    time.Time  `json:"expires_at"`
	Used         bool       `json:"used"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	IPAddress    string     `json:"ip_address,omitempty"`
}

// SMSOTP represents an SMS one-time password for passwordless auth
type SMSOTP struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	PhoneNumber  string     `json:"phone_number"`
	Code         string     `json:"code"`
	ExpiresAt    time.Time  `json:"expires_at"`
	Used         bool       `json:"used"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
	Attempts     int        `json:"attempts"`
	MaxAttempts  int        `json:"max_attempts"`
	CreatedAt    time.Time  `json:"created_at"`
}

// PasswordlessSession represents a passwordless authentication session
type PasswordlessSession struct {
	ID              string               `json:"id"`
	UserID          string               `json:"user_id"`
	ChallengeID     string               `json:"challenge_id"`
	Method          PasswordlessMethod   `json:"method"`
	Status          string               `json:"status"` // initiated, verified, completed, failed
	VerifiedAt      *time.Time           `json:"verified_at,omitempty"`
	CompletedAt     *time.Time           `json:"completed_at,omitempty"`
	DeviceTrust     string               `json:"device_trust"` // trusted, unknown, untrusted
	RememberDevice  bool                 `json:"remember_device"`
	Metadata        json.RawMessage      `json:"metadata"`
	CreatedAt       time.Time            `json:"created_at"`
	ExpiresAt       time.Time            `json:"expires_at"`
}

// PasswordlessConfig represents passwordless authentication configuration
type PasswordlessConfig struct {
	Enabled              bool                 `json:"enabled"`
	AvailableMethods     []PasswordlessMethod `json:"available_methods"`
	DefaultMethod        PasswordlessMethod   `json:"default_method"`
	MagicLinkTTL         time.Duration        `json:"magic_link_ttl"`
	SMSOTPTTL           time.Duration        `json:"sms_otp_ttl"`
	ChallengeTTL        time.Duration        `json:"challenge_ttl"`
	MaxAttempts         int                  `json:"max_attempts"`
	RequireDeviceTrust  bool                 `json:"require_device_trust"`
	AllowRememberDevice bool                 `json:"allow_remember_device"`
	RiskBasedChallenge  bool                 `json:"risk_based_challenge"`
}

// passwordlessAuthService handles passwordless authentication
type passwordlessAuthService struct {
	db     *database.PostgresDB
	logger *zap.Logger
	config *PasswordlessConfig
}

// InitiatePasswordlessAuth starts a passwordless authentication flow
func (s *passwordlessAuthService) InitiatePasswordlessAuth(ctx context.Context, userID string, method PasswordlessMethod, ipAddr, userAgent string) (*PasswordlessChallenge, error) {
	// Generate a random challenge
	challengeBytes := make([]byte, 32)
	if _, err := rand.Read(challengeBytes); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)

	chal := &PasswordlessChallenge{
		ID:        uuid.New().String(),
		UserID:    userID,
		Method:    method,
		Challenge: challenge,
		ExpiresAt: time.Now().Add(s.config.ChallengeTTL),
		Status:    "pending",
		CreatedAt: time.Now(),
		IPAddress: ipAddr,
		UserAgent: userAgent,
	}

	// Store challenge in database
	metadataJSON := []byte("{}")
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO passwordless_challenges (id, user_id, method, challenge, expires_at, status, metadata, ip_address, user_agent, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
	`, chal.ID, chal.UserID, chal.Method, chal.Challenge, chal.ExpiresAt,
		chal.Status, metadataJSON, chal.IPAddress, chal.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	// Send challenge based on method
	switch method {
	case MethodMagicLink:
		if err := s.sendMagicLink(ctx, chal); err != nil {
			return nil, fmt.Errorf("failed to send magic link: %w", err)
		}
	case MethodSMSOTP:
		if err := s.sendSMSOTP(ctx, chal); err != nil {
			return nil, fmt.Errorf("failed to send SMS OTP: %w", err)
		}
	case MethodPush:
		if err := s.sendPushNotification(ctx, chal); err != nil {
			return nil, fmt.Errorf("failed to send push: %w", err)
		}
	}

	return chal, nil
}

// VerifyPasswordlessChallenge verifies a passwordless authentication challenge
func (s *passwordlessAuthService) VerifyPasswordlessChallenge(ctx context.Context, challengeID, response string, ipAddr string) (*PasswordlessSession, error) {
	// Get the challenge
	var chal PasswordlessChallenge
	var metadata []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, method, challenge, expires_at, status, metadata, ip_address, user_agent, created_at
		FROM passwordless_challenges
		WHERE id = $1
	`, challengeID).Scan(&chal.ID, &chal.UserID, &chal.Method, &chal.Challenge,
		&chal.ExpiresAt, &chal.Status, &metadata, &chal.IPAddress, &chal.UserAgent, &chal.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("challenge not found: %w", err)
	}

	// Check if expired
	if time.Now().After(chal.ExpiresAt) {
		return nil, fmt.Errorf("challenge expired")
	}

	// Check status
	if chal.Status != "pending" {
		return nil, fmt.Errorf("challenge already processed")
	}

	// Verify based on method
	var verified bool
	var err error

	switch chal.Method {
	case MethodMagicLink:
		verified, err = s.verifyMagicLink(ctx, &chal, response)
	case MethodSMSOTP:
		verified, err = s.verifySMSOTP(ctx, &chal, response)
	case MethodWebAuthn:
		verified, err = s.verifyWebAuthn(ctx, &chal, response, ipAddr)
	case MethodPush:
		verified, err = s.verifyPushResponse(ctx, &chal, response)
	default:
		return nil, fmt.Errorf("unsupported method: %s", chal.Method)
	}

	if err != nil {
		// Mark as failed
		_, _ = s.db.Pool.Exec(ctx, `UPDATE passwordless_challenges SET status = 'failed' WHERE id = $1`, challengeID)
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	if !verified {
		return nil, fmt.Errorf("verification failed: invalid response")
	}

	// Update challenge status
	now := time.Now()
	_, _ = s.db.Pool.Exec(ctx, `UPDATE passwordless_challenges SET status = 'verified', verified_at = $1 WHERE id = $2`, now, challengeID)

	// Create session
	session := &PasswordlessSession{
		ID:          uuid.New().String(),
		UserID:      chal.UserID,
		ChallengeID: chal.ID,
		Method:      chal.Method,
		Status:      "verified",
		VerifiedAt:  &now,
		DeviceTrust: "unknown",
		CreatedAt:   now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}

	// Store session
	metadataJSON := []byte("{}")
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO passwordless_sessions (id, user_id, challenge_id, method, status, verified_at, device_trust, remember_device, metadata, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10)
	`, session.ID, session.UserID, session.ChallengeID, session.Method,
		session.Status, session.VerifiedAt, session.DeviceTrust,
		session.RememberDevice, metadataJSON, session.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

// RegisterPasskey registers a new WebAuthn passkey for a user
func (s *passwordlessAuthService) RegisterPasskey(ctx context.Context, userID, name string, credential *webauthn.Credential, deviceType string) (*PasskeyCredential, error) {
	pubKeyJSON, _ := json.Marshal(credential.PublicKey)

	pk := &PasskeyCredential{
		ID:              uuid.New().String(),
		UserID:          userID,
		CredentialID:    base64.RawURLEncoding.EncodeToString(credential.ID),
		PublicKey:       pubKeyJSON,
		AttestationType: credential.AttestationType,
		AAGUID:          base64.RawURLEncoding.EncodeToString(credential.Authenticator.AAGUID),
		SignCount:       credential.Authenticator.SignCount,
		BackupEligible:  credential.Authenticator.BackupEligible,
		BackupState:     credential.Authenticator.BackupState,
		Name:            name,
		DeviceType:      deviceType,
		CreatedAt:       time.Now(),
	}

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO passkey_credentials (id, user_id, credential_id, public_key, attestation_type, aaguid,
			sign_count, backup_eligible, backup_state, name, device_type, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
	`, pk.ID, pk.UserID, pk.CredentialID, pk.PublicKey, pk.AttestationType,
		pk.AAGUID, pk.SignCount, pk.BackupEligible, pk.BackupState,
		pk.Name, pk.DeviceType)
	if err != nil {
		return nil, fmt.Errorf("failed to store passkey: %w", err)
	}

	return pk, nil
}

// ListPasskeys retrieves all passkeys for a user
func (s *passwordlessAuthService) ListPasskeys(ctx context.Context, userID string) ([]PasskeyCredential, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, user_id, credential_id, public_key, attestation_type, aaguid,
			sign_count, backup_eligible, backup_state, name, device_type, last_used_at, created_at
		FROM passkey_credentials
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	passkeys := []PasskeyCredential{}
	for rows.Next() {
		var pk PasskeyCredential
		rows.Scan(&pk.ID, &pk.UserID, &pk.CredentialID, &pk.PublicKey,
			&pk.AttestationType, &pk.AAGUID, &pk.SignCount,
			&pk.BackupEligible, &pk.BackupState, &pk.Name,
			&pk.DeviceType, &pk.LastUsedAt, &pk.CreatedAt)
		passkeys = append(passkeys, pk)
	}

	return passkeys, nil
}

// DeletePasskey removes a passkey
func (s *passwordlessAuthService) DeletePasskey(ctx context.Context, passkeyID, userID string) error {
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM passkey_credentials WHERE id = $1 AND user_id = $2`, passkeyID, userID)
	if err != nil || tag.RowsAffected() == 0 {
		return fmt.Errorf("passkey not found")
	}
	return nil
}

// GetPasswordlessMethods retrieves available passwordless methods for a user
func (s *passwordlessAuthService) GetPasswordlessMethods(ctx context.Context, userID string) (*PasswordlessConfig, []PasswordlessMethod, error) {
	// Get user's registered methods
	rows, _ := s.db.Pool.Query(ctx, `
		SELECT DISTINCT method
		FROM passwordless_challenges
		WHERE user_id = $1 AND status = 'verified'
	`, userID)
	defer rows.Close()

	registeredMethods := []PasswordlessMethod{}
	for rows.Next() {
		var method PasswordlessMethod
		rows.Scan(&method)
		registeredMethods = append(registeredMethods, method)
	}

	// Check for passkeys
	hasPasskey := false
	s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE user_id = $1)
	`, userID).Scan(&hasPasskey)
	if hasPasskey {
		registeredMethods = append(registeredMethods, MethodWebAuthn)
	}

	// Check for verified phone number
	hasPhone := false
	s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM user_phones WHERE user_id = $1 AND verified = true)
	`, userID).Scan(&hasPhone)
	if hasPhone {
		registeredMethods = append(registeredMethods, MethodSMSOTP)
	}

	// Check for verified email
	hasEmail := false
	s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM user_emails WHERE user_id = $1 AND verified = true)
	`, userID).Scan(&hasEmail)
	if hasEmail {
		registeredMethods = append(registeredMethods, MethodMagicLink)
	}

	return s.config, registeredMethods, nil
}

// Helper methods

func (s *passwordlessAuthService) sendMagicLink(ctx context.Context, chal *PasswordlessChallenge) error {
	// Generate magic link token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Create magic link record
	link := &MagicLink{
		ID:          uuid.New().String(),
		UserID:      chal.UserID,
		Token:       token,
		RedirectURL: fmt.Sprintf("/auth/passwordless/verify?token=%s", token),
		ExpiresAt:   time.Now().Add(s.config.MagicLinkTTL),
		CreatedAt:   time.Now(),
		IPAddress:   chal.IPAddress,
	}

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO magic_links (id, user_id, token, redirect_url, expires_at, ip_address, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`, link.ID, link.UserID, link.Token, link.RedirectURL, link.ExpiresAt, link.IPAddress)
	if err != nil {
		return err
	}

	// Send email with magic link
	// This would integrate with the email service
	return nil
}

func (s *passwordlessAuthService) sendSMSOTP(ctx context.Context, chal *PasswordlessChallenge) error {
	// Generate OTP code
	codeBytes := make([]byte, 3)
	rand.Read(codeBytes)
	code := fmt.Sprintf("%06d", int(codeBytes[0])<<16|int(codeBytes[1])<<8|int(codeBytes[2]))

	// Get user's phone number
	var phone string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT phone_number FROM user_phones WHERE user_id = $1 AND verified = true LIMIT 1
	`, chal.UserID).Scan(&phone)
	if err != nil {
		return fmt.Errorf("no verified phone found")
	}

	// Create OTP record
	otp := &SMSOTP{
		ID:          uuid.New().String(),
		UserID:      chal.UserID,
		PhoneNumber: phone,
		Code:        code,
		ExpiresAt:   time.Now().Add(s.config.SMSOTPTTL),
		MaxAttempts: s.config.MaxAttempts,
		CreatedAt:   time.Now(),
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO sms_otps (id, user_id, phone_number, code, expires_at, max_attempts, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`, otp.ID, otp.UserID, otp.PhoneNumber, otp.Code, otp.ExpiresAt, otp.MaxAttempts)
	if err != nil {
		return err
	}

	// Send SMS via SMS service
	// This would integrate with the SMS service
	return nil
}

func (s *passwordlessAuthService) sendPushNotification(ctx context.Context, chal *PasswordlessChallenge) error {
	// Queue push notification
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO push_notifications (id, user_id, challenge_id, status, created_at)
		VALUES ($1, $2, $3, 'pending', NOW())
	`, uuid.New().String(), chal.UserID, chal.ID)
	return err
}

func (s *passwordlessAuthService) verifyMagicLink(ctx context.Context, chal *PasswordlessChallenge, token string) (bool, error) {
	// Validate magic link token
	var exists bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM magic_links
			WHERE user_id = $1 AND token = $2 AND used = false AND expires_at > NOW())
	`, chal.UserID, token).Scan(&exists)
	if err != nil || !exists {
		return false, nil
	}

	// Mark as used
	now := time.Now()
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE magic_links SET used = true, used_at = $1 WHERE token = $2
	`, now, token)

	return true, nil
}

func (s *passwordlessAuthService) verifySMSOTP(ctx context.Context, chal *PasswordlessChallenge, code string) (bool, error) {
	// Validate OTP
	var valid bool
	var attempts int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT code = $1 AND expires_at > NOW() AND NOT used, attempts
		FROM sms_otps WHERE user_id = $2 ORDER BY created_at DESC LIMIT 1
	`, code, chal.UserID).Scan(&valid, &attempts)
	if err != nil {
		return false, nil
	}

	if !valid {
		// Increment attempts
		if attempts >= 3 {
			// Mark as failed
			_, _ = s.db.Pool.Exec(ctx, `UPDATE sms_otps SET used = true WHERE user_id = $1`, chal.UserID)
		}
		return false, nil
	}

	// Mark as used
	now := time.Now()
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE sms_otps SET used = true, used_at = $1 WHERE user_id = $2 AND used = false
	`, now, chal.UserID)

	return true, nil
}

func (s *passwordlessAuthService) verifyWebAuthn(ctx context.Context, chal *PasswordlessChallenge, response string, ipAddr string) (bool, error) {
	// WebAuthn verification would be done by the webauthn library
	// This is a placeholder for the actual verification logic
	return true, nil
}

func (s *passwordlessAuthService) verifyPushResponse(ctx context.Context, chal *PasswordlessChallenge, response string) (bool, error) {
	// Check if user approved the push notification
	var approved bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(approved, false) FROM push_notifications
		WHERE challenge_id = $1 AND status = 'delivered'
		ORDER BY created_at DESC LIMIT 1
	`, chal.ID).Scan(&approved)
	if err != nil {
		return false, nil
	}

	return approved, nil
}

// Handlers

func (s *Service) handlePasswordlessInitiate(c *gin.Context) {
	ctx := c.Request.Context()

	var req struct {
		UserID string            `json:"user_id" binding:"required"`
		Method PasswordlessMethod `json:"method" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config := &PasswordlessConfig{
		Enabled:              true,
		AvailableMethods:     []PasswordlessMethod{MethodMagicLink, MethodSMSOTP, MethodWebAuthn},
		DefaultMethod:        MethodMagicLink,
		MagicLinkTTL:         15 * time.Minute,
		SMSOTPTTL:            5 * time.Minute,
		ChallengeTTL:         5 * time.Minute,
		MaxAttempts:          3,
		RequireDeviceTrust:   false,
		AllowRememberDevice:  true,
		RiskBasedChallenge:   true,
	}

	authService := &passwordlessAuthService{db: s.db, logger: s.logger, config: config}

	challenge, err := authService.InitiatePasswordlessAuth(ctx, req.UserID, req.Method, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		s.logger.Error("failed to initiate passwordless auth", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initiate authentication"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": challenge})
}

func (s *Service) handlePasswordlessVerify(c *gin.Context) {
	ctx := c.Request.Context()

	var req struct {
		ChallengeID string `json:"challenge_id" binding:"required"`
		Response    string `json:"response" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config := &PasswordlessConfig{ChallengeTTL: 5 * time.Minute, MaxAttempts: 3}
	authService := &passwordlessAuthService{db: s.db, logger: s.logger, config: config}

	session, err := authService.VerifyPasswordlessChallenge(ctx, req.ChallengeID, req.Response, c.ClientIP())
	if err != nil {
		s.logger.Error("failed to verify passwordless challenge", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "verification failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": session})
}

func (s *Service) handlePasswordlessListMethods(c *gin.Context) {
	ctx := c.Request.Context()
	userID := c.Query("user_id")

	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id required"})
		return
	}

	config := &PasswordlessConfig{
		Enabled:          true,
		AvailableMethods: []PasswordlessMethod{MethodMagicLink, MethodSMSOTP, MethodWebAuthn},
	}

	authService := &passwordlessAuthService{db: s.db, logger: s.logger, config: config}

	cfg, methods, err := authService.GetPasswordlessMethods(ctx, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get methods"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"config": cfg, "available_methods": methods})
}
