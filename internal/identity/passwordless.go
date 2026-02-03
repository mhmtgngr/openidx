// Package identity - Passwordless Authentication (Magic Link, QR Code, WebAuthn-only)
package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// MagicLink represents a magic link token
type MagicLink struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	Email       string     `json:"email"`
	Token       string     `json:"token,omitempty"` // Only returned on creation
	Purpose     string     `json:"purpose"`         // login, verify_email, link_device
	RedirectURL string     `json:"redirect_url,omitempty"`
	IPAddress   string     `json:"ip_address,omitempty"`
	UserAgent   string     `json:"user_agent,omitempty"`
	Status      string     `json:"status"` // pending, used, expired
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
}

// QRLoginSession represents a QR code login session
type QRLoginSession struct {
	ID           string                 `json:"id"`
	SessionToken string                 `json:"session_token"`
	QRCodeData   string                 `json:"qr_code_data,omitempty"`
	Status       string                 `json:"status"` // pending, scanned, approved, rejected, expired
	UserID       *string                `json:"user_id,omitempty"`
	BrowserInfo  map[string]interface{} `json:"browser_info,omitempty"`
	MobileInfo   map[string]interface{} `json:"mobile_info,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	ScannedAt    *time.Time             `json:"scanned_at,omitempty"`
	ApprovedAt   *time.Time             `json:"approved_at,omitempty"`
}

// PasswordlessPreferences represents user's passwordless settings
type PasswordlessPreferences struct {
	ID               string    `json:"id"`
	UserID           string    `json:"user_id"`
	WebAuthnOnly     bool      `json:"webauthn_only"`
	MagicLinkEnabled bool      `json:"magic_link_enabled"`
	QRLoginEnabled   bool      `json:"qr_login_enabled"`
	PreferredMethod  string    `json:"preferred_method"` // webauthn, magic_link, qr_code
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// CreateMagicLink generates a magic link for passwordless login
func (s *Service) CreateMagicLink(ctx context.Context, email, purpose, redirectURL, ipAddress, userAgent string) (*MagicLink, error) {
	// Find user by email
	var userID string
	err := s.db.Pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1 AND enabled = true", email).Scan(&userID)
	if err != nil {
		return nil, errors.New("user not found or disabled")
	}

	// Check if passwordless is enabled for this user
	prefs, _ := s.GetPasswordlessPreferences(ctx, userID)
	if prefs != nil && !prefs.MagicLinkEnabled {
		return nil, errors.New("magic link login is disabled for this user")
	}

	// Generate secure token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash token for storage
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Set purpose default
	if purpose == "" {
		purpose = "login"
	}

	linkID := uuid.New().String()
	expiresAt := time.Now().Add(15 * time.Minute) // 15 min expiry

	// Invalidate any existing pending magic links for this user
	s.db.Pool.Exec(ctx,
		"UPDATE magic_links SET status = 'expired' WHERE user_id = $1 AND status = 'pending'",
		userID,
	)

	// Create magic link
	query := `
		INSERT INTO magic_links (
			id, user_id, email, token_hash, purpose, redirect_url,
			ip_address, user_agent, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', NOW(), $9)
		RETURNING created_at
	`

	var createdAt time.Time
	err = s.db.Pool.QueryRow(ctx, query,
		linkID, userID, email, string(tokenHash), purpose, redirectURL,
		ipAddress, userAgent, expiresAt,
	).Scan(&createdAt)
	if err != nil {
		return nil, err
	}

	return &MagicLink{
		ID:          linkID,
		UserID:      userID,
		Email:       email,
		Token:       token,
		Purpose:     purpose,
		RedirectURL: redirectURL,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Status:      "pending",
		CreatedAt:   createdAt,
		ExpiresAt:   expiresAt,
	}, nil
}

// VerifyMagicLink validates a magic link token and returns the user
func (s *Service) VerifyMagicLink(ctx context.Context, token, ipAddress, userAgent string) (string, string, error) {
	// Find pending magic links
	query := `
		SELECT id, user_id, token_hash, purpose, expires_at
		FROM magic_links
		WHERE status = 'pending'
		ORDER BY created_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()

	for rows.Next() {
		var linkID, userID, tokenHash, purpose string
		var expiresAt time.Time

		if err := rows.Scan(&linkID, &userID, &tokenHash, &purpose, &expiresAt); err != nil {
			continue
		}

		// Check expiration
		if time.Now().After(expiresAt) {
			s.db.Pool.Exec(ctx, "UPDATE magic_links SET status = 'expired' WHERE id = $1", linkID)
			continue
		}

		// Verify token
		if err := bcrypt.CompareHashAndPassword([]byte(tokenHash), []byte(token)); err != nil {
			continue // Try next link
		}

		// Token is valid - mark as used
		s.db.Pool.Exec(ctx,
			"UPDATE magic_links SET status = 'used', used_at = NOW() WHERE id = $1",
			linkID,
		)

		return userID, purpose, nil
	}

	return "", "", errors.New("invalid or expired magic link")
}

// CreateQRLoginSession creates a QR code login session
func (s *Service) CreateQRLoginSession(ctx context.Context, ipAddress string, browserInfo map[string]interface{}) (*QRLoginSession, error) {
	// Generate session token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	sessionToken := base64.URLEncoding.EncodeToString(tokenBytes)

	// Create QR code data (contains session ID and server URL)
	qrData := map[string]interface{}{
		"session": sessionToken,
		"type":    "openidx_qr_login",
		"created": time.Now().Unix(),
	}
	qrDataJSON, _ := json.Marshal(qrData)

	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(5 * time.Minute)

	query := `
		INSERT INTO qr_login_sessions (
			id, session_token, qr_code_data, status, browser_info,
			ip_address, created_at, expires_at
		) VALUES ($1, $2, $3, 'pending', $4, $5, NOW(), $6)
		RETURNING created_at
	`

	var createdAt time.Time
	err := s.db.Pool.QueryRow(ctx, query,
		sessionID, sessionToken, string(qrDataJSON), browserInfo, ipAddress, expiresAt,
	).Scan(&createdAt)
	if err != nil {
		return nil, err
	}

	return &QRLoginSession{
		ID:           sessionID,
		SessionToken: sessionToken,
		QRCodeData:   string(qrDataJSON),
		Status:       "pending",
		BrowserInfo:  browserInfo,
		IPAddress:    ipAddress,
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
	}, nil
}

// ScanQRLoginSession marks a QR session as scanned (called from mobile app)
func (s *Service) ScanQRLoginSession(ctx context.Context, sessionToken, userID string, mobileInfo map[string]interface{}) (*QRLoginSession, error) {
	// Find session
	var sessionID, status string
	var expiresAt time.Time

	err := s.db.Pool.QueryRow(ctx,
		"SELECT id, status, expires_at FROM qr_login_sessions WHERE session_token = $1",
		sessionToken,
	).Scan(&sessionID, &status, &expiresAt)
	if err != nil {
		return nil, errors.New("session not found")
	}

	if status != "pending" {
		return nil, fmt.Errorf("session is not pending (status: %s)", status)
	}

	if time.Now().After(expiresAt) {
		s.db.Pool.Exec(ctx, "UPDATE qr_login_sessions SET status = 'expired' WHERE id = $1", sessionID)
		return nil, errors.New("session expired")
	}

	// Check if user has QR login enabled
	prefs, _ := s.GetPasswordlessPreferences(ctx, userID)
	if prefs != nil && !prefs.QRLoginEnabled {
		return nil, errors.New("QR login is disabled for this user")
	}

	// Mark as scanned
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE qr_login_sessions
		SET status = 'scanned', user_id = $1, mobile_info = $2, scanned_at = NOW()
		WHERE id = $3`,
		userID, mobileInfo, sessionID,
	)
	if err != nil {
		return nil, err
	}

	return s.GetQRLoginSession(ctx, sessionToken)
}

// ApproveQRLoginSession approves a QR login from mobile app
func (s *Service) ApproveQRLoginSession(ctx context.Context, sessionToken, userID string) error {
	var sessionID, status string
	var sessionUserID *string

	err := s.db.Pool.QueryRow(ctx,
		"SELECT id, status, user_id FROM qr_login_sessions WHERE session_token = $1",
		sessionToken,
	).Scan(&sessionID, &status, &sessionUserID)
	if err != nil {
		return errors.New("session not found")
	}

	if status != "scanned" {
		return errors.New("session must be scanned first")
	}

	if sessionUserID == nil || *sessionUserID != userID {
		return errors.New("user mismatch")
	}

	_, err = s.db.Pool.Exec(ctx,
		"UPDATE qr_login_sessions SET status = 'approved', approved_at = NOW() WHERE id = $1",
		sessionID,
	)

	return err
}

// RejectQRLoginSession rejects a QR login
func (s *Service) RejectQRLoginSession(ctx context.Context, sessionToken string) error {
	_, err := s.db.Pool.Exec(ctx,
		"UPDATE qr_login_sessions SET status = 'rejected' WHERE session_token = $1",
		sessionToken,
	)
	return err
}

// GetQRLoginSession returns the current state of a QR session
func (s *Service) GetQRLoginSession(ctx context.Context, sessionToken string) (*QRLoginSession, error) {
	query := `
		SELECT id, session_token, qr_code_data, status, user_id,
			browser_info, mobile_info, ip_address, created_at, expires_at,
			scanned_at, approved_at
		FROM qr_login_sessions
		WHERE session_token = $1
	`

	var session QRLoginSession
	err := s.db.Pool.QueryRow(ctx, query, sessionToken).Scan(
		&session.ID, &session.SessionToken, &session.QRCodeData, &session.Status,
		&session.UserID, &session.BrowserInfo, &session.MobileInfo, &session.IPAddress,
		&session.CreatedAt, &session.ExpiresAt, &session.ScannedAt, &session.ApprovedAt,
	)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) && session.Status == "pending" {
		s.db.Pool.Exec(ctx, "UPDATE qr_login_sessions SET status = 'expired' WHERE id = $1", session.ID)
		session.Status = "expired"
	}

	return &session, nil
}

// PollQRLoginSession polls for QR session status (browser calls this)
func (s *Service) PollQRLoginSession(ctx context.Context, sessionToken string) (string, *string, error) {
	session, err := s.GetQRLoginSession(ctx, sessionToken)
	if err != nil {
		return "", nil, err
	}

	return session.Status, session.UserID, nil
}

// GetPasswordlessPreferences returns user's passwordless preferences
func (s *Service) GetPasswordlessPreferences(ctx context.Context, userID string) (*PasswordlessPreferences, error) {
	query := `
		SELECT id, user_id, webauthn_only, magic_link_enabled, qr_login_enabled,
			preferred_method, created_at, updated_at
		FROM passwordless_preferences
		WHERE user_id = $1
	`

	var prefs PasswordlessPreferences
	err := s.db.Pool.QueryRow(ctx, query, userID).Scan(
		&prefs.ID, &prefs.UserID, &prefs.WebAuthnOnly, &prefs.MagicLinkEnabled,
		&prefs.QRLoginEnabled, &prefs.PreferredMethod, &prefs.CreatedAt, &prefs.UpdatedAt,
	)
	if err != nil {
		// Return defaults
		return &PasswordlessPreferences{
			UserID:           userID,
			WebAuthnOnly:     false,
			MagicLinkEnabled: true,
			QRLoginEnabled:   true,
			PreferredMethod:  "webauthn",
		}, nil
	}

	return &prefs, nil
}

// UpdatePasswordlessPreferences updates user's passwordless preferences
func (s *Service) UpdatePasswordlessPreferences(ctx context.Context, userID string, prefs *PasswordlessPreferences) error {
	// Check if exists
	var existing string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT id FROM passwordless_preferences WHERE user_id = $1",
		userID,
	).Scan(&existing)

	if err == nil {
		// Update
		_, err = s.db.Pool.Exec(ctx,
			`UPDATE passwordless_preferences
			SET webauthn_only = $1, magic_link_enabled = $2, qr_login_enabled = $3,
				preferred_method = $4, updated_at = NOW()
			WHERE user_id = $5`,
			prefs.WebAuthnOnly, prefs.MagicLinkEnabled, prefs.QRLoginEnabled,
			prefs.PreferredMethod, userID,
		)
	} else {
		// Insert
		_, err = s.db.Pool.Exec(ctx,
			`INSERT INTO passwordless_preferences (
				id, user_id, webauthn_only, magic_link_enabled, qr_login_enabled,
				preferred_method, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
			uuid.New().String(), userID, prefs.WebAuthnOnly, prefs.MagicLinkEnabled,
			prefs.QRLoginEnabled, prefs.PreferredMethod,
		)
	}

	return err
}

// EnableWebAuthnOnlyLogin enables passwordless WebAuthn-only login for a user
func (s *Service) EnableWebAuthnOnlyLogin(ctx context.Context, userID string) error {
	// Verify user has WebAuthn credentials registered
	var credCount int
	err := s.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1",
		userID,
	).Scan(&credCount)
	if err != nil || credCount == 0 {
		return errors.New("user must have at least one WebAuthn credential registered")
	}

	prefs, _ := s.GetPasswordlessPreferences(ctx, userID)
	prefs.WebAuthnOnly = true
	return s.UpdatePasswordlessPreferences(ctx, userID, prefs)
}

// DisableWebAuthnOnlyLogin disables passwordless login
func (s *Service) DisableWebAuthnOnlyLogin(ctx context.Context, userID string) error {
	prefs, _ := s.GetPasswordlessPreferences(ctx, userID)
	prefs.WebAuthnOnly = false
	return s.UpdatePasswordlessPreferences(ctx, userID, prefs)
}

// CanLoginPasswordless checks if user can login without password
func (s *Service) CanLoginPasswordless(ctx context.Context, userID string) (bool, string, error) {
	prefs, err := s.GetPasswordlessPreferences(ctx, userID)
	if err != nil {
		return false, "", err
	}

	if prefs.WebAuthnOnly {
		return true, "webauthn", nil
	}

	// Check if user has any passwordless options available
	if prefs.MagicLinkEnabled || prefs.QRLoginEnabled {
		return true, prefs.PreferredMethod, nil
	}

	return false, "", nil
}

// CleanupExpiredSessions removes old expired sessions
func (s *Service) CleanupExpiredPasswordlessSessions(ctx context.Context) error {
	// Expire old magic links
	s.db.Pool.Exec(ctx,
		"UPDATE magic_links SET status = 'expired' WHERE status = 'pending' AND expires_at < NOW()",
	)

	// Expire old QR sessions
	s.db.Pool.Exec(ctx,
		"UPDATE qr_login_sessions SET status = 'expired' WHERE status = 'pending' AND expires_at < NOW()",
	)

	// Delete very old records (> 7 days)
	s.db.Pool.Exec(ctx,
		"DELETE FROM magic_links WHERE created_at < NOW() - INTERVAL '7 days'",
	)
	s.db.Pool.Exec(ctx,
		"DELETE FROM qr_login_sessions WHERE created_at < NOW() - INTERVAL '7 days'",
	)

	return nil
}
