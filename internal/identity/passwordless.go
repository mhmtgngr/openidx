// Package identity - Passwordless Authentication (Magic Link, QR Code, WebAuthn-only)
package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/orgctx"
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
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Find user by email, within the caller's org
	var userID string
	err = s.db.Pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1 AND enabled = true AND org_id = $2", email, org.ID).Scan(&userID)
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
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(token), bcryptCost)
	if err != nil {
		return nil, err
	}

	// Set purpose default
	if purpose == "" {
		purpose = "login"
	}

	linkID := uuid.New().String()
	expiresAt := time.Now().Add(15 * time.Minute) // 15 min expiry

	// Invalidate any existing pending magic links for this user.
	//
	// Requesting a new link is how a person retires one they think went astray
	// -- forwarded, left in a shared inbox, sent to a stale address. The error
	// was discarded, so a failure here handed out a second live credential
	// while the first stayed redeemable for the rest of its fifteen minutes,
	// and the person was told the old one had been replaced. Refuse to mint
	// rather than widen what is outstanding.
	if _, err := s.db.Pool.Exec(ctx,
		"UPDATE magic_links SET status = 'expired' WHERE user_id = $1 AND status = 'pending' AND org_id = $2",
		userID, org.ID,
	); err != nil {
		return nil, fmt.Errorf("retire the outstanding magic links before minting another: %w", err)
	}

	// Create magic link
	query := `
		INSERT INTO magic_links (
			id, org_id, user_id, email, token_hash, purpose, redirect_url,
			ip_address, user_agent, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', NOW(), $10)
		RETURNING created_at
	`

	var createdAt time.Time
	err = s.db.Pool.QueryRow(ctx, query,
		linkID, org.ID, userID, email, string(tokenHash), purpose, redirectURL,
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

// SendMagicLinkEmail delivers a magic-link email to the given address. The full
// verify URL (including the one-time token) is built by the caller and passed in,
// so the token is never persisted in or logged by this method.
//
// Delivery is best-effort: when no email service is configured it logs a warning
// and returns nil, so callers can keep returning a generic response without
// leaking whether an account exists.
func (s *Service) SendMagicLinkEmail(ctx context.Context, to, magicLinkURL string) error {
	if s.emailService == nil {
		s.logger.Warn("Email service not configured, magic link not delivered",
			zap.String("email", maskEmail(to)))
		return nil
	}

	return s.emailService.SendAsync(ctx, to, "Your OpenIDX sign-in link", "magic-link", map[string]interface{}{
		"MagicLinkURL": magicLinkURL,
		"ExpiresIn":    "15 minutes",
	})
}

// VerifyMagicLink validates a magic link token and returns the user
func (s *Service) VerifyMagicLink(ctx context.Context, token, ipAddress, userAgent string) (string, string, error) {
	// A PRE-TENANT-RESOLUTION lookup, the same class as api-key-by-hash and
	// route-by-host that TestPreResolutionLookupsUnderRLS pins. The visitor
	// arrives holding a link and nothing else: no session, no organization, and
	// the link is what says who they are. There is no tenant to scope by yet,
	// so the belt is lifted here rather than in spite of it — under FORCE RLS
	// this query would return no rows and every magic link in the product would
	// stop working.
	//
	// Possession of the 32-byte token is the whole entitlement, and it is
	// checked against the stored bcrypt hash, so spanning organizations
	// discloses nothing: a token matches at most the one row it was minted for,
	// and that row names its own user.
	ctx = orgctx.WithBypassRLS(ctx)

	// Find pending magic links
	//orgscope:ignore pre-tenant-resolution: the link is presented before any organization is known and is itself the credential
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
			//silentwrite:ok the refusal is the `continue` below, decided from expires_at on every
			// pass; this row only spares the next scan a bcrypt compare it would lose anyway.
			s.db.Pool.Exec(ctx,
				//orgscope:ignore link id from the bypassed pre-resolution scan above; the token is the credential
				"UPDATE magic_links SET status = 'expired' WHERE id = $1", linkID)
			continue
		}

		// Verify token
		if err := bcrypt.CompareHashAndPassword([]byte(tokenHash), []byte(token)); err != nil {
			continue // Try next link
		}

		// Token is valid - mark as used.
		//
		// THIS IS the single-use property of a magic link. The error was
		// discarded and the function returned success regardless, so a failed
		// mark left the link 'pending' and the same emailed sign-in link could
		// be redeemed again -- by anyone who has the email, for as long as the
		// link had left to live. A credential that cannot be spent must not be
		// accepted.
		if _, err := s.db.Pool.Exec(ctx,
			//orgscope:ignore link id from the bypassed pre-resolution scan above; the token is the credential
			"UPDATE magic_links SET status = 'used', used_at = NOW() WHERE id = $1",
			linkID,
		); err != nil {
			s.logger.Error("could not spend a magic link; refusing the sign-in", zap.Error(err))
			return "", "", fmt.Errorf("mark magic link used: %w", err)
		}

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

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(5 * time.Minute)

	query := `
		INSERT INTO qr_login_sessions (
			id, session_token, qr_code_data, status, browser_info,
			ip_address, created_at, expires_at, org_id
		) VALUES ($1, $2, $3, 'pending', $4, $5, NOW(), $6, $7)
		RETURNING created_at
	`

	var createdAt time.Time
	err = s.db.Pool.QueryRow(ctx, query,
		sessionID, sessionToken, string(qrDataJSON), browserInfo, ipAddress, expiresAt, org.ID,
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
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Find session within the caller's org
	var sessionID, status string
	var expiresAt time.Time

	err = s.db.Pool.QueryRow(ctx,
		"SELECT id, status, expires_at FROM qr_login_sessions WHERE session_token = $1 AND org_id = $2",
		sessionToken, org.ID,
	).Scan(&sessionID, &status, &expiresAt)
	if err != nil {
		return nil, errors.New("session not found")
	}

	if status != "pending" {
		return nil, fmt.Errorf("session is not pending (status: %s)", status)
	}

	if time.Now().After(expiresAt) {
		//silentwrite:ok the scan is refused by the return below, decided from expires_at every time;
		// the row only saves the next caller the same comparison, and never grants what it denies.
		s.db.Pool.Exec(ctx, "UPDATE qr_login_sessions SET status = 'expired' WHERE id = $1 AND org_id = $2", sessionID, org.ID)
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
		WHERE id = $3 AND org_id = $4`,
		userID, mobileInfo, sessionID, org.ID,
	)
	if err != nil {
		return nil, err
	}

	return s.GetQRLoginSession(ctx, sessionToken)
}

// ApproveQRLoginSession approves a QR login from mobile app
func (s *Service) ApproveQRLoginSession(ctx context.Context, sessionToken, userID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Read and approve in one statement.
	//
	// Two things were wrong with reading first and then updating. The check and
	// the act were separate, so two approvals racing on one session both passed
	// the status test; and the five-minute expiry was never checked here at
	// all. ScanQRLoginSession refuses an expired session and GetQRLoginSession
	// marks one expired only while it is still 'pending' -- so once a phone had
	// scanned, the window never closed again, and a session scanned and left
	// alone could be approved a week later, until the cleanup sweep removed the
	// row. The clause below is the expiry the flow always claimed to have.
	var sessionID string
	err = s.db.Pool.QueryRow(ctx, `
		UPDATE qr_login_sessions SET status = 'approved', approved_at = NOW()
		WHERE session_token = $1 AND org_id = $2 AND status = 'scanned'
		  AND user_id = $3 AND expires_at > NOW()
		RETURNING id`,
		sessionToken, org.ID, userID,
	).Scan(&sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Say which of the four it was, without leaking a session's state to
		// someone who guessed a token: this is only reached by the user the
		// session already names, or by a caller holding the token.
		return s.explainUnapprovableQRSession(ctx, sessionToken, userID, org.ID)
	}
	return err
}

// explainUnapprovableQRSession turns a refused approval into the reason for it.
// The approve above is a single conditional UPDATE, so it cannot report which
// condition failed; this re-reads the row to say so.
func (s *Service) explainUnapprovableQRSession(ctx context.Context, sessionToken, userID, orgID string) error {
	var status string
	var sessionUserID *string
	var expiresAt time.Time
	if err := s.db.Pool.QueryRow(ctx,
		"SELECT status, user_id, expires_at FROM qr_login_sessions WHERE session_token = $1 AND org_id = $2",
		sessionToken, orgID,
	).Scan(&status, &sessionUserID, &expiresAt); err != nil {
		return errors.New("session not found")
	}
	switch {
	case status != "scanned":
		return errors.New("session must be scanned first")
	case sessionUserID == nil || *sessionUserID != userID:
		return errors.New("user mismatch")
	case time.Now().After(expiresAt):
		return errors.New("session expired")
	}
	// Scanned, this user's, unexpired -- and the UPDATE still matched nothing,
	// so another approval took it between the two statements.
	return errors.New("session was already approved")
}

// RejectQRLoginSession rejects a QR login
func (s *Service) RejectQRLoginSession(ctx context.Context, sessionToken string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx,
		"UPDATE qr_login_sessions SET status = 'rejected' WHERE session_token = $1 AND org_id = $2",
		sessionToken, org.ID,
	)
	return err
}

// GetQRLoginSession returns the current state of a QR session
func (s *Service) GetQRLoginSession(ctx context.Context, sessionToken string) (*QRLoginSession, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, session_token, qr_code_data, status, user_id,
			browser_info, mobile_info, ip_address, created_at, expires_at,
			scanned_at, approved_at
		FROM qr_login_sessions
		WHERE session_token = $1 AND org_id = $2
	`

	var session QRLoginSession
	err = s.db.Pool.QueryRow(ctx, query, sessionToken, org.ID).Scan(
		&session.ID, &session.SessionToken, &session.QRCodeData, &session.Status,
		&session.UserID, &session.BrowserInfo, &session.MobileInfo, &session.IPAddress,
		&session.CreatedAt, &session.ExpiresAt, &session.ScannedAt, &session.ApprovedAt,
	)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) && session.Status == "pending" {
		//silentwrite:ok the caller is told "expired" on the next line whether or not this lands,
		// and the same comparison runs on every read, so a failure costs a row, never a decision.
		s.db.Pool.Exec(ctx, "UPDATE qr_login_sessions SET status = 'expired' WHERE id = $1 AND org_id = $2", session.ID, org.ID)
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
		WHERE user_id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $1)
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
		`SELECT id FROM passwordless_preferences
		  WHERE user_id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $1)`,
		userID,
	).Scan(&existing)

	if err == nil {
		// Update
		_, err = s.db.Pool.Exec(ctx,
			`UPDATE passwordless_preferences
			SET webauthn_only = $1, magic_link_enabled = $2, qr_login_enabled = $3,
				preferred_method = $4, updated_at = NOW()
			WHERE user_id = $5 AND org_id = (SELECT org_id FROM users WHERE id = $5)`,
			prefs.WebAuthnOnly, prefs.MagicLinkEnabled, prefs.QRLoginEnabled,
			prefs.PreferredMethod, userID,
		)
	} else {
		// Insert
		_, err = s.db.Pool.Exec(ctx,
			// org_id comes from the row's own user, so the two cannot disagree
			// and the v143 WITH CHECK cannot refuse a legitimate write.
			`INSERT INTO passwordless_preferences (
				id, org_id, user_id, webauthn_only, magic_link_enabled, qr_login_enabled,
				preferred_method, created_at, updated_at
			) VALUES ($1, (SELECT org_id FROM users WHERE id = $2), $2, $3, $4, $5, $6, NOW(), NOW())`,
			uuid.New().String(), userID, prefs.WebAuthnOnly, prefs.MagicLinkEnabled,
			prefs.QRLoginEnabled, prefs.PreferredMethod,
		)
	}

	return err
}

// EnableWebAuthnOnlyLogin enables passwordless WebAuthn-only login for a user
func (s *Service) EnableWebAuthnOnlyLogin(ctx context.Context, userID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	// Verify the user has WebAuthn credentials registered. Creds live in
	// mfa_webauthn — the phantom `webauthn_credentials` table is never created.
	var credCount int
	if err := s.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM mfa_webauthn WHERE user_id = $1 AND org_id = $2",
		userID, org.ID,
	).Scan(&credCount); err != nil {
		return err
	}
	if credCount == 0 {
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

// CleanupExpiredPasswordlessSessions removes old expired sessions. This is a
// time-based maintenance sweep that runs across all orgs (e.g. from a
// background job with no request/tenant context), so its queries are
// intentionally org-unscoped: they only touch already-expired or week-old
// rows and expose no tenant data.
func (s *Service) CleanupExpiredPasswordlessSessions(ctx context.Context) error {
	// Since v145 magic_links sits behind the FORCE RLS belt, so a sweep with no
	// tenant on its connection would match nothing at all and quietly stop
	// cleaning up — the belt turning a maintenance job into a no-op is a real
	// failure mode of adding one. The bypass is what keeps the sweep doing its
	// job; the WHERE clauses are what keep it harmless.
	ctx = orgctx.WithBypassRLS(ctx)

	// Every statement below discarded its error and the function returned nil
	// regardless, so a sweep that cleaned nothing -- a revoked grant, a
	// permission the belt no longer allows, a table renamed under it -- looked
	// exactly like a sweep that worked, on every run, forever. The rows this
	// job deletes are spent sign-in credentials; a scheduler that is never told
	// it has stopped collecting them is how they accumulate for months.
	//
	// One failing statement does not stop the others: each is independent
	// cleanup, and the caller wants as much of it done as possible. It does
	// mean the run is reported as failed.
	var failed []string
	sweep := func(what, sql string) {
		if _, err := s.db.Pool.Exec(ctx, sql); err != nil {
			s.logger.Error("passwordless cleanup statement failed",
				zap.String("sweep", what), zap.Error(err))
			failed = append(failed, what)
		}
	}

	// Expire old magic links
	//orgscope:ignore cross-org maintenance sweep of expired links; no request/tenant context
	sweep("expire magic links", "UPDATE magic_links SET status = 'expired' WHERE status = 'pending' AND expires_at < NOW()")

	// Expire old QR sessions
	//orgscope:ignore cross-org maintenance sweep of expired sessions; no request/tenant context
	sweep("expire QR sessions", "UPDATE qr_login_sessions SET status = 'expired' WHERE status = 'pending' AND expires_at < NOW()")

	// Delete very old records (> 7 days)
	//orgscope:ignore cross-org maintenance sweep of week-old links; no request/tenant context
	sweep("delete week-old magic links", "DELETE FROM magic_links WHERE created_at < NOW() - INTERVAL '7 days'")
	//orgscope:ignore cross-org maintenance sweep of week-old sessions; no request/tenant context
	sweep("delete week-old QR sessions", "DELETE FROM qr_login_sessions WHERE created_at < NOW() - INTERVAL '7 days'")

	if len(failed) > 0 {
		return fmt.Errorf("passwordless cleanup did not run: %s", strings.Join(failed, ", "))
	}
	return nil
}
