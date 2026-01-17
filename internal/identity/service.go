// Package identity provides identity management functionality
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// User represents a user in the system
type User struct {
	ID            string            `json:"id"`
	Username      string            `json:"username"`
	Email         string            `json:"email"`
	FirstName     string            `json:"first_name"`
	LastName      string            `json:"last_name"`
	Enabled       bool              `json:"enabled"`
	EmailVerified bool              `json:"email_verified"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	Groups        []string          `json:"groups,omitempty"`
	Roles         []string          `json:"roles,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	LastLoginAt   *time.Time        `json:"last_login_at,omitempty"`
	// Password policy fields
	PasswordChangedAt    *time.Time `json:"password_changed_at,omitempty"`
	PasswordMustChange   bool       `json:"password_must_change"`
	// Account lockout fields
	FailedLoginCount     int        `json:"failed_login_count"`
	LastFailedLoginAt    *time.Time `json:"last_failed_login_at,omitempty"`
	LockedUntil          *time.Time `json:"locked_until,omitempty"`
}

// Session represents an active user session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	StartedAt time.Time `json:"started_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MFATOTP represents TOTP MFA settings for a user
type MFATOTP struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Secret     string     `json:"-"` // Never expose in JSON
	Enabled    bool       `json:"enabled"`
	EnrolledAt *time.Time `json:"enrolled_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// MFABackupCode represents a backup code for MFA
type MFABackupCode struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CodeHash  string    `json:"-"` // Never expose in JSON
	Used      bool      `json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// MFAPolicy represents an MFA enforcement policy
type MFAPolicy struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	Enabled          bool                   `json:"enabled"`
	Priority         int                    `json:"priority"`
	Conditions       map[string]interface{} `json:"conditions"`
	RequiredMethods  []string               `json:"required_methods"`
	GracePeriodHours int                    `json:"grace_period_hours"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// TOTPEnrollment represents the enrollment process
type TOTPEnrollment struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
	ManualKey string `json:"manual_key"`
}

// TOTPVerification represents a TOTP verification request
type TOTPVerification struct {
	Code string `json:"code"`
}

// Group represents a group in the system
type Group struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	ParentID       *string   `json:"parent_id,omitempty"`
	AllowSelfJoin  bool      `json:"allow_self_join"`
	RequireApproval bool     `json:"require_approval"`
	MaxMembers     *int      `json:"max_members,omitempty"`
	MemberCount    int       `json:"member_count"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// GroupMember represents a user's membership in a group
type GroupMember struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	JoinedAt  time.Time `json:"joined_at"`
}

// Service provides identity management operations
type Service struct {
	db                *database.PostgresDB
	redis             *database.RedisClient
	cfg               *config.Config
	logger            *zap.Logger
	webauthnSessions  sync.Map // In-memory storage for WebAuthn sessions (use Redis in production)
	pushMFASessions   sync.Map // In-memory storage for Push MFA challenges (use Redis in production)
}

// NewService creates a new identity service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		cfg:    cfg,
		logger: logger.With(zap.String("service", "identity")),
	}
}

// GetUser retrieves a user by ID
func (s *Service) GetUser(ctx context.Context, userID string) (*User, error) {
	s.logger.Debug("Getting user", zap.String("user_id", userID))

	// Query from Keycloak or local cache
	var user User
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, username, email, first_name, last_name, enabled, email_verified,
		       created_at, updated_at, last_login_at, password_changed_at,
		       password_must_change, failed_login_count, last_failed_login_at, locked_until
		FROM users WHERE id = $1
	`, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.FirstName, &user.LastName,
		&user.Enabled, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
		&user.PasswordChangedAt, &user.PasswordMustChange, &user.FailedLoginCount,
		&user.LastFailedLoginAt, &user.LockedUntil,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// ListUsers retrieves users with pagination
func (s *Service) ListUsers(ctx context.Context, offset, limit int) ([]User, int, error) {
	s.logger.Debug("Listing users", zap.Int("offset", offset), zap.Int("limit", limit))

	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, username, email, first_name, last_name, enabled, email_verified,
		       created_at, updated_at, last_login_at, password_changed_at,
		       password_must_change, failed_login_count, last_failed_login_at, locked_until
		FROM users
		ORDER BY created_at DESC
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName,
			&u.Enabled, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
			&u.PasswordChangedAt, &u.PasswordMustChange, &u.FailedLoginCount,
			&u.LastFailedLoginAt, &u.LockedUntil,
		); err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}

	return users, total, nil
}

// CreateUser creates a new user
func (s *Service) CreateUser(ctx context.Context, user *User) error {
	s.logger.Info("Creating user", zap.String("username", user.Username))

	// Generate UUID if not provided
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, first_name, last_name, enabled,
		                   email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, user.ID, user.Username, user.Email, user.FirstName, user.LastName,
		user.Enabled, user.EmailVerified, user.CreatedAt, user.UpdatedAt)

	return err
}

// UpdateUser updates an existing user
func (s *Service) UpdateUser(ctx context.Context, user *User) error {
	s.logger.Info("Updating user", zap.String("user_id", user.ID))
	
	user.UpdatedAt = time.Now()
	
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE users 
		SET username = $2, email = $3, first_name = $4, last_name = $5,
		    enabled = $6, email_verified = $7, updated_at = $8
		WHERE id = $1
	`, user.ID, user.Username, user.Email, user.FirstName, user.LastName,
		user.Enabled, user.EmailVerified, user.UpdatedAt)
	
	return err
}

// DeleteUser deletes a user
func (s *Service) DeleteUser(ctx context.Context, userID string) error {
	s.logger.Info("Deleting user", zap.String("user_id", userID))
	
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	return err
}

// GetUserSessions retrieves active sessions for a user
func (s *Service) GetUserSessions(ctx context.Context, userID string) ([]Session, error) {
	s.logger.Debug("Getting sessions for user", zap.String("user_id", userID))
	
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, user_id, client_id, ip_address, user_agent, 
		       started_at, last_seen_at, expires_at
		FROM sessions
		WHERE user_id = $1 AND expires_at > NOW()
		ORDER BY last_seen_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var sessions []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.ClientID, &s.IPAddress, &s.UserAgent,
			&s.StartedAt, &s.LastSeenAt, &s.ExpiresAt,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	
	return sessions, nil
}

// TerminateSession terminates a specific session
func (s *Service) TerminateSession(ctx context.Context, sessionID string) error {
	s.logger.Info("Terminating session", zap.String("session_id", sessionID))

	_, err := s.db.Pool.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)
	return err
}

// ListGroups retrieves groups with pagination
func (s *Service) ListGroups(ctx context.Context, offset, limit int) ([]Group, int, error) {
	s.logger.Debug("Listing groups", zap.Int("offset", offset), zap.Int("limit", limit))

	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM groups").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT g.id, g.name, g.description, g.parent_id, g.allow_self_join, g.require_approval, g.max_members, g.created_at, g.updated_at,
		       COALESCE((SELECT COUNT(*) FROM group_memberships gm WHERE gm.group_id = g.id), 0) as member_count
		FROM groups g
		ORDER BY g.name
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(
			&g.ID, &g.Name, &g.Description, &g.ParentID, &g.AllowSelfJoin, &g.RequireApproval, &g.MaxMembers, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount,
		); err != nil {
			return nil, 0, err
		}
		groups = append(groups, g)
	}

	return groups, total, nil
}

// GetGroup retrieves a group by ID
func (s *Service) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	s.logger.Debug("Getting group", zap.String("group_id", groupID))

	var g Group
	err := s.db.Pool.QueryRow(ctx, `
		SELECT g.id, g.name, g.description, g.parent_id, g.allow_self_join, g.require_approval, g.max_members, g.created_at, g.updated_at,
		       COALESCE((SELECT COUNT(*) FROM group_memberships gm WHERE gm.group_id = g.id), 0) as member_count
		FROM groups g WHERE g.id = $1
	`, groupID).Scan(
		&g.ID, &g.Name, &g.Description, &g.ParentID, &g.AllowSelfJoin, &g.RequireApproval, &g.MaxMembers, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount,
	)
	if err != nil {
		return nil, err
	}

	return &g, nil
}

// GetGroupMembers retrieves members of a group
func (s *Service) GetGroupMembers(ctx context.Context, groupID string) ([]GroupMember, error) {
	s.logger.Debug("Getting group members", zap.String("group_id", groupID))

	rows, err := s.db.Pool.Query(ctx, `
		SELECT u.id, u.username, u.email, u.first_name, u.last_name, gm.joined_at
		FROM users u
		JOIN group_memberships gm ON u.id = gm.user_id
		WHERE gm.group_id = $1
		ORDER BY gm.joined_at
	`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.UserID, &m.Username, &m.Email, &m.FirstName, &m.LastName, &m.JoinedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}

	return members, nil
}

// CreateGroup creates a new group
func (s *Service) CreateGroup(ctx context.Context, group *Group) error {
	s.logger.Info("Creating group", zap.String("name", group.Name))

	// Generate UUID if not provided
	if group.ID == "" {
		group.ID = uuid.New().String()
	}

	now := time.Now()
	group.CreatedAt = now
	group.UpdatedAt = now

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO groups (id, name, description, parent_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, group.ID, group.Name, group.Description, group.ParentID, group.CreatedAt, group.UpdatedAt)

	return err
}

// UpdateGroup updates an existing group
func (s *Service) UpdateGroup(ctx context.Context, group *Group) error {
	s.logger.Info("Updating group", zap.String("group_id", group.ID))

	group.UpdatedAt = time.Now()

	_, err := s.db.Pool.Exec(ctx, `
		UPDATE groups
		SET name = $2, description = $3, parent_id = $4, allow_self_join = $5, require_approval = $6, max_members = $7, updated_at = $8
		WHERE id = $1
	`, group.ID, group.Name, group.Description, group.ParentID, group.AllowSelfJoin, group.RequireApproval, group.MaxMembers, group.UpdatedAt)

	return err
}

// DeleteGroup deletes a group
func (s *Service) DeleteGroup(ctx context.Context, groupID string) error {
	s.logger.Info("Deleting group", zap.String("group_id", groupID))

	// First remove all group memberships
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM group_memberships WHERE group_id = $1", groupID)
	if err != nil {
		return fmt.Errorf("failed to remove group memberships: %w", err)
	}

	// Then delete the group
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM groups WHERE id = $1", groupID)
	return err
}

// CreateSession creates a new user session
func (s *Service) CreateSession(ctx context.Context, userID, clientID, ipAddress, userAgent string, sessionDuration time.Duration) (*Session, error) {
	s.logger.Info("Creating session", zap.String("user_id", userID), zap.String("client_id", clientID))

	sessionID := uuid.New().String()
	now := time.Now()
	expiresAt := now.Add(sessionDuration)

	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		ClientID:  clientID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		StartedAt: now,
		LastSeenAt: now,
		ExpiresAt: expiresAt,
	}

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, client_id, ip_address, user_agent, started_at, last_seen_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, session.ID, session.UserID, session.ClientID, session.IPAddress, session.UserAgent,
		session.StartedAt, session.LastSeenAt, session.ExpiresAt)

	if err != nil {
		return nil, err
	}

	return session, nil
}

// UpdateSessionActivity updates the last seen time for a session
func (s *Service) UpdateSessionActivity(ctx context.Context, sessionID string) error {
	s.logger.Debug("Updating session activity", zap.String("session_id", sessionID))

	now := time.Now()
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE sessions SET last_seen_at = $2 WHERE id = $1
	`, sessionID, now)

	return err
}

// RecordFailedLogin records a failed login attempt for account lockout
func (s *Service) RecordFailedLogin(ctx context.Context, username string) error {
	s.logger.Info("Recording failed login", zap.String("username", username))

	now := time.Now()

	// Get current user state
	var user User
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, failed_login_count, last_failed_login_at, locked_until
		FROM users WHERE username = $1
	`, username).Scan(&user.ID, &user.FailedLoginCount, &user.LastFailedLoginAt, &user.LockedUntil)
	if err != nil {
		return err
	}

	user.FailedLoginCount++
	user.LastFailedLoginAt = &now

	// Check if account should be locked (after 5 failed attempts)
	maxFailures := 5
	lockoutDuration := 15 * time.Minute // 15 minutes lockout

	if user.FailedLoginCount >= maxFailures {
		lockoutUntil := now.Add(lockoutDuration)
		user.LockedUntil = &lockoutUntil
		s.logger.Warn("Account locked due to failed login attempts",
			zap.String("username", username), zap.Int("failures", user.FailedLoginCount))
	}

	// Update user record
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE users
		SET failed_login_count = $2, last_failed_login_at = $3, locked_until = $4
		WHERE username = $1
	`, username, user.FailedLoginCount, user.LastFailedLoginAt, user.LockedUntil)

	return err
}

// ClearFailedLogins clears failed login attempts (on successful login)
func (s *Service) ClearFailedLogins(ctx context.Context, username string) error {
	s.logger.Debug("Clearing failed logins", zap.String("username", username))

	_, err := s.db.Pool.Exec(ctx, `
		UPDATE users
		SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL
		WHERE username = $1
	`, username)

	return err
}

// IsAccountLocked checks if a user account is currently locked
func (s *Service) IsAccountLocked(ctx context.Context, username string) (bool, error) {
	var lockedUntil *time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT locked_until FROM users WHERE username = $1
	`, username).Scan(&lockedUntil)

	if err != nil {
		return false, err
	}

	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		return true, nil
	}

	return false, nil
}

// ValidatePasswordPolicy validates a password against policy requirements
func (s *Service) ValidatePasswordPolicy(password string) error {
	// Basic password policy: minimum 8 characters, at least one uppercase, one lowercase, one digit
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}

	return nil
}

// UpdatePassword updates a user's password and enforces policy
func (s *Service) UpdatePassword(ctx context.Context, userID string, newPassword string) error {
	s.logger.Info("Updating password", zap.String("user_id", userID))

	// Validate password policy
	if err := s.ValidatePasswordPolicy(newPassword); err != nil {
		return err
	}

	now := time.Now()

	// Update password changed timestamp and clear must change flag
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE users
		SET password_changed_at = $2, password_must_change = false
		WHERE id = $1
	`, userID, now)

	return err
}

// CheckPasswordExpiry checks if a user's password has expired
func (s *Service) CheckPasswordExpiry(ctx context.Context, userID string) (bool, error) {
	var passwordChangedAt *time.Time
	var mustChange bool

	err := s.db.Pool.QueryRow(ctx, `
		SELECT password_changed_at, password_must_change FROM users WHERE id = $1
	`, userID).Scan(&passwordChangedAt, &mustChange)

	if err != nil {
		return false, err
	}

	// If must_change is set, password has expired
	if mustChange {
		return true, nil
	}

	// Check if password is older than 90 days
	if passwordChangedAt != nil {
		expiryDuration := 90 * 24 * time.Hour // 90 days
		if time.Since(*passwordChangedAt) > expiryDuration {
			return true, nil
		}
	}

	return false, nil
}

// GenerateTOTPSecret generates a new TOTP secret and QR code for enrollment
func (s *Service) GenerateTOTPSecret(ctx context.Context, userID string) (*TOTPEnrollment, error) {
	s.logger.Info("Generating TOTP secret", zap.String("user_id", userID))

	// Get user information for QR code
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "OpenIDX",
		AccountName: user.Email,
		SecretSize:  32,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Generate QR code URL
	qrURL := key.URL()

	return &TOTPEnrollment{
		Secret:    key.Secret(),
		QRCodeURL: qrURL,
		ManualKey: key.Secret(),
	}, nil
}

// EnrollTOTP enrolls a user with TOTP MFA after verification
func (s *Service) EnrollTOTP(ctx context.Context, userID, secret, verificationCode string) error {
	s.logger.Info("Enrolling TOTP for user", zap.String("user_id", userID))

	// Verify the code first
	valid := totp.Validate(verificationCode, secret)
	if !valid {
		return fmt.Errorf("invalid TOTP verification code")
	}

	now := time.Now()
	totpID := uuid.New().String()

	// Insert TOTP record
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO mfa_totp (id, user_id, secret, enabled, enrolled_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, totpID, userID, secret, true, now, now, now)

	if err != nil {
		return fmt.Errorf("failed to enroll TOTP: %w", err)
	}

	return nil
}

// VerifyTOTP verifies a TOTP code for a user
func (s *Service) VerifyTOTP(ctx context.Context, userID, code string) (bool, error) {
	s.logger.Debug("Verifying TOTP code", zap.String("user_id", userID))

	// Get user's TOTP secret
	var secret string
	var enabled bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT secret, enabled FROM mfa_totp WHERE user_id = $1
	`, userID).Scan(&secret, &enabled)

	if err != nil {
		return false, fmt.Errorf("failed to get TOTP settings: %w", err)
	}

	if !enabled {
		return false, fmt.Errorf("TOTP not enabled for user")
	}

	// Verify the code
	valid := totp.Validate(code, secret)
	if valid {
		// Update last used timestamp
		now := time.Now()
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE mfa_totp SET last_used_at = $2, updated_at = $2 WHERE user_id = $1
		`, userID, now)
		if err != nil {
			s.logger.Warn("Failed to update TOTP last used timestamp", zap.Error(err))
		}
	}

	return valid, nil
}

// DisableTOTP disables TOTP for a user
func (s *Service) DisableTOTP(ctx context.Context, userID string) error {
	s.logger.Info("Disabling TOTP for user", zap.String("user_id", userID))

	_, err := s.db.Pool.Exec(ctx, `
		UPDATE mfa_totp SET enabled = false, updated_at = $2 WHERE user_id = $1
	`, userID, time.Now())

	return err
}

// GetTOTPStatus returns the TOTP status for a user
func (s *Service) GetTOTPStatus(ctx context.Context, userID string) (*MFATOTP, error) {
	s.logger.Debug("Getting TOTP status", zap.String("user_id", userID))

	var totp MFATOTP
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, enabled, enrolled_at, last_used_at, created_at, updated_at
		FROM mfa_totp WHERE user_id = $1
	`, userID).Scan(
		&totp.ID, &totp.UserID, &totp.Enabled, &totp.EnrolledAt,
		&totp.LastUsedAt, &totp.CreatedAt, &totp.UpdatedAt,
	)

	if err != nil {
		// Return empty status if no TOTP configured
		return &MFATOTP{UserID: userID, Enabled: false}, nil
	}

	return &totp, nil
}

// GenerateBackupCodes generates backup codes for MFA
func (s *Service) GenerateBackupCodes(ctx context.Context, userID string, count int) ([]string, error) {
	s.logger.Info("Generating backup codes", zap.String("user_id", userID), zap.Int("count", count))

	if count <= 0 || count > 20 {
		count = 10 // Default to 10 codes
	}

	var codes []string

	for i := 0; i < count; i++ {
		// Generate random 8-character alphanumeric code
		bytes := make([]byte, 8)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}

		code := base32.StdEncoding.EncodeToString(bytes)[:8]
		codes = append(codes, strings.ToUpper(code))

		// Hash the code for storage
		hash := sha256.Sum256([]byte(code))
		codeHash := hex.EncodeToString(hash[:])

		// Store in database
		codeID := uuid.New().String()
		_, err := s.db.Pool.Exec(ctx, `
			INSERT INTO mfa_backup_codes (id, user_id, code_hash, created_at)
			VALUES ($1, $2, $3, $4)
		`, codeID, userID, codeHash, time.Now())

		if err != nil {
			return nil, fmt.Errorf("failed to store backup code: %w", err)
		}
	}

	return codes, nil
}

// ValidateBackupCode validates a backup code and marks it as used
func (s *Service) ValidateBackupCode(ctx context.Context, userID, code string) (bool, error) {
	s.logger.Info("Validating backup code", zap.String("user_id", userID))

	// Hash the provided code
	hash := sha256.Sum256([]byte(strings.ToUpper(code)))
	codeHash := hex.EncodeToString(hash[:])

	// Check if code exists and is unused
	var codeID string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id FROM mfa_backup_codes
		WHERE user_id = $1 AND code_hash = $2 AND used = false
	`, userID, codeHash).Scan(&codeID)

	if err != nil {
		return false, nil // Code not found or already used
	}

	// Mark code as used
	now := time.Now()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE mfa_backup_codes SET used = true, used_at = $2 WHERE id = $1
	`, codeID, now)

	if err != nil {
		s.logger.Warn("Failed to mark backup code as used", zap.Error(err))
	}

	return true, nil
}

// GetRemainingBackupCodes returns count of unused backup codes
func (s *Service) GetRemainingBackupCodes(ctx context.Context, userID string) (int, error) {
	var count int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1 AND used = false
	`, userID).Scan(&count)

	return count, err
}

// IsMFARequired checks if MFA is required for a user based on policies
func (s *Service) IsMFARequired(ctx context.Context, userID string, clientIP string) (bool, *MFAPolicy, error) {
	s.logger.Debug("Checking MFA requirements", zap.String("user_id", userID), zap.String("client_ip", clientIP))

	// Get all active MFA policies ordered by priority
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, enabled, priority, conditions, required_methods, grace_period_hours,
		       created_at, updated_at
		FROM mfa_policies
		WHERE enabled = true
		ORDER BY priority DESC
	`)
	if err != nil {
		return false, nil, fmt.Errorf("failed to query MFA policies: %w", err)
	}
	defer rows.Close()

	var policies []MFAPolicy
	for rows.Next() {
		var policy MFAPolicy
		err := rows.Scan(
			&policy.ID, &policy.Name, &policy.Description, &policy.Enabled, &policy.Priority,
			&policy.Conditions, &policy.RequiredMethods, &policy.GracePeriodHours,
			&policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return false, nil, fmt.Errorf("failed to scan policy: %w", err)
		}
		policies = append(policies, policy)
	}

	// Evaluate each policy in priority order
	for _, policy := range policies {
		required, err := s.evaluateMFAPolicy(ctx, userID, clientIP, &policy)
		if err != nil {
			s.logger.Warn("Failed to evaluate MFA policy", zap.String("policy_id", policy.ID), zap.Error(err))
			continue
		}

		if required {
			return true, &policy, nil
		}
	}

	return false, nil, nil
}

// evaluateMFAPolicy evaluates if a specific MFA policy applies to a user
func (s *Service) evaluateMFAPolicy(ctx context.Context, userID, clientIP string, policy *MFAPolicy) (bool, error) {
	// Parse conditions - Conditions is already map[string]interface{} from JSONB
	conditions := policy.Conditions
	if conditions == nil {
		// No conditions means policy applies to all
		return true, nil
	}

	// Check group membership conditions
	if groups, exists := conditions["groups"]; exists {
		if !s.checkUserInGroups(ctx, userID, groups) {
			return false, nil
		}
	}

	// Check IP range conditions
	if ipRanges, exists := conditions["ip_ranges"]; exists {
		if !s.checkIPInRanges(clientIP, ipRanges) {
			return false, nil
		}
	}

	// Check time-based conditions
	if timeWindows, exists := conditions["time_windows"]; exists {
		if !s.checkTimeWindow(timeWindows) {
			return false, nil
		}
	}

	// Check user attributes
	if attributes, exists := conditions["attributes"]; exists {
		if !s.checkUserAttributes(ctx, userID, attributes) {
			return false, nil
		}
	}

	// If we reach here, all conditions are met
	return true, nil
}

// checkUserInGroups checks if user belongs to any of the specified groups
func (s *Service) checkUserInGroups(ctx context.Context, userID string, groups interface{}) bool {
	groupList, ok := groups.([]interface{})
	if !ok {
		return false
	}

	// Get user's group memberships
	userGroups, err := s.getUserGroups(ctx, userID)
	if err != nil {
		s.logger.Warn("Failed to get user groups for MFA policy", zap.Error(err))
		return false
	}

	// Convert to string slice for comparison
	var userGroupNames []string
	for _, group := range userGroups {
		userGroupNames = append(userGroupNames, group.Name)
	}

	// Check if user is in any required group
	for _, requiredGroup := range groupList {
		groupName, ok := requiredGroup.(string)
		if !ok {
			continue
		}

		for _, userGroup := range userGroupNames {
			if userGroup == groupName {
				return true
			}
		}
	}

	return false
}

// checkIPInRanges checks if IP address falls within any specified ranges
func (s *Service) checkIPInRanges(clientIP string, ipRanges interface{}) bool {
	rangeList, ok := ipRanges.([]interface{})
	if !ok {
		return false
	}

	// Parse client IP
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	// Check each IP range
	for _, ipRange := range rangeList {
		rangeStr, ok := ipRange.(string)
		if !ok {
			continue
		}

		// Parse CIDR notation (e.g., "192.168.1.0/24")
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			s.logger.Warn("Invalid IP range in MFA policy", zap.String("range", rangeStr))
			continue
		}

		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// checkTimeWindow checks if current time falls within specified windows
func (s *Service) checkTimeWindow(timeWindows interface{}) bool {
	windows, ok := timeWindows.([]interface{})
	if !ok {
		return false
	}

	now := time.Now()
	currentDay := now.Weekday()
	currentHour := now.Hour()

	for _, window := range windows {
		windowMap, ok := window.(map[string]interface{})
		if !ok {
			continue
		}

		// Check day of week
		if days, exists := windowMap["days"]; exists {
			dayList, ok := days.([]interface{})
			if ok {
				dayMatches := false
				for _, day := range dayList {
					if dayStr, ok := day.(string); ok {
						if strings.EqualFold(dayStr, currentDay.String()) {
							dayMatches = true
							break
						}
					}
				}
				if !dayMatches {
					continue
				}
			}
		}

		// Check time range
		if startHour, exists := windowMap["start_hour"]; exists {
			if endHour, exists := windowMap["end_hour"]; exists {
				start, ok1 := startHour.(float64)
				end, ok2 := endHour.(float64)
				if ok1 && ok2 {
					if currentHour >= int(start) && currentHour <= int(end) {
						return true
					}
				}
			}
		}
	}

	return false
}

// checkUserAttributes checks if user has specified attributes
func (s *Service) checkUserAttributes(ctx context.Context, userID string, attributes interface{}) bool {
	attrMap, ok := attributes.(map[string]interface{})
	if !ok {
		return false
	}

	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return false
	}

	// Check user attributes (this could be extended to check custom attributes)
	for key, expectedValue := range attrMap {
		switch key {
		case "email_verified":
			if expected, ok := expectedValue.(bool); ok {
				if user.EmailVerified != expected {
					return false
				}
			}
		case "enabled":
			if expected, ok := expectedValue.(bool); ok {
				if user.Enabled != expected {
					return false
				}
			}
		// Add more attribute checks as needed
		}
	}

	return true
}

// getUserGroups retrieves all groups a user belongs to
func (s *Service) getUserGroups(ctx context.Context, userID string) ([]Group, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT g.id, g.name, g.description, g.parent_id, g.created_at, g.updated_at
		FROM groups g
		JOIN group_memberships gm ON g.id = gm.group_id
		WHERE gm.user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.ParentID, &g.CreatedAt, &g.UpdatedAt)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	return groups, nil
}

// RegisterRoutes registers identity service routes
func RegisterRoutes(router *gin.Engine, svc *Service) {
	identity := router.Group("/api/v1/identity")
	{
		// User management
		identity.GET("/users", svc.handleListUsers)
		identity.POST("/users", svc.handleCreateUser)
		identity.GET("/users/:id", svc.handleGetUser)
		identity.PUT("/users/:id", svc.handleUpdateUser)
		identity.DELETE("/users/:id", svc.handleDeleteUser)

		// Session management
		identity.GET("/users/:id/sessions", svc.handleGetUserSessions)
		identity.DELETE("/sessions/:id", svc.handleTerminateSession)

		// Group management
		identity.GET("/groups", svc.handleListGroups)
		identity.POST("/groups", svc.handleCreateGroup)
		identity.GET("/groups/:id", svc.handleGetGroup)
		identity.PUT("/groups/:id", svc.handleUpdateGroup)
		identity.DELETE("/groups/:id", svc.handleDeleteGroup)
		identity.GET("/groups/:id/members", svc.handleGetGroupMembers)

		// MFA management
		identity.POST("/mfa/totp/setup", svc.handleSetupTOTP)
		identity.POST("/mfa/totp/enroll", svc.handleEnrollTOTP)
		identity.POST("/mfa/totp/verify", svc.handleVerifyTOTP)
		identity.GET("/mfa/totp/status", svc.handleGetTOTPStatus)
		identity.DELETE("/mfa/totp", svc.handleDisableTOTP)
		identity.POST("/mfa/backup/generate", svc.handleGenerateBackupCodes)
		identity.POST("/mfa/backup/verify", svc.handleVerifyBackupCode)
		identity.GET("/mfa/backup/count", svc.handleGetBackupCodeCount)

		// WebAuthn (Passwordless) MFA
		identity.POST("/mfa/webauthn/register/begin", svc.handleBeginWebAuthnRegistration)
		identity.POST("/mfa/webauthn/register/finish", svc.handleFinishWebAuthnRegistration)
		identity.POST("/mfa/webauthn/authenticate/begin", svc.handleBeginWebAuthnAuthentication)
		identity.POST("/mfa/webauthn/authenticate/finish", svc.handleFinishWebAuthnAuthentication)
		identity.GET("/mfa/webauthn/credentials", svc.handleGetWebAuthnCredentials)
		identity.DELETE("/mfa/webauthn/credentials/:credential_id", svc.handleDeleteWebAuthnCredential)

		// Push MFA
		identity.POST("/mfa/push/register", svc.handleRegisterPushDevice)
		identity.GET("/mfa/push/devices", svc.handleGetPushDevices)
		identity.DELETE("/mfa/push/devices/:device_id", svc.handleDeletePushDevice)
		identity.POST("/mfa/push/challenge", svc.handleCreatePushChallenge)
		identity.POST("/mfa/push/verify", svc.handleVerifyPushChallenge)
		identity.GET("/mfa/push/challenge/:challenge_id", svc.handleGetPushChallenge)
	}
}

// HTTP Handlers

func (s *Service) handleListUsers(c *gin.Context) {
	offset := 0
	limit := 20
	
	users, total, err := s.ListUsers(c.Request.Context(), offset, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, users)
}

func (s *Service) handleGetUser(c *gin.Context) {
	userID := c.Param("id")
	
	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}
	
	c.JSON(200, user)
}

func (s *Service) handleCreateUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	if err := s.CreateUser(c.Request.Context(), &user); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(201, user)
}

func (s *Service) handleUpdateUser(c *gin.Context) {
	userID := c.Param("id")
	
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	user.ID = userID
	if err := s.UpdateUser(c.Request.Context(), &user); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(200, user)
}

func (s *Service) handleDeleteUser(c *gin.Context) {
	userID := c.Param("id")
	
	if err := s.DeleteUser(c.Request.Context(), userID); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(204, nil)
}

func (s *Service) handleGetUserSessions(c *gin.Context) {
	userID := c.Param("id")
	
	sessions, err := s.GetUserSessions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(200, sessions)
}

func (s *Service) handleTerminateSession(c *gin.Context) {
	sessionID := c.Param("id")

	if err := s.TerminateSession(c.Request.Context(), sessionID); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(204, nil)
}

func (s *Service) handleListGroups(c *gin.Context) {
	offset := 0
	limit := 50

	groups, total, err := s.ListGroups(c.Request.Context(), offset, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, groups)
}

func (s *Service) handleGetGroup(c *gin.Context) {
	groupID := c.Param("id")

	group, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(404, gin.H{"error": "group not found"})
		return
	}

	c.JSON(200, group)
}

func (s *Service) handleGetGroupMembers(c *gin.Context) {
	groupID := c.Param("id")

	members, err := s.GetGroupMembers(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, members)
}

func (s *Service) handleCreateGroup(c *gin.Context) {
	var group Group
	if err := c.ShouldBindJSON(&group); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.CreateGroup(c.Request.Context(), &group); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, group)
}

func (s *Service) handleUpdateGroup(c *gin.Context) {
	groupID := c.Param("id")

	var group Group
	if err := c.ShouldBindJSON(&group); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	group.ID = groupID
	if err := s.UpdateGroup(c.Request.Context(), &group); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, group)
}

func (s *Service) handleDeleteGroup(c *gin.Context) {
	groupID := c.Param("id")

	if err := s.DeleteGroup(c.Request.Context(), groupID); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(204, nil)
}

// MFA HTTP Handlers

func (s *Service) handleSetupTOTP(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	enrollment, err := s.GenerateTOTPSecret(c.Request.Context(), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, enrollment)
}

func (s *Service) handleEnrollTOTP(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		Secret string `json:"secret" binding:"required"`
		Code   string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	err := s.EnrollTOTP(c.Request.Context(), userID, req.Secret, req.Code)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "enrolled"})
}

func (s *Service) handleVerifyTOTP(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req TOTPVerification
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	valid, err := s.VerifyTOTP(c.Request.Context(), userID, req.Code)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"valid": valid})
}

func (s *Service) handleGetTOTPStatus(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	status, err := s.GetTOTPStatus(c.Request.Context(), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, status)
}

func (s *Service) handleDisableTOTP(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	err := s.DisableTOTP(c.Request.Context(), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "disabled"})
}

func (s *Service) handleGenerateBackupCodes(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		Count int `json:"count"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Count = 10 // Default
	}

	codes, err := s.GenerateBackupCodes(c.Request.Context(), userID, req.Count)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"backup_codes": codes})
}

func (s *Service) handleVerifyBackupCode(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	valid, err := s.ValidateBackupCode(c.Request.Context(), userID, req.Code)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"valid": valid})
}

func (s *Service) handleGetBackupCodeCount(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	count, err := s.GetRemainingBackupCodes(c.Request.Context(), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"remaining_codes": count})
}
