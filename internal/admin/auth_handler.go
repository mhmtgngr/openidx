// Package admin provides authentication handlers for the admin console
package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// AuthHandler handles authentication operations for the admin console
type AuthHandler struct {
	db     *pgxpool.Pool
	logger *zap.Logger
	jwtSecret string
	tokenExpiry time.Duration
}

// AdminUser represents an admin user
type AdminUser struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	PasswordHash string    `json:"-"`
	IsActive     bool      `json:"is_active"`
	IsSuperAdmin bool      `json:"is_super_admin"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// AuthSession represents an admin auth session
type AuthSession struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UserAgent string    `json:"user_agent,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Remember bool   `json:"remember,omitempty"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token     string     `json:"token"`
	ExpiresAt time.Time  `json:"expires_at"`
	User      AdminUser  `json:"user"`
	SessionID string     `json:"session_id"`
}

// MFAVerifyRequest represents an MFA verification request
type MFAVerifyRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

// Claims represents JWT claims
type Claims struct {
	UserID    string   `json:"sub"`
	Email     string   `json:"email"`
	Name      string   `json:"name"`
	Roles     []string `json:"roles"`
	IsAdmin   bool     `json:"is_admin"`
	jwt.RegisteredClaims
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(db *pgxpool.Pool, logger *zap.Logger, jwtSecret string) *AuthHandler {
	return &AuthHandler{
		db:         db,
		logger:     logger,
		jwtSecret:  jwtSecret,
		tokenExpiry: 24 * time.Hour,
	}
}

// SetTokenExpiry sets the token expiration time
func (h *AuthHandler) SetTokenExpiry(expiry time.Duration) {
	h.tokenExpiry = expiry
}

// Authenticate authenticates an admin user
func (h *AuthHandler) Authenticate(ctx context.Context, email, password string) (*AdminUser, error) {
	// Fetch user by email
	user, err := h.getAdminUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("invalid credentials")
		}
		h.logger.Error("Failed to fetch admin user", zap.Error(err))
		return nil, fmt.Errorf("authentication failed")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("account is disabled")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
}

// GenerateToken generates a JWT token for a user
func (h *AuthHandler) GenerateToken(user *AdminUser) (string, time.Time, error) {
	expiresAt := time.Now().Add(h.tokenExpiry)

	claims := Claims{
		UserID:    user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Roles:     []string{"admin"},
		IsAdmin:   true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "openidx-gateway",
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(h.jwtSecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// CreateSession creates a new admin session
func (h *AuthHandler) CreateSession(ctx context.Context, userID, token, userAgent, ipAddress string) (*AuthSession, error) {
	sessionID := generateSessionID()
	expiresAt := time.Now().Add(h.tokenExpiry)

	session := &AuthSession{
		ID:        sessionID,
		UserID:    userID,
		Token:     token,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	}

	// Store session in database
	query := `
		INSERT INTO admin_sessions (id, user_id, token, created_at, expires_at, user_agent, ip_address)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := h.db.Exec(ctx, query,
		session.ID, session.UserID, session.Token,
		session.CreatedAt, session.ExpiresAt,
		session.UserAgent, session.IPAddress,
	)
	if err != nil {
		h.logger.Error("Failed to create admin session",
			zap.String("user_id", userID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create session")
	}

	// Update last login time
	_, err = h.db.Exec(ctx,
		"UPDATE admin_users SET last_login_at = $1 WHERE id = $2",
		time.Now(), userID)
	if err != nil {
		h.logger.Warn("Failed to update last login time",
			zap.String("user_id", userID),
			zap.Error(err))
	}

	return session, nil
}

// ValidateSession validates a session token
func (h *AuthHandler) ValidateSession(ctx context.Context, token string) (*AuthSession, *AdminUser, error) {
	// Query session with user
	query := `
		SELECT s.id, s.user_id, s.token, s.created_at, s.expires_at, s.user_agent, s.ip_address,
		       u.id, u.email, u.name, u.is_active, u.is_super_admin, u.created_at, u.updated_at
		FROM admin_sessions s
		JOIN admin_users u ON u.id = s.user_id
		WHERE s.token = $1 AND s.expires_at > NOW()
		LIMIT 1
	`

	row := h.db.QueryRow(ctx, query, token)

	var session AuthSession
	var user AdminUser

	err := row.Scan(
		&session.ID, &session.UserID, &session.Token, &session.CreatedAt, &session.ExpiresAt,
		&session.UserAgent, &session.IPAddress,
		&user.ID, &user.Email, &user.Name, &user.IsActive, &user.IsSuperAdmin,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("invalid or expired session")
		}
		return nil, nil, fmt.Errorf("failed to validate session: %w", err)
	}

	if !user.IsActive {
		return nil, nil, fmt.Errorf("user account is disabled")
	}

	return &session, &user, nil
}

// InvalidateSession invalidates a session
func (h *AuthHandler) InvalidateSession(ctx context.Context, sessionID string) error {
	_, err := h.db.Exec(ctx, "DELETE FROM admin_sessions WHERE id = $1", sessionID)
	if err != nil {
		return fmt.Errorf("failed to invalidate session: %w", err)
	}
	return nil
}

// InvalidateAllUserSessions invalidates all sessions for a user
func (h *AuthHandler) InvalidateAllUserSessions(ctx context.Context, userID string) error {
	_, err := h.db.Exec(ctx, "DELETE FROM admin_sessions WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate user sessions: %w", err)
	}
	return nil
}

// HashPassword hashes a password using bcrypt
func (h *AuthHandler) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// getAdminUserByEmail fetches an admin user by email
func (h *AuthHandler) getAdminUserByEmail(ctx context.Context, email string) (*AdminUser, error) {
	query := `
		SELECT id, email, name, password_hash, is_active, is_super_admin,
		       created_at, updated_at, last_login_at
		FROM admin_users
		WHERE email = $1
		LIMIT 1
	`

	var user AdminUser
	err := h.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Name, &user.PasswordHash,
		&user.IsActive, &user.IsSuperAdmin,
		&user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetAdminUserByID fetches an admin user by ID
func (h *AuthHandler) GetAdminUserByID(ctx context.Context, userID string) (*AdminUser, error) {
	query := `
		SELECT id, email, name, is_active, is_super_admin,
		       created_at, updated_at, last_login_at
		FROM admin_users
		WHERE id = $1
		LIMIT 1
	`

	var user AdminUser
	err := h.db.QueryRow(ctx, query, userID).Scan(
		&user.ID, &user.Email, &user.Name,
		&user.IsActive, &user.IsSuperAdmin,
		&user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// generateSessionID generates a unique session ID
func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// ValidateToken validates a JWT token and returns the claims
func (h *AuthHandler) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// RefreshToken refreshes a session token
func (h *AuthHandler) RefreshToken(ctx context.Context, oldToken string) (string, time.Time, error) {
	// Validate old token
	claims, err := h.ValidateToken(oldToken)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid token: %w", err)
	}

	// Get user
	user, err := h.GetAdminUserByID(ctx, claims.UserID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("user not found: %w", err)
	}

	// Generate new token
	token, expiresAt, err := h.GenerateToken(user)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate new token: %w", err)
	}

	// Invalidate old session
	session, _, err := h.ValidateSession(ctx, oldToken)
	if err == nil {
		h.InvalidateSession(ctx, session.ID)
	}

	return token, expiresAt, nil
}

// CleanupExpiredSessions removes expired sessions from the database
func (h *AuthHandler) CleanupExpiredSessions(ctx context.Context) error {
	_, err := h.db.Exec(ctx, "DELETE FROM admin_sessions WHERE expires_at < NOW()")
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	h.logger.Info("Cleaned up expired admin sessions")
	return nil
}
