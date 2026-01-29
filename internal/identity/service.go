// Package identity provides identity management functionality
package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"github.com/pquerna/otp/totp"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// Use the min function from pushmfa.go

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

// Role represents a role in the system
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsComposite bool      `json:"is_composite"`
	CreatedAt   time.Time `json:"created_at"`
}

// Service provides identity management operations
type Service struct {
	db                *database.PostgresDB
	redis             *database.RedisClient
	cfg               *config.Config
	logger            *zap.Logger
	webauthnSessions  sync.Map // In-memory storage for WebAuthn sessions (use Redis in production)
	pushMFASessions   sync.Map // In-memory storage for Push MFA challenges (use Redis in production)

	// JWKS public key cache
	jwksCacheMu    sync.RWMutex
	jwksCachedKey  *rsa.PublicKey
	jwksCacheExpiry time.Time
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

// openIDXAuthMiddleware validates OpenIDX OAuth JWT tokens
func (s *Service) openIDXAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header format",
			})
			return
		}

		tokenString := parts[1]

		// Parse JWT token with signature validation
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				s.logger.Warn("Unexpected signing method", zap.String("method", token.Header["alg"].(string)))
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Fetch the public key from OAuth service (cached with 5-min TTL)
			key, err := s.getOAuthPublicKey()
			if err != nil {
				s.logger.Error("Failed to get OAuth public key", zap.Error(err))
				return nil, err
			}
			return key, nil
		})

		if err != nil {
			s.logger.Warn("JWT parsing failed", zap.Error(err), zap.String("token_prefix", tokenString[:min(50, len(tokenString))]))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}

		// Validate token
		if token == nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token claims",
			})
			return
		}

		// Validate expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "token expired",
				})
				return
			}
		}

		// Validate issuer
		if iss, ok := claims["iss"].(string); ok {
			expectedIssuer := s.cfg.OAuthIssuer
			if expectedIssuer == "" {
				expectedIssuer = "http://localhost:8006"
			}
			if iss != expectedIssuer {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid token issuer",
				})
				return
			}
		}

		// Set user context from token claims
		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
		}
		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}
		if name, ok := claims["name"].(string); ok {
			c.Set("name", name)
		}

		// Extract roles
		if rolesRaw, ok := claims["roles"].([]interface{}); ok {
			var roles []string
			for _, r := range rolesRaw {
				if role, ok := r.(string); ok {
					roles = append(roles, role)
				}
			}
			c.Set("roles", roles)
		}

		c.Next()
	}
}

// getOAuthPublicKey returns the OAuth service's RSA public key, using a cache with 5-minute TTL
func (s *Service) getOAuthPublicKey() (*rsa.PublicKey, error) {
	// Check cache first (read lock)
	s.jwksCacheMu.RLock()
	if s.jwksCachedKey != nil && time.Now().Before(s.jwksCacheExpiry) {
		key := s.jwksCachedKey
		s.jwksCacheMu.RUnlock()
		return key, nil
	}
	s.jwksCacheMu.RUnlock()

	// Cache miss or expired - fetch and update (write lock)
	s.jwksCacheMu.Lock()
	defer s.jwksCacheMu.Unlock()

	// Double-check after acquiring write lock
	if s.jwksCachedKey != nil && time.Now().Before(s.jwksCacheExpiry) {
		return s.jwksCachedKey, nil
	}

	jwksURL := s.cfg.OAuthJWKSURL
	if jwksURL == "" {
		jwksURL = "http://localhost:8006/.well-known/jwks.json"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Find the first RSA signing key
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.Use == "sig" {
			pubKey, err := parseRSAPublicKey(key.N, key.E)
			if err != nil {
				return nil, err
			}
			s.jwksCachedKey = pubKey
			s.jwksCacheExpiry = time.Now().Add(5 * time.Minute)
			s.logger.Info("JWKS public key cached", zap.String("jwks_url", jwksURL))
			return pubKey, nil
		}
	}

	return nil, fmt.Errorf("no valid RSA signing key found")
}

// parseRSAPublicKey parses RSA public key from base64url encoded n and e
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// Remove padding for base64url encoding
	nClean := strings.TrimRight(nStr, "=")
	eClean := strings.TrimRight(eStr, "=")

	// Decode n (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(nClean)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode e (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(eClean)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
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

// CreateIdentityProvider creates a new identity provider
func (s *Service) CreateIdentityProvider(ctx context.Context, idp *IdentityProvider) error {
	s.logger.Info("Creating identity provider", zap.String("name", idp.Name))

	idp.ID = uuid.New()
	now := time.Now()
	idp.CreatedAt = now
	idp.UpdatedAt = now

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO identity_providers (id, name, provider_type, issuer_url, client_id, client_secret, scopes, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, idp.ID, idp.Name, idp.ProviderType, idp.IssuerURL, idp.ClientID, idp.ClientSecret, idp.Scopes, idp.Enabled, idp.CreatedAt, idp.UpdatedAt)

	return err
}

// GetIdentityProvider retrieves an identity provider by ID
func (s *Service) GetIdentityProvider(ctx context.Context, idpID string) (*IdentityProvider, error) {
	s.logger.Debug("Getting identity provider", zap.String("idp_id", idpID))

	var idp IdentityProvider
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, provider_type, issuer_url, client_id, client_secret, scopes, enabled, created_at, updated_at
		FROM identity_providers WHERE id = $1
	`, idpID).Scan(
		&idp.ID, &idp.Name, &idp.ProviderType, &idp.IssuerURL, &idp.ClientID, &idp.ClientSecret, &idp.Scopes, &idp.Enabled, &idp.CreatedAt, &idp.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &idp, nil
}

// ListIdentityProviders retrieves identity providers with pagination
func (s *Service) ListIdentityProviders(ctx context.Context, offset, limit int) ([]IdentityProvider, int, error) {
	s.logger.Debug("Listing identity providers", zap.Int("offset", offset), zap.Int("limit", limit))

	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM identity_providers").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, provider_type, issuer_url, client_id, client_secret, scopes, enabled, created_at, updated_at
		FROM identity_providers
		ORDER BY name
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	idps := make([]IdentityProvider, 0)
	for rows.Next() {
		var idp IdentityProvider
		if err := rows.Scan(
			&idp.ID, &idp.Name, &idp.ProviderType, &idp.IssuerURL, &idp.ClientID, &idp.ClientSecret, &idp.Scopes, &idp.Enabled, &idp.CreatedAt, &idp.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		idps = append(idps, idp)
	}

	return idps, total, nil
}

// UpdateIdentityProvider updates an existing identity provider
func (s *Service) UpdateIdentityProvider(ctx context.Context, idp *IdentityProvider) error {
	s.logger.Info("Updating identity provider", zap.String("idp_id", idp.ID.String()))
	
	idp.UpdatedAt = time.Now()
	
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE identity_providers 
		SET name = $2, provider_type = $3, issuer_url = $4, client_id = $5, client_secret = $6, scopes = $7, enabled = $8, updated_at = $9
		WHERE id = $1
	`, idp.ID, idp.Name, idp.ProviderType, idp.IssuerURL, idp.ClientID, idp.ClientSecret, idp.Scopes, idp.Enabled, idp.UpdatedAt)
	
	return err
}

// DeleteIdentityProvider deletes an identity provider
func (s *Service) DeleteIdentityProvider(ctx context.Context, idpID string) error {
	s.logger.Info("Deleting identity provider", zap.String("idp_id", idpID))
	
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM identity_providers WHERE id = $1", idpID)
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

// AddGroupMember adds a user to a group
func (s *Service) AddGroupMember(ctx context.Context, groupID, userID string) error {
	s.logger.Info("Adding member to group", zap.String("group_id", groupID), zap.String("user_id", userID))

	// Check if group exists
	group, err := s.GetGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("group not found: %w", err)
	}

	// Check max members limit if set
	if group.MaxMembers != nil && group.MemberCount >= *group.MaxMembers {
		return fmt.Errorf("group has reached maximum member limit of %d", *group.MaxMembers)
	}

	// Check if user exists
	_, err = s.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Check if membership already exists
	var exists bool
	err = s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM group_memberships WHERE group_id = $1 AND user_id = $2)
	`, groupID, userID).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("user is already a member of this group")
	}

	// Insert membership
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO group_memberships (group_id, user_id, joined_at)
		VALUES ($1, $2, NOW())
	`, groupID, userID)

	return err
}

// RemoveGroupMember removes a user from a group
func (s *Service) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	s.logger.Info("Removing member from group", zap.String("group_id", groupID), zap.String("user_id", userID))

	result, err := s.db.Pool.Exec(ctx, `
		DELETE FROM group_memberships WHERE group_id = $1 AND user_id = $2
	`, groupID, userID)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user is not a member of this group")
	}

	return nil
}

// SearchUsers searches for users by username or email
func (s *Service) SearchUsers(ctx context.Context, query string, limit int) ([]User, error) {
	s.logger.Debug("Searching users", zap.String("query", query))

	if limit <= 0 || limit > 50 {
		limit = 20
	}

	searchPattern := "%" + query + "%"
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, username, email, first_name, last_name, enabled, email_verified,
		       created_at, updated_at, last_login_at, password_changed_at,
		       password_must_change, failed_login_count, last_failed_login_at, locked_until
		FROM users
		WHERE username ILIKE $1 OR email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1
		ORDER BY username
		LIMIT $2
	`, searchPattern, limit)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		users = append(users, u)
	}

	return users, nil
}

// GetGroupMembersPaginated retrieves members of a group with pagination and search
func (s *Service) GetGroupMembersPaginated(ctx context.Context, groupID string, search string, offset, limit int) ([]GroupMember, int, error) {
	s.logger.Debug("Getting group members paginated", zap.String("group_id", groupID))

	// Get total count
	var total int
	countQuery := `
		SELECT COUNT(*) FROM users u
		JOIN group_memberships gm ON u.id = gm.user_id
		WHERE gm.group_id = $1
	`
	countArgs := []interface{}{groupID}

	if search != "" {
		countQuery += ` AND (u.username ILIKE $2 OR u.email ILIKE $2 OR u.first_name ILIKE $2 OR u.last_name ILIKE $2)`
		countArgs = append(countArgs, "%"+search+"%")
	}

	err := s.db.Pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get members
	query := `
		SELECT u.id, u.username, u.email, u.first_name, u.last_name, gm.joined_at
		FROM users u
		JOIN group_memberships gm ON u.id = gm.user_id
		WHERE gm.group_id = $1
	`
	args := []interface{}{groupID}

	if search != "" {
		query += ` AND (u.username ILIKE $2 OR u.email ILIKE $2 OR u.first_name ILIKE $2 OR u.last_name ILIKE $2)`
		args = append(args, "%"+search+"%")
		query += ` ORDER BY gm.joined_at DESC OFFSET $3 LIMIT $4`
		args = append(args, offset, limit)
	} else {
		query += ` ORDER BY gm.joined_at DESC OFFSET $2 LIMIT $3`
		args = append(args, offset, limit)
	}

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var members []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.UserID, &m.Username, &m.Email, &m.FirstName, &m.LastName, &m.JoinedAt); err != nil {
			return nil, 0, err
		}
		members = append(members, m)
	}

	return members, total, nil
}

// GetSubgroups retrieves subgroups of a parent group
func (s *Service) GetSubgroups(ctx context.Context, parentID string) ([]Group, error) {
	s.logger.Debug("Getting subgroups", zap.String("parent_id", parentID))

	rows, err := s.db.Pool.Query(ctx, `
		SELECT g.id, g.name, g.description, g.parent_id, g.allow_self_join, g.require_approval, g.max_members, g.created_at, g.updated_at,
		       COALESCE((SELECT COUNT(*) FROM group_memberships gm WHERE gm.group_id = g.id), 0) as member_count
		FROM groups g
		WHERE g.parent_id = $1
		ORDER BY g.name
	`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(
			&g.ID, &g.Name, &g.Description, &g.ParentID, &g.AllowSelfJoin, &g.RequireApproval, &g.MaxMembers, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount,
		); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	return groups, nil
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

// ErrInvalidCredentials is returned when username or password is incorrect
var ErrInvalidCredentials = errors.New("invalid username or password")

// ErrAccountLocked is returned when the user account is locked
var ErrAccountLocked = errors.New("account is locked")

// ErrAccountDisabled is returned when the user account is disabled
var ErrAccountDisabled = errors.New("account is disabled")

// AuthenticateUser verifies username and password credentials
func (s *Service) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	s.logger.Info("Authenticating user", zap.String("username", username))

	var userID, passwordHash string
	var enabled bool
	var lockedUntil *time.Time
	var failedLoginCount int

	// Get user by username or email
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, password_hash, enabled, locked_until, failed_login_count
		FROM users
		WHERE username = $1 OR email = $1
	`, username).Scan(&userID, &passwordHash, &enabled, &lockedUntil, &failedLoginCount)

	if err != nil {
		s.logger.Debug("User not found", zap.String("username", username))
		return nil, ErrInvalidCredentials
	}

	// Check if account is disabled
	if !enabled {
		s.logger.Warn("Login attempt on disabled account", zap.String("username", username))
		return nil, ErrAccountDisabled
	}

	// Check if account is locked
	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		s.logger.Warn("Login attempt on locked account", zap.String("username", username))
		return nil, ErrAccountLocked
	}

	// Verify password
	if passwordHash == "" {
		s.logger.Debug("User has no password set", zap.String("username", username))
		return nil, ErrInvalidCredentials
	}

	hashPrefix := passwordHash
	if len(hashPrefix) > 20 {
		hashPrefix = hashPrefix[:20]
	}
	s.logger.Debug("Comparing password",
		zap.String("username", username),
		zap.Int("hash_len", len(passwordHash)),
		zap.String("hash_prefix", hashPrefix),
		zap.Int("password_len", len(password)),
		zap.String("password_bytes", fmt.Sprintf("%v", []byte(password))))

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		// Update failed login count
		s.recordFailedLogin(ctx, userID, failedLoginCount)
		s.logger.Debug("Invalid password", zap.String("username", username), zap.Error(err))
		return nil, ErrInvalidCredentials
	}

	// Reset failed login count and update last login
	now := time.Now()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE users
		SET failed_login_count = 0, last_login_at = $2, locked_until = NULL
		WHERE id = $1
	`, userID, now)
	if err != nil {
		s.logger.Error("Failed to update login stats", zap.Error(err))
	}

	// Return full user object
	return s.GetUser(ctx, userID)
}

// recordFailedLogin records a failed login attempt and locks account if necessary
func (s *Service) recordFailedLogin(ctx context.Context, userID string, currentCount int) {
	newCount := currentCount + 1
	now := time.Now()

	var lockedUntil *time.Time
	// Lock account after 5 failed attempts for 30 minutes
	if newCount >= 5 {
		lockTime := now.Add(30 * time.Minute)
		lockedUntil = &lockTime
		s.logger.Warn("Account locked due to failed attempts", zap.String("user_id", userID))
	}

	_, err := s.db.Pool.Exec(ctx, `
		UPDATE users
		SET failed_login_count = $2, last_failed_login_at = $3, locked_until = $4
		WHERE id = $1
	`, userID, newCount, now, lockedUntil)
	if err != nil {
		s.logger.Error("Failed to record failed login", zap.Error(err))
	}
}

// SetPassword sets a new password for a user (hashes and stores)
func (s *Service) SetPassword(ctx context.Context, userID string, password string) error {
	s.logger.Info("Setting password", zap.String("user_id", userID))

	// Validate password policy
	if err := s.ValidatePasswordPolicy(password); err != nil {
		return err
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE users
		SET password_hash = $2, password_changed_at = $3, password_must_change = false
		WHERE id = $1
	`, userID, string(hash), now)

	return err
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
	s.logger.Info("Generated TOTP QR code URL", zap.String("qr_url", qrURL), zap.String("secret", key.Secret()))

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

	// Remove any existing TOTP records for this user before inserting
	_, _ = s.db.Pool.Exec(ctx, `DELETE FROM mfa_totp WHERE user_id = $1`, userID)

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

// ListRoles retrieves all available roles
func (s *Service) ListRoles(ctx context.Context) ([]Role, error) {
	s.logger.Debug("Listing roles")

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, is_composite, created_at
		FROM roles
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var r Role
		err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.IsComposite, &r.CreatedAt)
		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}

	return roles, nil
}

// GetRole retrieves a role by ID
func (s *Service) GetRole(ctx context.Context, roleID string) (*Role, error) {
	s.logger.Debug("Getting role", zap.String("role_id", roleID))

	var role Role
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, is_composite, created_at
		FROM roles WHERE id = $1
	`, roleID).Scan(&role.ID, &role.Name, &role.Description, &role.IsComposite, &role.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

// CreateRole creates a new role
func (s *Service) CreateRole(ctx context.Context, role *Role) error {
	s.logger.Info("Creating role", zap.String("name", role.Name))

	if role.ID == "" {
		role.ID = uuid.New().String()
	}

	now := time.Now()
	role.CreatedAt = now

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO roles (id, name, description, is_composite, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5)
	`, role.ID, role.Name, role.Description, role.IsComposite, now)

	return err
}

// UpdateRole updates an existing role
func (s *Service) UpdateRole(ctx context.Context, role *Role) error {
	s.logger.Info("Updating role", zap.String("role_id", role.ID))

	result, err := s.db.Pool.Exec(ctx, `
		UPDATE roles
		SET name = $2, description = $3, is_composite = $4, updated_at = $5
		WHERE id = $1
	`, role.ID, role.Name, role.Description, role.IsComposite, time.Now())

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("role not found")
	}

	return nil
}

// DeleteRole deletes a role
func (s *Service) DeleteRole(ctx context.Context, roleID string) error {
	s.logger.Info("Deleting role", zap.String("role_id", roleID))

	// First remove all user-role assignments
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM user_roles WHERE role_id = $1", roleID)
	if err != nil {
		return fmt.Errorf("failed to remove role assignments: %w", err)
	}

	// Remove composite role relationships
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM composite_roles WHERE parent_role_id = $1 OR child_role_id = $1", roleID)
	if err != nil {
		return fmt.Errorf("failed to remove composite role relationships: %w", err)
	}

	// Delete the role
	result, err := s.db.Pool.Exec(ctx, "DELETE FROM roles WHERE id = $1", roleID)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("role not found")
	}

	return nil
}

// GetUserRoles retrieves roles assigned to a user
func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]Role, error) {
	s.logger.Debug("Getting user roles", zap.String("user_id", userID))

	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.id, r.name, r.description, r.is_composite, r.created_at
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY r.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var r Role
		err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.IsComposite, &r.CreatedAt)
		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}

	return roles, nil
}

// AssignUserRole assigns a role to a user
func (s *Service) AssignUserRole(ctx context.Context, userID, roleID string, assignedBy string) error {
	s.logger.Info("Assigning role to user",
		zap.String("user_id", userID), zap.String("role_id", roleID), zap.String("assigned_by", assignedBy))

	// Check if role assignment already exists
	var exists bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2)
	`, userID, roleID).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("user already has this role")
	}

	// Insert role assignment
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id, assigned_by, assigned_at)
		VALUES ($1, $2, $3, NOW())
	`, userID, roleID, assignedBy)

	return err
}

// RemoveUserRole removes a role from a user
func (s *Service) RemoveUserRole(ctx context.Context, userID, roleID string) error {
	s.logger.Info("Removing role from user", zap.String("user_id", userID), zap.String("role_id", roleID))

	result, err := s.db.Pool.Exec(ctx, `
		DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2
	`, userID, roleID)

	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user does not have this role")
	}

	return nil
}

// UpdateUserRoles replaces all roles for a user
func (s *Service) UpdateUserRoles(ctx context.Context, userID string, roleIDs []string, assignedBy string) error {
	s.logger.Info("Updating user roles", zap.String("user_id", userID), zap.Int("role_count", len(roleIDs)))

	// Start transaction
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Remove all existing roles
	_, err = tx.Exec(ctx, "DELETE FROM user_roles WHERE user_id = $1", userID)
	if err != nil {
		return err
	}

	// Insert new roles
	for _, roleID := range roleIDs {
		_, err = tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, assigned_at)
			VALUES ($1, $2, NOW())
		`, userID, roleID)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// RegisterRoutes registers identity service routes
func RegisterRoutes(router *gin.Engine, svc *Service) {
	// Public routes (no auth required)
	public := router.Group("/api/v1/identity")
	{
		public.POST("/users/forgot-password", svc.handleForgotPassword)
		public.POST("/users/reset-password", svc.handleResetPassword)
	}

	identity := router.Group("/api/v1/identity")
	identity.Use(svc.openIDXAuthMiddleware())
	{
		// User Self-Service endpoints (require authentication)
		identity.GET("/users/me", svc.handleGetCurrentUser)
		identity.PUT("/users/me", svc.handleUpdateCurrentUser)
		identity.POST("/users/me/change-password", svc.handleChangePassword)
		identity.POST("/users/me/mfa/setup", svc.handleSetupUserMFA)
		identity.POST("/users/me/mfa/enable", svc.handleEnableUserMFA)
		identity.POST("/users/me/mfa/disable", svc.handleDisableUserMFA)

		// User management
		identity.GET("/users", svc.handleListUsers)
		identity.POST("/users", svc.handleCreateUser)
		identity.GET("/users/search", svc.handleSearchUsers) // Must be before :id route
		identity.GET("/users/export", svc.handleExportUsersCSV)
		identity.POST("/users/import", svc.handleImportUsersCSV)
		identity.GET("/users/:id", svc.handleGetUser)
		identity.PUT("/users/:id", svc.handleUpdateUser)
		identity.DELETE("/users/:id", svc.handleDeleteUser)

		// Identity Providers (for SSO)
		identity.GET("/providers", svc.handleListIdentityProviders)
		identity.POST("/providers", svc.handleCreateIdentityProvider)
		identity.GET("/providers/:id", svc.handleGetIdentityProvider)
		identity.PUT("/providers/:id", svc.handleUpdateIdentityProvider)
		identity.DELETE("/providers/:id", svc.handleDeleteIdentityProvider)

		// Session management
		identity.GET("/users/:id/sessions", svc.handleGetUserSessions)
		identity.DELETE("/sessions/:id", svc.handleTerminateSession)

		// Role management (CRUD)
		identity.GET("/roles", svc.handleListRoles)
		identity.POST("/roles", svc.handleCreateRole)
		identity.GET("/roles/:id", svc.handleGetRole)
		identity.PUT("/roles/:id", svc.handleUpdateRole)
		identity.DELETE("/roles/:id", svc.handleDeleteRole)

		// Permissions
		identity.GET("/permissions", svc.handleListPermissions)
		identity.GET("/roles/:id/permissions", svc.handleGetRolePermissions)
		identity.PUT("/roles/:id/permissions", svc.handleSetRolePermissions)

		// User-Role assignments
		identity.GET("/users/:id/roles", svc.handleGetUserRoles)
		identity.POST("/users/:id/roles", svc.handleAssignUserRole)
		identity.DELETE("/users/:id/roles/:roleId", svc.handleRemoveUserRole)
		identity.PUT("/users/:id/roles", svc.handleUpdateUserRoles)

		// Group management
		identity.GET("/groups", svc.handleListGroups)
		identity.POST("/groups", svc.handleCreateGroup)
		identity.GET("/groups/:id", svc.handleGetGroup)
		identity.PUT("/groups/:id", svc.handleUpdateGroup)
		identity.DELETE("/groups/:id", svc.handleDeleteGroup)
		identity.GET("/groups/:id/members", svc.handleGetGroupMembers)
		identity.POST("/groups/:id/members", svc.handleAddGroupMember)
		identity.DELETE("/groups/:id/members/:userId", svc.handleRemoveGroupMember)
		identity.GET("/groups/:id/subgroups", svc.handleGetSubgroups)

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

func (s *Service) handleListIdentityProviders(c *gin.Context) {
	offset := 0
	limit := 20
	
	idps, total, err := s.ListIdentityProviders(c.Request.Context(), offset, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, idps)
}

func (s *Service) handleGetIdentityProvider(c *gin.Context) {
	idpID := c.Param("id")
	
	idp, err := s.GetIdentityProvider(c.Request.Context(), idpID)
	if err != nil {
		c.JSON(404, gin.H{"error": "identity provider not found"})
		return
	}
	
	c.JSON(200, idp)
}

func (s *Service) handleCreateIdentityProvider(c *gin.Context) {
	var idp IdentityProvider
	if err := c.ShouldBindJSON(&idp); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	if err := s.CreateIdentityProvider(c.Request.Context(), &idp); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(201, idp)
}

func (s *Service) handleUpdateIdentityProvider(c *gin.Context) {
	idpID := c.Param("id")
	
	var idp IdentityProvider
	if err := c.ShouldBindJSON(&idp); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	idp.ID, _ = uuid.Parse(idpID)
	if err := s.UpdateIdentityProvider(c.Request.Context(), &idp); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(200, idp)
}

func (s *Service) handleDeleteIdentityProvider(c *gin.Context) {
	idpID := c.Param("id")
	
	if err := s.DeleteIdentityProvider(c.Request.Context(), idpID); err != nil {
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

func (s *Service) handleListRoles(c *gin.Context) {
	roles, err := s.ListRoles(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, roles)
}

func (s *Service) handleGetRole(c *gin.Context) {
	roleID := c.Param("id")

	role, err := s.GetRole(c.Request.Context(), roleID)
	if err != nil {
		c.JSON(404, gin.H{"error": "role not found"})
		return
	}

	c.JSON(200, role)
}

func (s *Service) handleCreateRole(c *gin.Context) {
	var role Role
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.CreateRole(c.Request.Context(), &role); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, role)
}

func (s *Service) handleUpdateRole(c *gin.Context) {
	roleID := c.Param("id")

	var role Role
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	role.ID = roleID
	if err := s.UpdateRole(c.Request.Context(), &role); err != nil {
		if err.Error() == "role not found" {
			c.JSON(404, gin.H{"error": err.Error()})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, role)
}

func (s *Service) handleDeleteRole(c *gin.Context) {
	roleID := c.Param("id")

	if err := s.DeleteRole(c.Request.Context(), roleID); err != nil {
		if err.Error() == "role not found" {
			c.JSON(404, gin.H{"error": err.Error()})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(204, nil)
}

func (s *Service) handleGetUserRoles(c *gin.Context) {
	userID := c.Param("id")

	roles, err := s.GetUserRoles(c.Request.Context(), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, roles)
}

func (s *Service) handleAssignUserRole(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		RoleID string `json:"role_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Get current user ID from context (admin performing the action)
	assignedBy := c.GetString("user_id")
	if assignedBy == "" {
		assignedBy = "" // Allow NULL for unauthenticated requests
	}

	err := s.AssignUserRole(c.Request.Context(), userID, req.RoleID, assignedBy)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "assigned"})
}

func (s *Service) handleRemoveUserRole(c *gin.Context) {
	userID := c.Param("id")
	roleID := c.Param("roleId")

	err := s.RemoveUserRole(c.Request.Context(), userID, roleID)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "removed"})
}

func (s *Service) handleUpdateUserRoles(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		RoleIDs []string `json:"role_ids"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Get current user ID from context (admin performing the action)
	assignedBy := c.GetString("user_id")
	if assignedBy == "" {
		assignedBy = "00000000-0000-0000-0000-000000000001" // Default admin user
	}

	err := s.UpdateUserRoles(c.Request.Context(), userID, req.RoleIDs, assignedBy)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "updated"})
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

func (s *Service) handleAddGroupMember(c *gin.Context) {
	groupID := c.Param("id")

	var req struct {
		UserID string `json:"user_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.AddGroupMember(c.Request.Context(), groupID, req.UserID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(404, gin.H{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "already a member") || strings.Contains(err.Error(), "maximum member limit") {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "member added"})
}

func (s *Service) handleRemoveGroupMember(c *gin.Context) {
	groupID := c.Param("id")
	userID := c.Param("userId")

	if err := s.RemoveGroupMember(c.Request.Context(), groupID, userID); err != nil {
		if strings.Contains(err.Error(), "not a member") {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "member removed"})
}

func (s *Service) handleGetSubgroups(c *gin.Context) {
	parentID := c.Param("id")

	subgroups, err := s.GetSubgroups(c.Request.Context(), parentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, subgroups)
}

func (s *Service) handleSearchUsers(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(400, gin.H{"error": "search query is required"})
		return
	}

	limitStr := c.DefaultQuery("limit", "20")
	limit, _ := strconv.Atoi(limitStr)

	users, err := s.SearchUsers(c.Request.Context(), query, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, users)
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

// User Self-Service Handlers

func (s *Service) handleGetCurrentUser(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	// Get MFA status
	totpStatus, err := s.GetTOTPStatus(c.Request.Context(), userID)
	if err != nil {
		s.logger.Warn("Failed to get MFA status", zap.Error(err))
	}

	// Build MFA methods list
	mfaMethods := []string{}
	if totpStatus.Enabled {
		mfaMethods = append(mfaMethods, "totp")
	}

	// Return user profile with camelCase fields matching frontend expectations
	c.JSON(200, gin.H{
		"id":            user.ID,
		"username":      user.Username,
		"email":         user.Email,
		"firstName":     user.FirstName,
		"lastName":      user.LastName,
		"enabled":       user.Enabled,
		"emailVerified": user.EmailVerified,
		"createdAt":     user.CreatedAt,
		"mfaEnabled":    totpStatus.Enabled,
		"mfaMethods":    mfaMethods,
	})
}

func (s *Service) handleUpdateCurrentUser(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Email     string `json:"email"`
		Enabled   bool   `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Get current user
	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	// Update allowed fields
	user.FirstName = req.FirstName
	user.LastName = req.LastName
	user.Email = req.Email
	user.Enabled = req.Enabled

	if err := s.UpdateUser(c.Request.Context(), user); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"id":            user.ID,
		"username":      user.Username,
		"email":         user.Email,
		"firstName":     user.FirstName,
		"lastName":      user.LastName,
		"enabled":       user.Enabled,
		"emailVerified": user.EmailVerified,
		"createdAt":     user.CreatedAt,
	})
}

func (s *Service) handleChangePassword(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		CurrentPassword string `json:"currentPassword" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Get user's current password hash
	var passwordHash string
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT password_hash FROM users WHERE id = $1
	`, userID).Scan(&passwordHash)

	if err != nil {
		s.logger.Error("Failed to get user password hash", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to verify password"})
		return
	}

	// Verify current password using bcrypt directly
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.CurrentPassword)); err != nil {
		c.JSON(400, gin.H{"error": "current password is incorrect"})
		return
	}

	// Set new password
	if err := s.SetPassword(c.Request.Context(), userID, req.NewPassword); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "password changed"})
}

func (s *Service) handleSetupUserMFA(c *gin.Context) {
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

	// Cache the secret in Redis so handleEnableUserMFA can retrieve it
	cacheKey := fmt.Sprintf("mfa_setup:%s", userID)
	if s.redis != nil {
		s.redis.Client.Set(c.Request.Context(), cacheKey, enrollment.Secret, 10*time.Minute)
	}

	c.JSON(200, gin.H{
		"secret":    enrollment.Secret,
		"qrCodeUrl": enrollment.QRCodeURL,
	})
}

func (s *Service) handleEnableUserMFA(c *gin.Context) {
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

	// Retrieve the cached secret from the setup step
	cacheKey := fmt.Sprintf("mfa_setup:%s", userID)
	var secret string
	if s.redis != nil {
		var err error
		secret, err = s.redis.Client.Get(c.Request.Context(), cacheKey).Result()
		if err != nil || secret == "" {
			c.JSON(400, gin.H{"error": "MFA setup expired or not initiated. Please start setup again."})
			return
		}
	} else {
		c.JSON(500, gin.H{"error": "cache unavailable"})
		return
	}

	err := s.EnrollTOTP(c.Request.Context(), userID, secret, req.Code)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid verification code"})
		return
	}

	// Clear the cached secret after successful enrollment
	s.redis.Client.Del(c.Request.Context(), cacheKey)

	// Generate backup codes
	backupCodes, err := s.GenerateBackupCodes(c.Request.Context(), userID, 10)
	if err != nil {
		s.logger.Warn("Failed to generate backup codes", zap.Error(err))
	}

	c.JSON(200, gin.H{
		"status":      "mfa enabled",
		"backupCodes": backupCodes,
	})
}

func (s *Service) handleDisableUserMFA(c *gin.Context) {
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

	c.JSON(200, gin.H{"status": "mfa disabled"})
}

func (s *Service) handleExportUsersCSV(c *gin.Context) {
	users, _, err := s.ListUsers(c.Request.Context(), 0, 10000)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment; filename=users.csv")

	writer := csv.NewWriter(c.Writer)
	writer.Write([]string{"username", "email", "first_name", "last_name", "enabled"})

	for _, u := range users {
		enabled := "true"
		if !u.Enabled {
			enabled = "false"
		}
		writer.Write([]string{u.Username, u.Email, u.FirstName, u.LastName, enabled})
	}
	writer.Flush()
}

func (s *Service) handleImportUsersCSV(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "file is required"})
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read header
	header, err := reader.Read()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid CSV file"})
		return
	}

	// Build column index map
	colIndex := make(map[string]int)
	for i, col := range header {
		colIndex[strings.ToLower(strings.TrimSpace(col))] = i
	}

	var total, created, errCount int
	var importErrors []string

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			errCount++
			importErrors = append(importErrors, fmt.Sprintf("Row %d: invalid CSV row", total+2))
			continue
		}
		total++

		getField := func(name string) string {
			if idx, ok := colIndex[name]; ok && idx < len(record) {
				return strings.TrimSpace(record[idx])
			}
			return ""
		}

		username := getField("username")
		email := getField("email")
		if username == "" || email == "" {
			errCount++
			importErrors = append(importErrors, fmt.Sprintf("Row %d: username and email are required", total+1))
			continue
		}

		user := &User{
			Username:      username,
			Email:         email,
			FirstName:     getField("first_name"),
			LastName:      getField("last_name"),
			Enabled:       getField("enabled") != "false",
			EmailVerified: false,
		}

		if err := s.CreateUser(c.Request.Context(), user); err != nil {
			errCount++
			importErrors = append(importErrors, fmt.Sprintf("Row %d: %s", total+1, err.Error()))
			continue
		}
		created++
	}

	c.JSON(200, gin.H{
		"total":   total,
		"created": created,
		"errors":  errCount,
		"details": importErrors,
	})
}

func (s *Service) handleForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "email is required"})
		return
	}

	// Always return success to prevent email enumeration
	// Look up user by email
	var userID string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT id FROM users WHERE email = $1 AND enabled = true", req.Email).Scan(&userID)
	if err != nil {
		// User not found - still return success
		c.JSON(200, gin.H{"message": "If an account with that email exists, a password reset link has been sent."})
		return
	}

	// Generate token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	// Store token with 1 hour expiry
	_, err = s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO password_reset_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
	`, userID, token, time.Now().Add(1*time.Hour))
	if err != nil {
		s.logger.Error("Failed to create password reset token", zap.Error(err))
		c.JSON(200, gin.H{"message": "If an account with that email exists, a password reset link has been sent."})
		return
	}

	// In dev mode, log the token so it can be used for testing
	s.logger.Info("Password reset token created",
		zap.String("email", req.Email),
		zap.String("token", token),
		zap.String("reset_url", fmt.Sprintf("http://localhost:3000/reset-password?token=%s", token)))

	c.JSON(200, gin.H{"message": "If an account with that email exists, a password reset link has been sent."})
}

func (s *Service) handleResetPassword(c *gin.Context) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "token and password are required"})
		return
	}

	if len(req.Password) < 8 {
		c.JSON(400, gin.H{"error": "Password must be at least 8 characters"})
		return
	}

	// Validate token
	var userID string
	var usedAt *time.Time
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT user_id, used_at FROM password_reset_tokens
		WHERE token = $1 AND expires_at > NOW()
	`, req.Token).Scan(&userID, &usedAt)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid or expired reset token"})
		return
	}
	if usedAt != nil {
		c.JSON(400, gin.H{"error": "This reset token has already been used"})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to process password"})
		return
	}

	// Update password
	_, err = s.db.Pool.Exec(c.Request.Context(),
		"UPDATE users SET password_hash = $1, password_changed_at = NOW(), updated_at = NOW() WHERE id = $2",
		string(hashedPassword), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to update password"})
		return
	}

	// Mark token as used
	s.db.Pool.Exec(c.Request.Context(),
		"UPDATE password_reset_tokens SET used_at = NOW() WHERE token = $1", req.Token)

	c.JSON(200, gin.H{"message": "Password has been reset successfully"})
}

// Permission represents a system permission
type Permission struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	CreatedAt   time.Time `json:"created_at"`
}

// ListPermissions returns all available permissions
func (s *Service) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, resource, action, created_at
		FROM permissions ORDER BY resource, action
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, nil
}

// GetRolePermissions returns permissions assigned to a role
func (s *Service) GetRolePermissions(ctx context.Context, roleID string) ([]Permission, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT p.id, p.name, p.description, p.resource, p.action, p.created_at
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.resource, p.action
	`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, nil
}

// SetRolePermissions replaces all permissions for a role
func (s *Service) SetRolePermissions(ctx context.Context, roleID string, permissionIDs []string) error {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, "DELETE FROM role_permissions WHERE role_id = $1", roleID)
	if err != nil {
		return err
	}

	for _, permID := range permissionIDs {
		_, err = tx.Exec(ctx, "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)", roleID, permID)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *Service) handleListPermissions(c *gin.Context) {
	perms, err := s.ListPermissions(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, perms)
}

func (s *Service) handleGetRolePermissions(c *gin.Context) {
	roleID := c.Param("id")
	perms, err := s.GetRolePermissions(c.Request.Context(), roleID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, perms)
}

func (s *Service) handleSetRolePermissions(c *gin.Context) {
	roleID := c.Param("id")
	var req struct {
		PermissionIDs []string `json:"permission_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.SetRolePermissions(c.Request.Context(), roleID, req.PermissionIDs); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "Permissions updated"})
}
