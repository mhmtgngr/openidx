// Package identity provides identity management functionality
package identity

import (
	"context"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
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

// Group represents a group in the system
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	ParentID    *string   `json:"parent_id,omitempty"`
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	db     *database.PostgresDB
	redis  *database.RedisClient
	config *config.Config
	logger *zap.Logger
}

// NewService creates a new identity service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		config: cfg,
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
		       created_at, updated_at, last_login_at
		FROM users WHERE id = $1
	`, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.FirstName, &user.LastName,
		&user.Enabled, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
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
		       created_at, updated_at, last_login_at
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
		SELECT g.id, g.name, g.description, g.parent_id, g.created_at, g.updated_at,
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
			&g.ID, &g.Name, &g.Description, &g.ParentID, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount,
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
		SELECT g.id, g.name, g.description, g.parent_id, g.created_at, g.updated_at,
		       COALESCE((SELECT COUNT(*) FROM group_memberships gm WHERE gm.group_id = g.id), 0) as member_count
		FROM groups g WHERE g.id = $1
	`, groupID).Scan(
		&g.ID, &g.Name, &g.Description, &g.ParentID, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount,
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
		identity.GET("/groups/:id", svc.handleGetGroup)
		identity.GET("/groups/:id/members", svc.handleGetGroupMembers)
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
