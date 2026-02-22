// Package identity provides identity management functionality with enhanced validation and error handling
// This is an example of how to use the new validation, error handling, and logging features
package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/errors"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/common/validation"
)

// EnhancedService provides identity management operations with validation and error handling
type EnhancedService struct {
	db        *database.PostgresDB
	redis     *database.RedisClient
	config    *config.Config
	logger    *zap.Logger
	audit     *logger.AuditLogger
	perf      *logger.PerformanceLogger
}

// NewEnhancedService creates a new enhanced identity service
func NewEnhancedService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, log *zap.Logger) *EnhancedService {
	serviceLogger := log.With(zap.String("service", "identity"))
	return &EnhancedService{
		db:     db,
		redis:  redis,
		config: cfg,
		logger: serviceLogger,
		audit:  logger.NewAuditLogger(serviceLogger),
		perf:   logger.NewPerformanceLogger(serviceLogger),
	}
}

// ValidateUser validates user input
func (s *EnhancedService) ValidateUser(user *User) error {
	return validation.ValidateAll(
		func() error { return validation.ValidateRequired("username", user.GetUsername()) },
		func() error { return validation.ValidateUsername("username", user.GetUsername()) },
		func() error { return validation.ValidateRequired("email", user.GetEmail()) },
		func() error { return validation.ValidateEmail("email", user.GetEmail()) },
		func() error { return validation.ValidateRequired("first_name", user.GetFirstName()) },
		func() error { return validation.ValidateMaxLength("first_name", user.GetFirstName(), 50) },
		func() error { return validation.ValidateRequired("last_name", user.GetLastName()) },
		func() error { return validation.ValidateMaxLength("last_name", user.GetLastName(), 50) },
	)
}

// CreateUser creates a new user with validation and error handling
func (s *EnhancedService) CreateUser(ctx context.Context, user *User) error {
	// Start performance timer
	timer := s.perf.StartContextTimer(ctx, "create_user",
		zap.String("username", user.GetUsername()),
		zap.String("email", user.GetEmail()),
	)
	defer timer.Stop()

	// Sanitize input
	user.SetUsername(validation.SanitizeUsername(user.GetUsername()))
	user.SetEmail(validation.SanitizeEmail(user.GetEmail()))
	user.SetFirstName(validation.SanitizeString(user.GetFirstName()))
	user.SetLastName(validation.SanitizeString(user.GetLastName()))

	// Validate input
	if err := s.ValidateUser(user); err != nil {
		s.logger.Warn("User validation failed",
			zap.String("username", user.GetUsername()),
			zap.Error(err),
		)
		return errors.ValidationError(err.Error())
	}

	// Check if user already exists
	var exists bool
	err := s.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 OR email = $2)",
		user.GetUsername(), user.GetEmail()).Scan(&exists)
	if err != nil {
		s.logger.Error("Failed to check user existence", zap.Error(err))
		return errors.DatabaseError("check user existence", err)
	}
	if exists {
		return errors.UserAlreadyExists(user.GetUsername())
	}

	// Create user
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, first_name, last_name, enabled,
		                   email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, user.ID, user.GetUsername(), user.GetEmail(), user.GetFirstName(), user.GetLastName(),
		user.Enabled, user.EmailVerified, user.CreatedAt, user.UpdatedAt)

	if err != nil {
		s.logger.Error("Failed to create user",
			zap.String("username", user.GetUsername()),
			zap.Error(err),
		)
		return errors.DatabaseError("create user", err)
	}

	// Audit log
	s.audit.LogUserCreated("system", "", user.ID, user.GetUsername(), map[string]interface{}{
		"email": user.GetEmail(),
	})

	s.logger.Info("User created successfully",
		zap.String("user_id", user.ID),
		zap.String("username", user.GetUsername()),
	)

	return nil
}

// GetUser retrieves a user by ID with enhanced error handling
func (s *EnhancedService) GetUser(ctx context.Context, userID string) (*User, error) {
	timer := s.perf.StartContextTimer(ctx, "get_user", zap.String("user_id", userID))
	defer timer.Stop()

	// Validate input
	if err := validation.ValidateRequired("user_id", userID); err != nil {
		return nil, errors.ValidationError(err.Error())
	}

	var dbUser UserDB
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, username, email, first_name, last_name, enabled, email_verified,
		       created_at, updated_at, last_login_at
		FROM users WHERE id = $1
	`, userID).Scan(
		&dbUser.ID, &dbUser.Username, &dbUser.Email, &dbUser.FirstName, &dbUser.LastName,
		&dbUser.Enabled, &dbUser.EmailVerified, &dbUser.CreatedAt, &dbUser.UpdatedAt, &dbUser.LastLoginAt,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, errors.UserNotFound(userID)
		}
		s.logger.Error("Failed to get user", zap.String("user_id", userID), zap.Error(err))
		return nil, errors.DatabaseError("get user", err)
	}

	user := dbUser.ToUser()
	return &user, nil
}

// UpdateUser updates an existing user with validation
func (s *EnhancedService) UpdateUser(ctx context.Context, user *User) error {
	timer := s.perf.StartContextTimer(ctx, "update_user",
		zap.String("user_id", user.ID),
		zap.String("username", user.GetUsername()),
	)
	defer timer.Stop()

	// Sanitize input
	user.SetUsername(validation.SanitizeUsername(user.GetUsername()))
	user.SetEmail(validation.SanitizeEmail(user.GetEmail()))
	user.SetFirstName(validation.SanitizeString(user.GetFirstName()))
	user.SetLastName(validation.SanitizeString(user.GetLastName()))

	// Validate input
	if err := s.ValidateUser(user); err != nil {
		return errors.ValidationError(err.Error())
	}

	// Check if user exists
	_, err := s.GetUser(ctx, user.ID)
	if err != nil {
		return err // Already a proper AppError
	}

	user.UpdatedAt = time.Now()

	result, err := s.db.Pool.Exec(ctx, `
		UPDATE users
		SET username = $2, email = $3, first_name = $4, last_name = $5,
		    enabled = $6, email_verified = $7, updated_at = $8
		WHERE id = $1
	`, user.ID, user.GetUsername(), user.GetEmail(), user.GetFirstName(), user.GetLastName(),
		user.Enabled, user.EmailVerified, user.UpdatedAt)

	if err != nil {
		s.logger.Error("Failed to update user", zap.String("user_id", user.ID), zap.Error(err))
		return errors.DatabaseError("update user", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.UserNotFound(user.ID)
	}

	// Audit log
	s.audit.LogUserUpdated("system", "", user.ID, map[string]interface{}{
		"username": user.GetUsername(),
		"email":    user.GetEmail(),
	})

	s.logger.Info("User updated successfully", zap.String("user_id", user.ID))

	return nil
}

// DeleteUser deletes a user with audit logging
func (s *EnhancedService) DeleteUser(ctx context.Context, userID string) error {
	timer := s.perf.StartContextTimer(ctx, "delete_user", zap.String("user_id", userID))
	defer timer.Stop()

	// Validate input
	if err := validation.ValidateRequired("user_id", userID); err != nil {
		return errors.ValidationError(err.Error())
	}

	// Get user for audit logging
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	result, err := s.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		s.logger.Error("Failed to delete user", zap.String("user_id", userID), zap.Error(err))
		return errors.DatabaseError("delete user", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.UserNotFound(userID)
	}

	// Audit log
	s.audit.LogUserDeleted("system", "", user.ID, user.GetUsername())

	s.logger.Info("User deleted successfully", zap.String("user_id", userID))

	return nil
}

// ListUsers retrieves users with pagination and validation
func (s *EnhancedService) ListUsers(ctx context.Context, offset, limit int) ([]User, int, error) {
	timer := s.perf.StartContextTimer(ctx, "list_users",
		zap.Int("offset", offset),
		zap.Int("limit", limit),
	)
	defer timer.Stop()

	// Validate pagination parameters
	if err := validation.ValidateMin("offset", offset, 0); err != nil {
		return nil, 0, errors.ValidationError(err.Error())
	}
	if err := validation.ValidateRange("limit", limit, 1, 100); err != nil {
		return nil, 0, errors.ValidationError(err.Error())
	}

	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&total)
	if err != nil {
		s.logger.Error("Failed to count users", zap.Error(err))
		return nil, 0, errors.DatabaseError("count users", err)
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, username, email, first_name, last_name, enabled, email_verified,
		       created_at, updated_at, last_login_at
		FROM users
		ORDER BY created_at DESC
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		s.logger.Error("Failed to list users", zap.Error(err))
		return nil, 0, errors.DatabaseError("list users", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u UserDB
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName,
			&u.Enabled, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
		); err != nil {
			s.logger.Error("Failed to scan user", zap.Error(err))
			return nil, 0, errors.DatabaseError("scan user", err)
		}
		users = append(users, u.ToUser())
	}

	return users, total, nil
}

// HTTP Handlers with enhanced error handling

func (s *EnhancedService) handleCreateUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		errors.HandleError(c, errors.BadRequest("Invalid request body"))
		return
	}

	if err := s.CreateUser(c.Request.Context(), &user); err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(201, user)
}

func (s *EnhancedService) handleGetUser(c *gin.Context) {
	userID := c.Param("id")

	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(200, user)
}

func (s *EnhancedService) handleUpdateUser(c *gin.Context) {
	userID := c.Param("id")

	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		errors.HandleError(c, errors.BadRequest("Invalid request body"))
		return
	}

	user.ID = userID
	if err := s.UpdateUser(c.Request.Context(), &user); err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(200, user)
}

func (s *EnhancedService) handleDeleteUser(c *gin.Context) {
	userID := c.Param("id")

	if err := s.DeleteUser(c.Request.Context(), userID); err != nil {
		errors.HandleError(c, err)
		return
	}

	c.JSON(204, nil)
}

func (s *EnhancedService) handleListUsers(c *gin.Context) {
	offset := 0
	limit := 20

	// Parse query parameters
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if o, err := parseInt(offsetStr); err == nil {
			offset = o
		}
	}
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := parseInt(limitStr); err == nil {
			limit = l
		}
	}

	users, total, err := s.ListUsers(c.Request.Context(), offset, limit)
	if err != nil {
		errors.HandleError(c, err)
		return
	}

	c.Header("X-Total-Count", string(rune(total)))
	c.JSON(200, users)
}

// Helper function
func parseInt(s string) (int, error) {
	var i int
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}
