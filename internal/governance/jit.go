// Package governance provides Just-In-Time (JIT) access elevation functionality
package governance

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

const (
	// MinimumJITDuration is the minimum allowed JIT elevation duration
	MinimumJITDuration = 15 * time.Minute
	// MaximumJITDuration is the maximum allowed JIT elevation duration
	MaximumJITDuration = 8 * time.Hour
	// JITExpiryCheckInterval is how often the background goroutine checks for expired grants
	JITExpiryCheckInterval = 30 * time.Second
)

// JITGrant represents a temporary elevation of privilege
type JITGrant struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	RoleID       string    `json:"role_id"`
	RoleName     string    `json:"role_name"`
	GrantedBy    string    `json:"granted_by"`
	Justification string   `json:"justification"`
	Duration     time.Duration `json:"duration"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedBy    *string   `json:"revoked_by,omitempty"`
	Status       string    `json:"status"` // active, expired, revoked
}

// JITRequest represents a request for JIT access elevation
type JITRequest struct {
	UserID        string        `json:"user_id"`
	RoleID        string        `json:"role_id"`
	Duration      time.Duration `json:"duration"`
	Justification string        `json:"justification"`
	RequestedBy   string        `json:"requested_by"` // May differ from UserID (e.g., manager requesting)
}

// JITService handles Just-In-Time access operations
type JITService struct {
	db     *database.PostgresDB
	logger *zap.Logger
}

// NewJITService creates a new JIT service instance
func NewJITService(db *database.PostgresDB, logger *zap.Logger) *JITService {
	return &JITService{
		db:     db,
		logger: logger,
	}
}

// RequestElevation submits a request for temporary privilege elevation
// Duration must be between MinimumJITDuration (15min) and MaximumJITDuration (8hrs)
func (s *JITService) RequestElevation(ctx context.Context, req JITRequest) (*JITGrant, error) {
	// Validate duration
	if req.Duration < MinimumJITDuration {
		return nil, fmt.Errorf("duration must be at least %v", MinimumJITDuration)
	}
	if req.Duration > MaximumJITDuration {
		return nil, fmt.Errorf("duration must not exceed %v", MaximumJITDuration)
	}

	// Validate required fields
	if req.UserID == "" {
		return nil, fmt.Errorf("user_id is required")
	}
	if req.RoleID == "" {
		return nil, fmt.Errorf("role_id is required")
	}
	if req.Justification == "" {
		return nil, fmt.Errorf("justification is required")
	}

	// Check if user already has an active JIT grant for this role
	var existingID string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id FROM jit_grants WHERE user_id = $1 AND role_id = $2 AND status = 'active' AND expires_at > NOW()`,
		req.UserID, req.RoleID).Scan(&existingID)
	if err == nil {
		return nil, fmt.Errorf("user already has an active JIT grant for this role: %s", existingID)
	}

	// Verify the role exists
	var roleName string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT name FROM roles WHERE id = $1`, req.RoleID).Scan(&roleName)
	if err != nil {
		return nil, fmt.Errorf("role not found: %w", err)
	}

	// Create the JIT grant
	id := uuid.New().String()
	now := time.Now()
	expiresAt := now.Add(req.Duration)

	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO jit_grants (id, user_id, role_id, role_name, granted_by, justification, duration, expires_at, created_at, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active')`,
		id, req.UserID, req.RoleID, roleName, req.RequestedBy, req.Justification,
		req.Duration.String(), expiresAt, now)
	if err != nil {
		s.logger.Error("Failed to create JIT grant",
			zap.String("user_id", req.UserID),
			zap.String("role_id", req.RoleID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create JIT grant: %w", err)
	}

	grant := &JITGrant{
		ID:            id,
		UserID:        req.UserID,
		RoleID:        req.RoleID,
		RoleName:      roleName,
		GrantedBy:     req.RequestedBy,
		Justification: req.Justification,
		Duration:      req.Duration,
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
		Status:        "active",
	}

	s.logger.Info("JIT elevation granted",
		zap.String("grant_id", id),
		zap.String("user_id", req.UserID),
		zap.String("role_id", req.RoleID),
		zap.Duration("duration", req.Duration),
		zap.Time("expires_at", expiresAt))

	return grant, nil
}

// GrantElevation directly grants JIT access (bypassing request flow for auto-approved scenarios)
func (s *JITService) GrantElevation(ctx context.Context, userID, roleID, grantedBy, justification string, duration time.Duration) (*JITGrant, error) {
	return s.RequestElevation(ctx, JITRequest{
		UserID:        userID,
		RoleID:        roleID,
		Duration:      duration,
		Justification: justification,
		RequestedBy:   grantedBy,
	})
}

// GetActiveGrant retrieves an active JIT grant for a user and role
func (s *JITService) GetActiveGrant(ctx context.Context, userID, roleID string) (*JITGrant, error) {
	var grant JITGrant
	var revokedAt *time.Time
	var revokedBy *string
	var durationStr string

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, user_id, role_id, role_name, granted_by, justification, duration, expires_at, created_at, revoked_at, revoked_by, status
		 FROM jit_grants
		 WHERE user_id = $1 AND role_id = $2 AND status = 'active' AND expires_at > NOW()`,
		userID, roleID).Scan(
		&grant.ID, &grant.UserID, &grant.RoleID, &grant.RoleName,
		&grant.GrantedBy, &grant.Justification, &durationStr,
		&grant.ExpiresAt, &grant.CreatedAt, &revokedAt, &revokedBy, &grant.Status)

	if err != nil {
		return nil, fmt.Errorf("active grant not found: %w", err)
	}

	grant.RevokedAt = revokedAt
	grant.RevokedBy = revokedBy

	// Parse duration string
	duration, err := time.ParseDuration(durationStr)
	if err == nil {
		grant.Duration = duration
	}

	return &grant, nil
}

// GetUserActiveGrants returns all active JIT grants for a user
func (s *JITService) GetUserActiveGrants(ctx context.Context, userID string) ([]JITGrant, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, user_id, role_id, role_name, granted_by, justification, duration, expires_at, created_at, revoked_at, revoked_by, status
		 FROM jit_grants
		 WHERE user_id = $1 AND status = 'active' AND expires_at > NOW()
		 ORDER BY expires_at ASC`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query active grants: %w", err)
	}
	defer rows.Close()

	var grants []JITGrant
	for rows.Next() {
		var grant JITGrant
		var revokedAt *time.Time
		var revokedBy *string
		var durationStr string

		if err := rows.Scan(
			&grant.ID, &grant.UserID, &grant.RoleID, &grant.RoleName,
			&grant.GrantedBy, &grant.Justification, &durationStr,
			&grant.ExpiresAt, &grant.CreatedAt, &revokedAt, &revokedBy, &grant.Status); err != nil {
			continue
		}

		grant.RevokedAt = revokedAt
		grant.RevokedBy = revokedBy

		if duration, err := time.ParseDuration(durationStr); err == nil {
			grant.Duration = duration
		}

		grants = append(grants, grant)
	}

	if grants == nil {
		return []JITGrant{}, nil
	}
	return grants, nil
}

// ExtendGrant extends the duration of an existing JIT grant
func (s *JITService) ExtendGrant(ctx context.Context, grantID string, additionalDuration time.Duration, extendedBy string) (*JITGrant, error) {
	// Lock the row for update
	var grant JITGrant
	var currentExpiresAt time.Time
	var durationStr string

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, user_id, role_id, role_name, granted_by, justification, duration, expires_at, created_at, status
		 FROM jit_grants WHERE id = $1 AND status = 'active' FOR UPDATE`,
		grantID).Scan(
		&grant.ID, &grant.UserID, &grant.RoleID, &grant.RoleName,
		&grant.GrantedBy, &grant.Justification, &durationStr,
		&currentExpiresAt, &grant.CreatedAt, &grant.Status)

	if err != nil {
		return nil, fmt.Errorf("active grant not found: %w", err)
	}

	// Calculate new expiration time
	newExpiresAt := currentExpiresAt.Add(additionalDuration)
	totalDuration := time.Since(grant.CreatedAt) + (newExpiresAt.Sub(time.Now()))

	// Enforce maximum duration from creation time
	if totalDuration > MaximumJITDuration {
		return nil, fmt.Errorf("extension would exceed maximum duration of %v", MaximumJITDuration)
	}

	// Update the grant
	now := time.Now()
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE jit_grants SET expires_at = $1, updated_at = $2 WHERE id = $3`,
		newExpiresAt, now, grantID)
	if err != nil {
		return nil, fmt.Errorf("failed to extend grant: %w", err)
	}

	grant.ExpiresAt = newExpiresAt
	if duration, err := time.ParseDuration(durationStr); err == nil {
		grant.Duration = duration + additionalDuration
	}

	s.logger.Info("JIT grant extended",
		zap.String("grant_id", grantID),
		zap.String("extended_by", extendedBy),
		zap.Duration("additional", additionalDuration),
		zap.Time("new_expires_at", newExpiresAt))

	return &grant, nil
}

// RevokeGrant immediately revokes an active JIT grant
func (s *JITService) RevokeGrant(ctx context.Context, grantID, revokedBy, reason string) error {
	// Get the grant details before revoking
	var userID, roleID string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT user_id, role_id FROM jit_grants WHERE id = $1 AND status = 'active'`,
		grantID).Scan(&userID, &roleID)
	if err != nil {
		return fmt.Errorf("active grant not found: %w", err)
	}

	now := time.Now()
	result, err := s.db.Pool.Exec(ctx,
		`UPDATE jit_grants SET status = 'revoked', revoked_at = $1, revoked_by = $2, updated_at = $1 WHERE id = $3 AND status = 'active'`,
		now, revokedBy, grantID)
	if err != nil {
		return fmt.Errorf("failed to revoke grant: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("grant not found or already revoked")
	}

	s.logger.Info("JIT grant revoked",
		zap.String("grant_id", grantID),
		zap.String("revoked_by", revokedBy),
		zap.String("reason", reason),
		zap.String("user_id", userID),
		zap.String("role_id", roleID))

	return nil
}

// StartExpiryChecker starts the background goroutine that checks for expired grants
// and revokes them. Runs every 30 seconds by default.
func (s *JITService) StartExpiryChecker(ctx context.Context) {
	ticker := time.NewTicker(JITExpiryCheckInterval)
	defer ticker.Stop()

	s.logger.Info("JIT grant expiry checker started",
		zap.Duration("interval", JITExpiryCheckInterval))

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("JIT grant expiry checker stopped")
			return
		case <-ticker.C:
			s.revokeExpiredGrants(ctx)
		}
	}
}

// revokeExpiredGrants finds and revokes all expired JIT grants
func (s *JITService) revokeExpiredGrants(ctx context.Context) {
	// Find all active grants that have expired
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, user_id, role_id, role_name FROM jit_grants WHERE status = 'active' AND expires_at <= NOW()`)
	if err != nil {
		s.logger.Error("Failed to query expired JIT grants", zap.Error(err))
		return
	}
	defer rows.Close()

	var revokedCount int
	var expiredGrants []struct {
		ID       string
		UserID   string
		RoleID   string
		RoleName string
	}

	for rows.Next() {
		var g struct {
			ID       string
			UserID   string
			RoleID   string
			RoleName string
		}
		if err := rows.Scan(&g.ID, &g.UserID, &g.RoleID, &g.RoleName); err != nil {
			continue
		}
		expiredGrants = append(expiredGrants, g)
	}

	for _, g := range expiredGrants {
		now := time.Now()
		result, err := s.db.Pool.Exec(ctx,
			`UPDATE jit_grants SET status = 'expired', updated_at = $1 WHERE id = $2 AND status = 'active'`,
			now, g.ID)
		if err != nil {
			s.logger.Error("Failed to mark JIT grant as expired",
				zap.String("grant_id", g.ID),
				zap.Error(err))
			continue
		}

		if result.RowsAffected() > 0 {
			revokedCount++
			s.logger.Info("JIT grant expired and revoked",
				zap.String("grant_id", g.ID),
				zap.String("user_id", g.UserID),
				zap.String("role_id", g.RoleID),
				zap.String("role_name", g.RoleName))
		}
	}

	if revokedCount > 0 {
		s.logger.Info("JIT grant expiry check complete",
			zap.Int("revoked_count", revokedCount))
	}
}

// ValidateGrant checks if a user has a valid, non-revoked JIT grant for a role
func (s *JITService) ValidateGrant(ctx context.Context, userID, roleID string) (bool, error) {
	var count int
	err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM jit_grants
		 WHERE user_id = $1 AND role_id = $2 AND status = 'active' AND expires_at > NOW()`,
		userID, roleID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to validate grant: %w", err)
	}
	return count > 0, nil
}
