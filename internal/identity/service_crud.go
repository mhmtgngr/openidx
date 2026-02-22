// Package identity provides additional CRUD service methods
package identity

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// ============================================================
// Repository-based CRUD methods
// ============================================================

// SetRepository sets the repository for the service (enables repository pattern)
func (s *Service) SetRepository(repo Repository) {
	s.repository = repo
}

// repository is the optional repository for CRUD operations
var repository Repository // This would be a field on Service struct in a refactor

// ============================================================
// User CRUD Methods using Repository Interface
// ============================================================

// GetUserByUsername retrieves a user by username
func (s *Service) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	s.logger.Debug("Getting user by username", zap.String("username", username))

	// Try using repository if available
	if repo := s.getRepository(); repo != nil {
		return repo.GetUserByUsername(ctx, username)
	}

	// Fall back to direct database query
	var dbUser UserDB
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, username, email, first_name, last_name, enabled, email_verified,
		       created_at, updated_at, last_login_at, password_changed_at,
		       password_must_change, failed_login_count, last_failed_login_at, locked_until
		FROM users WHERE username = $1
	`, username).Scan(
		&dbUser.ID, &dbUser.Username, &dbUser.Email, &dbUser.FirstName, &dbUser.LastName,
		&dbUser.Enabled, &dbUser.EmailVerified, &dbUser.CreatedAt, &dbUser.UpdatedAt, &dbUser.LastLoginAt,
		&dbUser.PasswordChangedAt, &dbUser.PasswordMustChange, &dbUser.FailedLoginCount,
		&dbUser.LastFailedLoginAt, &dbUser.LockedUntil,
	)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	user := dbUser.ToUser()
	return &user, nil
}

// GetUserByEmail retrieves a user by email address
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	s.logger.Debug("Getting user by email", zap.String("email", email))

	// Try using repository if available
	if repo := s.getRepository(); repo != nil {
		return repo.GetUserByEmail(ctx, email)
	}

	// Fall back to direct database query
	var dbUser UserDB
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, username, email, first_name, last_name, enabled, email_verified,
		       created_at, updated_at, last_login_at, password_changed_at,
		       password_must_change, failed_login_count, last_failed_login_at, locked_until
		FROM users WHERE email = $1
	`, email).Scan(
		&dbUser.ID, &dbUser.Username, &dbUser.Email, &dbUser.FirstName, &dbUser.LastName,
		&dbUser.Enabled, &dbUser.EmailVerified, &dbUser.CreatedAt, &dbUser.UpdatedAt, &dbUser.LastLoginAt,
		&dbUser.PasswordChangedAt, &dbUser.PasswordMustChange, &dbUser.FailedLoginCount,
		&dbUser.LastFailedLoginAt, &dbUser.LockedUntil,
	)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	user := dbUser.ToUser()
	return &user, nil
}

// ListUsersWithFilter lists users with advanced filtering and pagination
func (s *Service) ListUsersWithFilter(ctx context.Context, filter UserFilter) (*ListResponse, error) {
	s.logger.Debug("Listing users with filter",
		zap.Int("offset", filter.Offset),
		zap.Int("limit", filter.Limit),
		zap.String("query", pointerString(filter.Query)))

	// Try using repository if available
	if repo := s.getRepository(); repo != nil {
		return repo.ListUsers(ctx, filter)
	}

	// Fall back to direct database query
	// Set default pagination values
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	// Build query - simplified version
	searchQuery := ""
	if filter.Query != nil {
		searchQuery = *filter.Query
	}

	users, total, err := s.ListUsers(ctx, filter.Offset, filter.Limit, searchQuery)
	if err != nil {
		return nil, err
	}

	return &ListResponse{
		TotalResults: total,
		ItemsPerPage: filter.Limit,
		StartIndex:   filter.Offset + 1,
		Resources:    users,
	}, nil
}

// ============================================================
// Group CRUD Methods using Repository Interface
// ============================================================

// GetGroupByDisplayName retrieves a group by display name
func (s *Service) GetGroupByDisplayName(ctx context.Context, displayName string) (*Group, error) {
	s.logger.Debug("Getting group by display name", zap.String("display_name", displayName))

	// Try using repository if available
	if repo := s.getRepository(); repo != nil {
		return repo.GetGroupByDisplayName(ctx, displayName)
	}

	// Fall back to direct database query
	var dbGroup GroupDB
	err := s.db.Pool.QueryRow(ctx, `
		SELECT g.id, g.name, g.description, g.parent_id, g.allow_self_join, g.require_approval, g.max_members, g.created_at, g.updated_at,
		       COALESCE((SELECT COUNT(*) FROM group_memberships gm WHERE gm.group_id = g.id), 0) as member_count
		FROM groups g WHERE g.name = $1
	`, displayName).Scan(
		&dbGroup.ID, &dbGroup.DisplayName, &dbGroup.Description, &dbGroup.ParentID, &dbGroup.AllowSelfJoin, &dbGroup.RequireApproval, &dbGroup.MaxMembers, &dbGroup.CreatedAt, &dbGroup.UpdatedAt, &dbGroup.MemberCount,
	)
	if err != nil {
		return nil, fmt.Errorf("group not found")
	}

	group := dbGroup.ToGroup()
	return &group, nil
}

// ListGroupsWithFilter lists groups with advanced filtering and pagination
func (s *Service) ListGroupsWithFilter(ctx context.Context, filter GroupFilter) (*ListResponse, error) {
	s.logger.Debug("Listing groups with filter",
		zap.Int("offset", filter.Offset),
		zap.Int("limit", filter.Limit),
		zap.String("query", pointerString(filter.Query)))

	// Try using repository if available
	if repo := s.getRepository(); repo != nil {
		return repo.ListGroups(ctx, filter)
	}

	// Fall back to direct database query
	// Set default pagination values
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	// Build query - simplified version
	searchQuery := ""
	if filter.Query != nil {
		searchQuery = *filter.Query
	}

	groups, total, err := s.ListGroups(ctx, filter.Offset, filter.Limit, searchQuery)
	if err != nil {
		return nil, err
	}

	return &ListResponse{
		TotalResults: total,
		ItemsPerPage: filter.Limit,
		StartIndex:   filter.Offset + 1,
		Resources:    groups,
	}, nil
}

// ============================================================
// Validation and Helper Methods
// ============================================================

// ValidateUserForCreate validates user data before creation
func (s *Service) ValidateUserForCreate(ctx context.Context, user *User) error {
	// Check required fields
	if user.UserName == "" {
		return fmt.Errorf("username is required")
	}
	if len(user.UserName) < 3 {
		return fmt.Errorf("username must be at least 3 characters")
	}

	if len(user.Emails) == 0 {
		return fmt.Errorf("email is required")
	}

	email := user.GetEmail()
	if email == "" {
		return fmt.Errorf("email is required")
	}

	// Check for duplicate username
	existing, _ := s.GetUserByUsername(ctx, user.UserName)
	if existing != nil {
		return fmt.Errorf("username already exists")
	}

	// Check for duplicate email
	existing, _ = s.GetUserByEmail(ctx, email)
	if existing != nil {
		return fmt.Errorf("email already exists")
	}

	return nil
}

// ValidateUserForUpdate validates user data before update
func (s *Service) ValidateUserForUpdate(ctx context.Context, user *User, currentUserName, currentEmail string) error {
	// Check username uniqueness if changed
	if user.UserName != currentUserName {
		existing, _ := s.GetUserByUsername(ctx, user.UserName)
		if existing != nil && existing.ID != user.ID {
			return fmt.Errorf("username already exists")
		}
	}

	// Check email uniqueness if changed
	email := user.GetEmail()
	if email != "" && email != currentEmail {
		existing, _ := s.GetUserByEmail(ctx, email)
		if existing != nil && existing.ID != user.ID {
			return fmt.Errorf("email already exists")
		}
	}

	return nil
}

// ValidateGroupForCreate validates group data before creation
func (s *Service) ValidateGroupForCreate(ctx context.Context, group *Group) error {
	// Check required fields
	if group.DisplayName == "" {
		return fmt.Errorf("group name is required")
	}
	if len(group.DisplayName) < 2 {
		return fmt.Errorf("group name must be at least 2 characters")
	}

	// Check for duplicate group name
	existing, _ := s.GetGroupByDisplayName(ctx, group.DisplayName)
	if existing != nil {
		return fmt.Errorf("group name already exists")
	}

	return nil
}

// IsTenantAccessible checks if a resource is accessible to the given tenant
func (s *Service) IsTenantAccessible(resourceOrgID *string, tenantID string) bool {
	if resourceOrgID == nil {
		// No tenant association - globally accessible
		return true
	}
	return *resourceOrgID == tenantID
}

// ============================================================
// Helper Functions
// ============================================================

// getRepository returns the repository if set (for future use)
func (s *Service) getRepository() Repository {
	// In a future refactor, this would return s.repository
	// For now, return nil to use direct database access
	return nil
}

// pointerString safely dereferences a string pointer
func pointerString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
