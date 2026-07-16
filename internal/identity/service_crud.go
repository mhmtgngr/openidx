// Package identity provides additional CRUD service methods
package identity

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// ============================================================
// User CRUD Methods (direct database access)
// ============================================================

// GetUserByUsername retrieves a user by username
func (s *Service) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	s.logger.Debug("Getting user by username", zap.String("username", username))
	// Delegates to the user repository (see user_repository.go). The repo owns
	// the SQL, scopes to the caller's tenant, reads from the replica, and returns
	// ErrUserNotFound on a miss. Note: the repo's shared column list COALESCEs
	// first_name/last_name, fixing a latent scan error this method had for users
	// with a NULL name.
	return s.users.GetByUsername(ctx, username)
}

// GetUserByEmail retrieves a user by email address
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	s.logger.Debug("Getting user by email", zap.String("email", email))
	return s.users.GetByEmail(ctx, email)
}

// ListUsersWithFilter lists users with advanced filtering and pagination
func (s *Service) ListUsersWithFilter(ctx context.Context, filter UserFilter) (*ListResponse, error) {
	s.logger.Debug("Listing users with filter",
		zap.Int("offset", filter.Offset),
		zap.Int("limit", filter.Limit),
		zap.String("query", pointerString(filter.Query)))

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
// Group CRUD Methods (direct database access)
// ============================================================

// GetGroupByDisplayName retrieves a group by display name
func (s *Service) GetGroupByDisplayName(ctx context.Context, displayName string) (*Group, error) {
	s.logger.Debug("Getting group by display name", zap.String("display_name", displayName))
	// Delegates to the group repository (see group_repository.go).
	return s.groups.GetByName(ctx, displayName)
}

// ListGroupsWithFilter lists groups with advanced filtering and pagination
func (s *Service) ListGroupsWithFilter(ctx context.Context, filter GroupFilter) (*ListResponse, error) {
	s.logger.Debug("Listing groups with filter",
		zap.Int("offset", filter.Offset),
		zap.Int("limit", filter.Limit),
		zap.String("query", pointerString(filter.Query)))

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

// CheckTenantAccessible is a package-level helper for testing tenant isolation logic
func CheckTenantAccessible(resourceOrgID *string, tenantID string) bool {
	if resourceOrgID == nil {
		// No tenant association - globally accessible
		return true
	}
	return *resourceOrgID == tenantID
}

// ============================================================
// Helper Functions
// ============================================================

// pointerString safely dereferences a string pointer
func pointerString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
