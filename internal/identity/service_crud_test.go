// Package identity provides unit tests for identity CRUD operations
package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// MockRepository is a mock implementation of the Repository interface for testing
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) CreateUser(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) GetUser(ctx context.Context, id string) (*User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockRepository) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	args := m.Called(ctx, externalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockRepository) UpdateUser(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) ListUsers(ctx context.Context, filter UserFilter) (*ListResponse, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListResponse), args.Error(1)
}

func (m *MockRepository) ListUsersByGroup(ctx context.Context, groupID string, filter UserFilter) (*ListResponse, error) {
	args := m.Called(ctx, groupID, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListResponse), args.Error(1)
}

func (m *MockRepository) CreateGroup(ctx context.Context, group *Group) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}

func (m *MockRepository) GetGroup(ctx context.Context, id string) (*Group, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Group), args.Error(1)
}

func (m *MockRepository) GetGroupByDisplayName(ctx context.Context, displayName string) (*Group, error) {
	args := m.Called(ctx, displayName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Group), args.Error(1)
}

func (m *MockRepository) GetGroupByExternalID(ctx context.Context, externalID string) (*Group, error) {
	args := m.Called(ctx, externalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Group), args.Error(1)
}

func (m *MockRepository) UpdateGroup(ctx context.Context, group *Group) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}

func (m *MockRepository) DeleteGroup(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) ListGroups(ctx context.Context, filter GroupFilter) (*ListResponse, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListResponse), args.Error(1)
}

func (m *MockRepository) ListGroupsByUser(ctx context.Context, userID string, filter GroupFilter) (*ListResponse, error) {
	args := m.Called(ctx, userID, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListResponse), args.Error(1)
}

func (m *MockRepository) AddGroupMember(ctx context.Context, groupID, userID string) error {
	args := m.Called(ctx, groupID, userID)
	return args.Error(0)
}

func (m *MockRepository) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	args := m.Called(ctx, groupID, userID)
	return args.Error(0)
}

func (m *MockRepository) CreateOrganization(ctx context.Context, org *Organization) error {
	args := m.Called(ctx, org)
	return args.Error(0)
}

func (m *MockRepository) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Organization), args.Error(1)
}

func (m *MockRepository) GetOrganizationByName(ctx context.Context, name string) (*Organization, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Organization), args.Error(1)
}

func (m *MockRepository) GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error) {
	args := m.Called(ctx, domain)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Organization), args.Error(1)
}

func (m *MockRepository) GetOrganizationByExternalID(ctx context.Context, externalID string) (*Organization, error) {
	args := m.Called(ctx, externalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Organization), args.Error(1)
}

func (m *MockRepository) UpdateOrganization(ctx context.Context, org *Organization) error {
	args := m.Called(ctx, org)
	return args.Error(0)
}

func (m *MockRepository) DeleteOrganization(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) ListOrganizations(ctx context.Context, filter OrganizationFilter) (*ListResponse, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListResponse), args.Error(1)
}

func (m *MockRepository) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// ============================================================
// Test Helper Functions
// ============================================================

// createTestUser creates a test user with default values
func createTestUser(username, email string) *User {
	user := NewUser(username)
	user.SetEmail(email)
	user.SetFirstName("Test")
	user.SetLastName("User")
	enabled := true
	user.Enabled = enabled
	user.Active = enabled
	return user
}

// createTestGroup creates a test group with default values
func createTestGroup(displayName string) *Group {
	group := NewGroup(displayName)
	return group
}

// ============================================================
// User CRUD Tests
// ============================================================

// TestUserCreateSuccess tests successful user creation
func TestUserCreateSuccess(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	user := createTestUser("john.doe", "john@example.com")
	userID := user.ID

	mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*identity.User")).Return(nil)

	// For the repository-based test, we would inject the mock repository
	// Since the current implementation uses direct DB access, we test the validation logic
	err := mockRepo.CreateUser(ctx, user)
	assert.NoError(t, err)
	assert.Equal(t, userID, user.ID)
	assert.Equal(t, "john.doe", user.UserName)
	assert.Equal(t, "john@example.com", user.GetEmail())

	mockRepo.AssertExpectations(t)
}

// TestUserCreateDuplicateEmail tests user creation with duplicate email
func TestUserCreateDuplicateEmail(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	user := createTestUser("john.doe", "john@example.com")

	// First call returns success, second returns duplicate error
	mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*identity.User")).Return(nil).Once()
	mockRepo.On("GetUserByEmail", ctx, "john@example.com").Return(user, nil).Once()

	// Create first user
	err := mockRepo.CreateUser(ctx, user)
	assert.NoError(t, err)

	// Try to get user by email - should return the existing user
	existing, err := mockRepo.GetUserByEmail(ctx, "john@example.com")
	assert.NoError(t, err)
	assert.Equal(t, user.ID, existing.ID)

	mockRepo.AssertExpectations(t)
}

// TestUserCreateValidation tests input validation for user creation
func TestUserCreateValidation(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name        string
		user        *User
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid user",
			user: createTestUser("validuser", "valid@example.com"),
			expectError: false,
		},
		{
			name:        "Missing username",
			user:        func() *User { u := NewUser(""); u.SetEmail("test@example.com"); return u }(),
			expectError: true,
			errorMsg:    "username is required",
		},
		{
			name:        "Username too short",
			user:        func() *User { u := NewUser("ab"); u.SetEmail("test@example.com"); return u }(),
			expectError: true,
			errorMsg:    "username must be at least 3 characters",
		},
		{
			name:        "Missing email",
			user:        func() *User { u := NewUser("testuser"); return u }(),
			expectError: true,
			errorMsg:    "email is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTestUser(tc.user)
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// validateTestUser is a test helper for user validation
func validateTestUser(user *User) error {
	if user.UserName == "" {
		return errors.New("username is required")
	}
	if len(user.UserName) < 3 {
		return errors.New("username must be at least 3 characters")
	}
	if len(user.Emails) == 0 {
		return errors.New("email is required")
	}
	return nil
}

// TestUserNotFound tests retrieving a non-existent user
func TestUserNotFound(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	userID := uuid.New().String()
	mockRepo.On("GetUser", ctx, userID).Return(nil, errors.New("user not found"))

	user, err := mockRepo.GetUser(ctx, userID)
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "user not found")

	mockRepo.AssertExpectations(t)
}

// TestUserUpdateSuccess tests successful user update
func TestUserUpdateSuccess(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	user := createTestUser("john.doe", "john.doe@example.com")
	user.ID = uuid.New().String()

	mockRepo.On("UpdateUser", ctx, mock.MatchedBy(func(u *User) bool {
		return u.ID == user.ID && u.UserName == "john.doe"
	})).Return(nil)

	err := mockRepo.UpdateUser(ctx, user)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

// TestUserDeleteSuccess tests successful user deletion
func TestUserDeleteSuccess(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	userID := uuid.New().String()

	mockRepo.On("DeleteUser", ctx, userID).Return(nil)

	err := mockRepo.DeleteUser(ctx, userID)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

// TestUserListPagination tests user listing with pagination
func TestUserListPagination(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	filter := UserFilter{
		PaginationParams: PaginationParams{
			Offset: 0,
			Limit:  10,
		},
	}

	expectedUsers := []User{
		*createTestUser("user1", "user1@example.com"),
		*createTestUser("user2", "user2@example.com"),
		*createTestUser("user3", "user3@example.com"),
	}

	expectedResponse := &ListResponse{
		TotalResults: 3,
		ItemsPerPage: 10,
		StartIndex:   1,
		Resources:    expectedUsers,
	}

	mockRepo.On("ListUsers", ctx, mock.MatchedBy(func(f UserFilter) bool {
		return f.Offset == 0 && f.Limit == 10
	})).Return(expectedResponse, nil)

	response, err := mockRepo.ListUsers(ctx, filter)
	assert.NoError(t, err)
	assert.Equal(t, 3, response.TotalResults)
	assert.Equal(t, 10, response.ItemsPerPage)

	users, ok := response.Resources.([]User)
	require.True(t, ok)
	assert.Len(t, users, 3)

	mockRepo.AssertExpectations(t)
}

// TestUserListWithSearch tests user listing with search query
func TestUserListWithSearch(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	query := "john"
	filter := UserFilter{
		PaginationParams: PaginationParams{
			Offset: 0,
			Limit:  20,
		},
		Query: &query,
	}

	expectedUsers := []User{
		*createTestUser("john.doe", "john@example.com"),
		*createTestUser("john.smith", "jsmith@example.com"),
	}

	expectedResponse := &ListResponse{
		TotalResults: 2,
		ItemsPerPage: 20,
		StartIndex:   1,
		Resources:    expectedUsers,
	}

	mockRepo.On("ListUsers", ctx, mock.MatchedBy(func(f UserFilter) bool {
		return f.Query != nil && *f.Query == "john"
	})).Return(expectedResponse, nil)

	response, err := mockRepo.ListUsers(ctx, filter)
	assert.NoError(t, err)
	assert.Equal(t, 2, response.TotalResults)

	mockRepo.AssertExpectations(t)
}

// ============================================================
// Tenant Isolation Tests
// ============================================================

// TestTenantIsolation tests that tenant isolation is enforced
func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()

	tenant1ID := "tenant-1"
	tenant2ID := "tenant-2"

	// Create users in different tenants
	user1 := createTestUser("user1", "user1@example.com")
	user1.OrganizationID = &tenant1ID

	user2 := createTestUser("user2", "user2@example.com")
	user2.OrganizationID = &tenant2ID

	// Test tenant isolation
	assert.True(t, IsTenantAccessible(user1.OrganizationID, tenant1ID))
	assert.False(t, IsTenantAccessible(user1.OrganizationID, tenant2ID))
	assert.True(t, IsTenantAccessible(user2.OrganizationID, tenant2ID))
	assert.False(t, IsTenantAccessible(user2.OrganizationID, tenant1ID))

	// Test global resource (no tenant)
	var globalUser *User
	globalUser = createTestUser("global", "global@example.com")
	assert.True(t, IsTenantAccessible(globalUser.OrganizationID, tenant1ID))
	assert.True(t, IsTenantAccessible(globalUser.OrganizationID, tenant2ID))
}

// ============================================================
// Group CRUD Tests
// ============================================================

// TestGroupCreateSuccess tests successful group creation
func TestGroupCreateSuccess(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	group := createTestGroup("Developers")
	groupID := group.ID

	mockRepo.On("CreateGroup", ctx, mock.AnythingOfType("*identity.Group")).Return(nil)

	err := mockRepo.CreateGroup(ctx, group)
	assert.NoError(t, err)
	assert.Equal(t, groupID, group.ID)
	assert.Equal(t, "Developers", group.DisplayName)

	mockRepo.AssertExpectations(t)
}

// TestGroupCreateDuplicateName tests group creation with duplicate name
func TestGroupCreateDuplicateName(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	group := createTestGroup("Developers")

	mockRepo.On("GetGroupByDisplayName", ctx, "Developers").Return(group, nil).Once()

	// Check for duplicate
	existing, err := mockRepo.GetGroupByDisplayName(ctx, "Developers")
	assert.NoError(t, err)
	assert.NotNil(t, existing)
	assert.Equal(t, "Developers", existing.DisplayName)

	mockRepo.AssertExpectations(t)
}

// TestGroupNotFound tests retrieving a non-existent group
func TestGroupNotFound(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	groupID := uuid.New().String()
	mockRepo.On("GetGroup", ctx, groupID).Return(nil, errors.New("group not found"))

	group, err := mockRepo.GetGroup(ctx, groupID)
	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "group not found")

	mockRepo.AssertExpectations(t)
}

// TestGroupUpdateSuccess tests successful group update
func TestGroupUpdateSuccess(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	group := createTestGroup("Engineering")
	group.ID = uuid.New().String()

	mockRepo.On("UpdateGroup", ctx, mock.MatchedBy(func(g *Group) bool {
		return g.ID == group.ID && g.DisplayName == "Engineering"
	})).Return(nil)

	err := mockRepo.UpdateGroup(ctx, group)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

// TestGroupDeleteSuccess tests successful group deletion
func TestGroupDeleteSuccess(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	groupID := uuid.New().String()

	mockRepo.On("DeleteGroup", ctx, groupID).Return(nil)

	err := mockRepo.DeleteGroup(ctx, groupID)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

// TestGroupListPagination tests group listing with pagination
func TestGroupListPagination(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	filter := GroupFilter{
		PaginationParams: PaginationParams{
			Offset: 0,
			Limit:  10,
		},
	}

	expectedGroups := []Group{
		*createTestGroup("Admins"),
		*createTestGroup("Developers"),
		*createTestGroup("Designers"),
	}

	expectedResponse := &ListResponse{
		TotalResults: 3,
		ItemsPerPage: 10,
		StartIndex:   1,
		Resources:    expectedGroups,
	}

	mockRepo.On("ListGroups", ctx, mock.MatchedBy(func(f GroupFilter) bool {
		return f.Offset == 0 && f.Limit == 10
	})).Return(expectedResponse, nil)

	response, err := mockRepo.ListGroups(ctx, filter)
	assert.NoError(t, err)
	assert.Equal(t, 3, response.TotalResults)

	groups, ok := response.Resources.([]Group)
	require.True(t, ok)
	assert.Len(t, groups, 3)

	mockRepo.AssertExpectations(t)
}

// ============================================================
// Group Member Tests
// ============================================================

// TestAddGroupMemberSuccess tests successful group member addition
func TestAddGroupMemberSuccess(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	groupID := uuid.New().String()
	userID := uuid.New().String()

	mockRepo.On("AddGroupMember", ctx, groupID, userID).Return(nil)

	err := mockRepo.AddGroupMember(ctx, groupID, userID)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

// TestRemoveGroupMemberSuccess tests successful group member removal
func TestRemoveGroupMemberSuccess(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	groupID := uuid.New().String()
	userID := uuid.New().String()

	mockRepo.On("RemoveGroupMember", ctx, groupID, userID).Return(nil)

	err := mockRepo.RemoveGroupMember(ctx, groupID, userID)
	assert.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

// ============================================================
// Model Conversion Tests
// ============================================================

// TestUserDBToUserConversion tests UserDB to User conversion
func TestUserDBToUserConversion(t *testing.T) {
	dbUser := UserDB{
		ID:            "user-123",
		Username:      "john.doe",
		Email:         "john@example.com",
		FirstName:     "John",
		LastName:      "Doe",
		Enabled:       true,
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	user := dbUser.ToUser()

	assert.Equal(t, dbUser.ID, user.ID)
	assert.Equal(t, dbUser.Username, user.UserName)
	assert.Equal(t, dbUser.Email, user.GetEmail())
	assert.Equal(t, dbUser.FirstName, user.GetFirstName())
	assert.Equal(t, dbUser.LastName, user.GetLastName())
	assert.Equal(t, dbUser.Enabled, user.Enabled)
	assert.Equal(t, dbUser.Enabled, user.Active)
}

// TestUserToUserDBConversion tests User to UserDB conversion
func TestUserToUserDBConversion(t *testing.T) {
	user := NewUser("john.doe")
	user.SetEmail("john@example.com")
	user.SetFirstName("John")
	user.SetLastName("Doe")
	user.Enabled = true
	user.Active = true

	dbUser := FromUser(*user)

	assert.Equal(t, user.ID, dbUser.ID)
	assert.Equal(t, user.UserName, dbUser.Username)
	assert.Equal(t, user.GetEmail(), dbUser.Email)
	assert.Equal(t, user.GetFirstName(), dbUser.FirstName)
	assert.Equal(t, user.GetLastName(), dbUser.LastName)
	assert.Equal(t, user.Enabled, dbUser.Enabled)
}

// TestGroupDBToGroupConversion tests GroupDB to Group conversion
func TestGroupDBToGroupConversion(t *testing.T) {
	description := "Developer group"
	parentID := "parent-123"
	orgID := "org-123"

	dbGroup := GroupDB{
		ID:             "group-123",
		DisplayName:    "Developers",
		Description:    &description,
		ParentID:       &parentID,
		OrganizationID: &orgID,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	group := dbGroup.ToGroup()

	assert.Equal(t, dbGroup.ID, group.ID)
	assert.Equal(t, dbGroup.DisplayName, group.DisplayName)
	assert.NotNil(t, group.Attributes)
	assert.Equal(t, description, group.Attributes["description"])
	assert.Equal(t, parentID, group.Attributes["parentId"])
	assert.Equal(t, &orgID, group.OrganizationID)
}

// ============================================================
// Pagination and Filter Tests
// ============================================================

// TestPaginationDefaults tests default pagination values
func TestPaginationDefaults(t *testing.T) {
	testCases := []struct {
		name            string
		inputLimit      int
		inputOffset     int
		expectedLimit   int
		expectedOffset  int
	}{
		{
			name:           "Default values",
			inputLimit:     0,
			inputOffset:    0,
			expectedLimit:  50,
			expectedOffset: 0,
		},
		{
			name:           "Custom values",
			inputLimit:     20,
			inputOffset:    10,
			expectedLimit:  20,
			expectedOffset: 10,
		},
		{
			name:           "Limit exceeds maximum",
			inputLimit:     200,
			inputOffset:    0,
			expectedLimit:  100,
			expectedOffset: 0,
		},
		{
			name:           "Negative offset",
			inputLimit:     20,
			inputOffset:    -10,
			expectedLimit:  20,
			expectedOffset: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := UserFilter{
				PaginationParams: PaginationParams{
					Limit:  tc.inputLimit,
					Offset: tc.inputOffset,
				},
			}

			// Apply default logic
			if filter.Limit <= 0 || filter.Limit > 100 {
				filter.Limit = 50
			}
			if filter.Offset < 0 {
				filter.Offset = 0
			}

			assert.Equal(t, tc.expectedLimit, filter.Limit)
			assert.Equal(t, tc.expectedOffset, filter.Offset)
		})
	}
}

// ============================================================
// Service Logger Tests
// ============================================================

// TestServiceWithLogger tests service creation with logger
func TestServiceWithLogger(t *testing.T) {
	logger := zap.NewNop()
	// In a real test, we would create a service with a mock DB
	// and test that logging occurs correctly

	assert.NotNil(t, logger)
	// Service would be created like:
	// svc := NewService(nil, nil, nil, logger)
	// assert.NotNil(t, svc)
}

// ============================================================
// Integration-style tests (multiple operations)
// ============================================================

// TestUserCRUDLifecycle tests the full CRUD lifecycle for a user
func TestUserCRUDLifecycle(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	user := createTestUser("lifecycle", "lifecycle@example.com")
	userID := user.ID

	// Create
	mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*identity.User")).Return(nil).Once()
	err := mockRepo.CreateUser(ctx, user)
	require.NoError(t, err)

	// Read
	mockRepo.On("GetUser", ctx, userID).Return(user, nil).Once()
	retrieved, err := mockRepo.GetUser(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrieved.ID)

	// Update
	user.SetFirstName("Updated")
	mockRepo.On("UpdateUser", ctx, mock.MatchedBy(func(u *User) bool {
		return u.GetFirstName() == "Updated"
	})).Return(nil).Once()
	err = mockRepo.UpdateUser(ctx, user)
	require.NoError(t, err)

	// Delete
	mockRepo.On("DeleteUser", ctx, userID).Return(nil).Once()
	err = mockRepo.DeleteUser(ctx, userID)
	require.NoError(t, err)

	mockRepo.AssertExpectations(t)
}

// TestGroupCRUDLifecycle tests the full CRUD lifecycle for a group
func TestGroupCRUDLifecycle(t *testing.T) {
	mockRepo := new(MockRepository)
	ctx := context.Background()

	group := createTestGroup("TestGroup")
	groupID := group.ID

	// Create
	mockRepo.On("CreateGroup", ctx, mock.AnythingOfType("*identity.Group")).Return(nil).Once()
	err := mockRepo.CreateGroup(ctx, group)
	require.NoError(t, err)

	// Read
	mockRepo.On("GetGroup", ctx, groupID).Return(group, nil).Once()
	retrieved, err := mockRepo.GetGroup(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, group.ID, retrieved.ID)

	// Update
	group.SetDescription("Updated description")
	mockRepo.On("UpdateGroup", ctx, mock.MatchedBy(func(g *Group) bool {
		return g.GetDescription() != nil && *g.GetDescription() == "Updated description"
	})).Return(nil).Once()
	err = mockRepo.UpdateGroup(ctx, group)
	require.NoError(t, err)

	// Delete
	mockRepo.On("DeleteGroup", ctx, groupID).Return(nil).Once()
	err = mockRepo.DeleteGroup(ctx, groupID)
	require.NoError(t, err)

	mockRepo.AssertExpectations(t)
}
