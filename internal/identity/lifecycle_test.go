// Package identity provides tests for identity lifecycle management
package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/events"
	"go.uber.org/zap"
)

func TestIdentityState_GetState(t *testing.T) {
	tests := []struct {
		name     string
		user     *User
		expected IdentityState
	}{
		{
			name:     "User with no attributes defaults to Created",
			user:     &User{Attributes: nil},
			expected: StateCreated,
		},
		{
			name:     "User with empty attributes defaults to Created",
			user:     &User{Attributes: make(map[string]string)},
			expected: StateCreated,
		},
		{
			name: "User in Active state",
			user: &User{Attributes: map[string]string{
				AttributeKeyState: string(StateActive),
			}},
			expected: StateActive,
		},
		{
			name: "User in Suspended state",
			user: &User{Attributes: map[string]string{
				AttributeKeyState: string(StateSuspended),
			}},
			expected: StateSuspended,
		},
		{
			name: "User in Deprovisioned state",
			user: &User{Attributes: map[string]string{
				AttributeKeyState: string(StateDeprovisioned),
			}},
			expected: StateDeprovisioned,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := tt.user.GetState()
			assert.Equal(t, tt.expected, state)
		})
	}
}

func TestIdentityState_SetState(t *testing.T) {
	user := &User{Attributes: make(map[string]string)}
	user.SetState(StateActive)

	assert.Equal(t, StateActive, user.GetState())
	assert.Contains(t, user.Attributes, AttributeKeyState)
	assert.Contains(t, user.Attributes, AttributeKeyStateSince)

	// Check timestamp was set
	sinceStr := user.Attributes[AttributeKeyStateSince]
	since, err := time.Parse(time.RFC3339, sinceStr)
	assert.NoError(t, err)
	assert.WithinDuration(t, time.Now(), since, 5*time.Second)
}

func TestIdentityState_StateHistory(t *testing.T) {
	user := &User{Attributes: make(map[string]string)}

	// Record some transitions
	user.RecordStateTransition(StateCreated, StateActive, "admin")
	user.RecordStateTransition(StateActive, StateSuspended, "system")
	user.RecordStateTransition(StateSuspended, StateActive, "admin")

	history := user.GetStateHistory()

	require.Len(t, history, 3)

	// Check first transition
	assert.Equal(t, StateCreated, history[0].From)
	assert.Equal(t, StateActive, history[0].To)
	assert.Equal(t, "admin", history[0].Actor)

	// Check second transition
	assert.Equal(t, StateActive, history[1].From)
	assert.Equal(t, StateSuspended, history[1].To)
	assert.Equal(t, "system", history[1].Actor)

	// Check third transition
	assert.Equal(t, StateSuspended, history[2].From)
	assert.Equal(t, StateActive, history[2].To)
	assert.Equal(t, "admin", history[2].Actor)
}

func TestValidStateTransitions(t *testing.T) {
	tests := []struct {
		name        string
		from        IdentityState
		to          IdentityState
		expectValid bool
	}{
		// Valid transitions
		{"Created -> Active", StateCreated, StateActive, true},
		{"Created -> Deprovisioned", StateCreated, StateDeprovisioned, true},
		{"Active -> Suspended", StateActive, StateSuspended, true},
		{"Active -> Deprovisioned", StateActive, StateDeprovisioned, true},
		{"Suspended -> Active", StateSuspended, StateActive, true},
		{"Suspended -> Deprovisioned", StateSuspended, StateDeprovisioned, true},

		// Invalid transitions
		{"Active -> Created", StateActive, StateCreated, false},
		{"Suspended -> Created", StateSuspended, StateCreated, false},
		{"Deprovisioned -> Active", StateDeprovisioned, StateActive, false},
		{"Deprovisioned -> Suspended", StateDeprovisioned, StateSuspended, false},
		{"Deprovisioned -> Created", StateDeprovisioned, StateCreated, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validStates, ok := ValidStateTransitions[tt.from]
			require.True(t, ok, "From state should exist in transition map")

			found := false
			for _, s := range validStates {
				if s == tt.to {
					found = true
					break
				}
			}

			if tt.expectValid {
				assert.True(t, found, "Transition should be valid")
			} else {
				assert.False(t, found, "Transition should be invalid")
			}
		})
	}
}

func TestLifecycleManager_ValidateTransition(t *testing.T) {
	repo := &MockLifecycleRepository{}
	eventBus := events.NewMemoryBus()
	manager := NewLifecycleManager(repo, zap.NewNop(), eventBus, nil, nil, nil)

	tests := []struct {
		name        string
		from        IdentityState
		to          IdentityState
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid transition: Created -> Active",
			from:        StateCreated,
			to:          StateActive,
			expectError: false,
		},
		{
			name:        "Valid transition: Active -> Suspended",
			from:        StateActive,
			to:          StateSuspended,
			expectError: false,
		},
		{
			name:        "Valid transition: Suspended -> Active",
			from:        StateSuspended,
			to:          StateActive,
			expectError: false,
		},
		{
			name:        "Valid transition: Active -> Deprovisioned",
			from:        StateActive,
			to:          StateDeprovisioned,
			expectError: false,
		},
		{
			name:        "Invalid transition: Active -> Created",
			from:        StateActive,
			to:          StateCreated,
			expectError: true,
			errorMsg:    "invalid state transition",
		},
		{
			name:        "Invalid transition: Deprovisioned -> Active",
			from:        StateDeprovisioned,
			to:          StateActive,
			expectError: true,
			errorMsg:    "invalid state transition",
		},
		{
			name:        "Same state transition",
			from:        StateActive,
			to:          StateActive,
			expectError: true,
			errorMsg:    "already in state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.ValidateTransition(tt.from, tt.to)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLifecycleManager_TransitionState_ValidTransitions(t *testing.T) {
	tests := []struct {
		name            string
		initialState    IdentityState
		targetState     IdentityState
		expectedActions []string
	}{
		{
			name:         "Created -> Active: sends welcome email",
			initialState: StateCreated,
			targetState:  StateActive,
			expectedActions: []string{
				"welcome_email_sent",
				"status_activated",
			},
		},
		{
			name:         "Active -> Suspended: revokes sessions",
			initialState: StateActive,
			targetState:  StateSuspended,
			expectedActions: []string{
				"sessions_revoked",
				"login_disabled",
			},
		},
		{
			name:         "Suspended -> Active: reactivates",
			initialState: StateSuspended,
			targetState:  StateActive,
			expectedActions: []string{
				"status_activated",
			},
		},
		{
			name:         "Active -> Deprovisioned: removes access",
			initialState: StateActive,
			targetState:  StateDeprovisioned,
			expectedActions: []string{
				"sessions_revoked",
				"access_removed",
				"pii_anonymization_scheduled",
			},
		},
		{
			name:         "Suspended -> Deprovisioned: removes access",
			initialState: StateSuspended,
			targetState:  StateDeprovisioned,
			expectedActions: []string{
				"sessions_revoked",
				"access_removed",
				"pii_anonymization_scheduled",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &MockLifecycleRepository{
				user: &User{
					ID:        uuid.New().String(),
					UserName:  "testuser",
					Active:    true,
					Enabled:   true,
					Emails:    []Email{{Value: "test@example.com"}},
					Attributes: make(map[string]string),
				},
			}
			repo.user.SetState(tt.initialState)

			sessionRevoker := &MockSessionRevoker{}
			emailService := &MockEmailService{}

			eventBus := events.NewMemoryBus()
			manager := NewLifecycleManager(repo, zap.NewNop(), eventBus, nil, emailService, sessionRevoker)

			ctx := context.Background()
			result, err := manager.TransitionState(ctx, repo.user.ID, tt.targetState, "admin", nil)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.True(t, result.Success)
			assert.Equal(t, tt.initialState, result.FromState)
			assert.Equal(t, tt.targetState, result.ToState)
			assert.NotEmpty(t, result.Actions)

			// Check the user was updated
			assert.Equal(t, tt.targetState, repo.user.GetState())

			// Check specific actions based on transition
			if tt.targetState == StateActive && tt.initialState == StateCreated {
				assert.True(t, emailService.welcomeEmailSent, "Welcome email should be sent")
			}

			if tt.targetState == StateSuspended || tt.targetState == StateDeprovisioned {
				assert.True(t, sessionRevoker.sessionsRevoked, "Sessions should be revoked")
				assert.False(t, repo.user.Active, "User should be inactive")
				assert.False(t, repo.user.Enabled, "User should be disabled")
			}

			if tt.targetState == StateActive {
				assert.True(t, repo.user.Active, "User should be active")
				assert.True(t, repo.user.Enabled, "User should be enabled")
			}

			if tt.targetState == StateDeprovisioned {
				assert.Contains(t, repo.user.Attributes, AttributeKeyDeprovisionedAt)
			}
		})
	}
}

func TestLifecycleManager_TransitionState_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name         string
		initialState IdentityState
		targetState  IdentityState
		errorMsg     string
	}{
		{
			name:         "Active -> Created is invalid",
			initialState: StateActive,
			targetState:  StateCreated,
			errorMsg:     "invalid state transition",
		},
		{
			name:         "Deprovisioned -> Active is invalid",
			initialState: StateDeprovisioned,
			targetState:  StateActive,
			errorMsg:     "invalid state transition",
		},
		{
			name:         "Same state is invalid",
			initialState: StateActive,
			targetState:  StateActive,
			errorMsg:     "already in state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &MockLifecycleRepository{
				user: &User{
					ID:        uuid.New().String(),
					UserName:  "testuser",
					Active:    true,
					Enabled:   true,
					Attributes: make(map[string]string),
				},
			}
			repo.user.SetState(tt.initialState)

			manager := NewLifecycleManager(repo, zap.NewNop(), events.NewMemoryBus(), nil, nil, nil)

			ctx := context.Background()
			result, err := manager.TransitionState(ctx, repo.user.ID, tt.targetState, "admin", nil)

			require.Error(t, err)
			assert.NotNil(t, result)
			assert.False(t, result.Success)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

func TestLifecycleManager_TransitionState_UserNotFound(t *testing.T) {
	repo := &MockLifecycleRepository{
		user: nil, // User not found
	}

	manager := NewLifecycleManager(repo, zap.NewNop(), events.NewMemoryBus(), nil, nil, nil)

	ctx := context.Background()
	result, err := manager.TransitionState(ctx, "nonexistent", StateActive, "admin", nil)

	require.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "nonexistent", result.UserID)
}

func TestLifecycleManager_AnonymizeUser(t *testing.T) {
	tests := []struct {
		name               string
		userState          IdentityState
		deprovisionedDaysAgo int
		retentionDays      int
		expectError        bool
		errorMsg           string
		verifyAnonymized   bool
	}{
		{
			name:               "Successfully anonymize after retention period",
			userState:          StateDeprovisioned,
			deprovisionedDaysAgo: 90,
			retentionDays:      90,
			expectError:        false,
			verifyAnonymized:   true,
		},
		{
			name:               "Retention period not yet expired",
			userState:          StateDeprovisioned,
			deprovisionedDaysAgo: 30,
			retentionDays:      90,
			expectError:        true,
			errorMsg:           "retention period not expired",
			verifyAnonymized:   false,
		},
		{
			name:               "Cannot anonymize active user",
			userState:          StateActive,
			deprovisionedDaysAgo: 0,
			retentionDays:      90,
			expectError:        true,
			errorMsg:           "must be deprovisioned",
			verifyAnonymized:   false,
		},
		{
			name:               "Cannot anonymize suspended user",
			userState:          StateSuspended,
			deprovisionedDaysAgo: 0,
			retentionDays:      90,
			expectError:        true,
			errorMsg:           "must be deprovisioned",
			verifyAnonymized:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{
				ID:        uuid.New().String(),
				UserName:  "realuser",
				Emails:    []Email{{Value: "real@example.com"}},
				Name:      &Name{GivenName: stringPtr("Real"), FamilyName: stringPtr("User")},
				PhoneNumbers: []PhoneNumber{{Value: "+1234567890"}},
				Attributes: make(map[string]string),
			}
			user.SetState(tt.userState)

			// Set deprovisioned timestamp
			if tt.userState == StateDeprovisioned {
				deprovisionedAt := time.Now().AddDate(0, 0, -tt.deprovisionedDaysAgo)
				user.Attributes[AttributeKeyDeprovisionedAt] = deprovisionedAt.UTC().Format(time.RFC3339)
			}

			repo := &MockLifecycleRepository{user: user}
			manager := NewLifecycleManager(repo, zap.NewNop(), events.NewMemoryBus(), nil, nil, nil)
			manager.SetRetentionDays(tt.retentionDays)

			ctx := context.Background()
			err := manager.AnonymizeUser(ctx, user.ID)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}

			if tt.verifyAnonymized {
				// Verify PII was anonymized
				assert.Contains(t, user.UserName, "anon_")
				assert.Contains(t, user.GetPrimaryEmail(), "anon_")
				assert.Equal(t, "Anonymous", user.GetFirstName())
				assert.Equal(t, "User", user.GetLastName())
				assert.Nil(t, user.PhoneNumbers)
				assert.Nil(t, user.PasswordHash)
				assert.Contains(t, user.Attributes, "anonymized_at")
			}
		})
	}
}

func TestLifecycleManager_BatchTransition(t *testing.T) {
	// Create test users
	user1 := &User{
		ID:        uuid.New().String(),
		UserName:  "user1",
		Emails:    []Email{{Value: "user1@example.com"}},
		Active:    true,
		Attributes: make(map[string]string),
	}
	user1.SetState(StateActive)

	user2 := &User{
		ID:        uuid.New().String(),
		UserName:  "user2",
		Emails:    []Email{{Value: "user2@example.com"}},
		Active:    true,
		Attributes: make(map[string]string),
	}
	user2.SetState(StateActive)

	user3 := &User{
		ID:        uuid.New().String(),
		UserName:  "user3",
		Emails:    []Email{{Value: "user3@example.com"}},
		Active:    true,
		Attributes: make(map[string]string),
	}
	user3.SetState(StateDeprovisioned) // This one should fail

	repo := &MockLifecycleRepository{users: map[string]*User{
		user1.ID: user1,
		user2.ID: user2,
		user3.ID: user3,
	}}

	sessionRevoker := &MockSessionRevoker{}
	manager := NewLifecycleManager(repo, zap.NewNop(), events.NewMemoryBus(), nil, nil, sessionRevoker)

	ctx := context.Background()
	userIDs := []string{user1.ID, user2.ID, user3.ID}
	reason := stringPtr("Bulk suspension")

	results, err := manager.BatchTransition(ctx, userIDs, StateSuspended, "admin", reason)

	require.NoError(t, err)
	require.Len(t, results, 3)

	// Two should succeed, one should fail
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}
	assert.Equal(t, 2, successCount)
}

func TestLifecycleManager_CanLogin(t *testing.T) {
	tests := []struct {
		name        string
		userState   IdentityState
		active      bool
		enabled     bool
		lockedUntil *time.Time
		canLogin    bool
	}{
		{
			name:     "Active user can login",
			userState: StateActive,
			active:   true,
			enabled:  true,
			canLogin: true,
		},
		{
			name:     "Suspended user cannot login",
			userState: StateSuspended,
			active:   false,
			enabled:  false,
			canLogin: false,
		},
		{
			name:     "Deprovisioned user cannot login",
			userState: StateDeprovisioned,
			active:   false,
			enabled:  false,
			canLogin: false,
		},
		{
			name:     "Created user cannot login (not activated)",
			userState: StateCreated,
			active:   true,
			enabled:  true,
			canLogin: false, // Created users must transition to Active before login
		},
		{
			name:     "Locked user cannot login",
			userState: StateActive,
			active:   true,
			enabled:  true,
			lockedUntil: timePtr(time.Now().Add(1 * time.Hour)),
			canLogin: false,
		},
		{
			name:     "Expired lock user can login",
			userState: StateActive,
			active:   true,
			enabled:  true,
			lockedUntil: timePtr(time.Now().Add(-1 * time.Hour)),
			canLogin: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{
				ID:        uuid.New().String(),
				UserName:  "testuser",
				Active:    tt.active,
				Enabled:   tt.enabled,
				LockedUntil: tt.lockedUntil,
				Attributes: make(map[string]string),
			}
			user.SetState(tt.userState)

			repo := &MockLifecycleRepository{user: user}
			manager := NewLifecycleManager(repo, zap.NewNop(), events.NewMemoryBus(), nil, nil, nil)

			ctx := context.Background()
			canLogin, err := manager.CanLogin(ctx, user.ID)

			require.NoError(t, err)
			assert.Equal(t, tt.canLogin, canLogin)
		})
	}
}

func TestLifecycleManager_EvaluatePolicy(t *testing.T) {
	tests := []struct {
		name               string
		policy             *LifecyclePolicy
		user               *User
		expectedTransitions []IdentityState
	}{
		{
			name: "No policy - no transitions",
			policy: &LifecyclePolicy{
				Enabled: false,
			},
			user: &User{
				Attributes: make(map[string]string),
			},
			expectedTransitions: nil,
		},
		{
			name: "Inactive user should be suspended",
			policy: &LifecyclePolicy{
				Enabled: true,
				AutoSuspend: &AutoSuspendPolicy{
					Enabled:      true,
					InactiveDays: 30,
				},
			},
			user: &User{
				LastLoginAt: timePtr(time.Now().AddDate(0, 0, -35)),
				Attributes:  make(map[string]string),
			},
			expectedTransitions: []IdentityState{StateSuspended},
		},
		{
			name: "Recently active user should not be suspended",
			policy: &LifecyclePolicy{
				Enabled: true,
				AutoSuspend: &AutoSuspendPolicy{
					Enabled:      true,
					InactiveDays: 30,
				},
			},
			user: &User{
				LastLoginAt: timePtr(time.Now().AddDate(0, 0, -10)),
				Attributes:  make(map[string]string),
			},
			expectedTransitions: nil,
		},
		{
			name: "User with too many failed logins should be suspended",
			policy: &LifecyclePolicy{
				Enabled: true,
				AutoSuspend: &AutoSuspendPolicy{
					Enabled:              true,
					FailedLoginThreshold: 5,
				},
			},
			user: &User{
				FailedLoginCount: 7,
				Attributes:       make(map[string]string),
			},
			expectedTransitions: []IdentityState{StateSuspended},
		},
		{
			name: "Long-suspended user should be deprovisioned",
			policy: &LifecyclePolicy{
				Enabled: true,
				AutoDeprovision: &AutoDeprovisionPolicy{
					Enabled:       true,
					SuspendedDays: 90,
				},
			},
			user: &User{
				Attributes: make(map[string]string),
			},
			expectedTransitions: []IdentityState{StateDeprovisioned},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set user state
			if tt.policy != nil && tt.policy.AutoDeprovision != nil && tt.policy.AutoDeprovision.Enabled {
				tt.user.SetState(StateSuspended)
				// Set state since to more than SuspendedDays ago
				since := time.Now().AddDate(0, 0, -95)
				tt.user.Attributes[AttributeKeyStateSince] = since.UTC().Format(time.RFC3339)
			} else {
				tt.user.SetState(StateActive)
			}

			repo := &MockLifecycleRepository{user: tt.user}
			manager := NewLifecycleManager(repo, zap.NewNop(), events.NewMemoryBus(), nil, nil, nil)

			ctx := context.Background()
			transitions, err := manager.EvaluatePolicy(ctx, tt.policy, tt.user)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedTransitions, transitions)
		})
	}
}

func TestNewLifecycleAuditLog(t *testing.T) {
	transition := StateTransition{
		Timestamp: time.Now(),
		From:      StateCreated,
		To:        StateActive,
		Actor:     "admin",
	}
	reason := stringPtr("User activated")

	log := NewLifecycleAuditLog("user123", "admin", transition, reason)

	assert.NotEmpty(t, log.ID)
	assert.Equal(t, "user123", log.UserID)
	assert.Equal(t, transition, log.Transition)
	assert.Equal(t, reason, log.Reason)
	assert.Equal(t, "admin", log.PerformedBy)
	assert.WithinDuration(t, time.Now(), log.Timestamp, 1*time.Second)
}

// Mock implementations for testing

type MockLifecycleRepository struct {
	user  *User
	users map[string]*User
}

func (m *MockLifecycleRepository) GetUser(ctx context.Context, id string) (*User, error) {
	if m.user != nil && m.user.ID == id {
		return m.user, nil
	}
	if m.users != nil {
		if u, ok := m.users[id]; ok {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *MockLifecycleRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) UpdateUser(ctx context.Context, user *User) error {
	if m.user != nil && m.user.ID == user.ID {
		m.user = user
	}
	if m.users != nil {
		m.users[user.ID] = user
	}
	return nil
}

func (m *MockLifecycleRepository) CreateUser(ctx context.Context, user *User) error {
	if m.users == nil {
		m.users = make(map[string]*User)
	}
	m.users[user.ID] = user
	return nil
}

func (m *MockLifecycleRepository) DeleteUser(ctx context.Context, id string) error {
	return nil
}

func (m *MockLifecycleRepository) ListUsers(ctx context.Context, filter UserFilter) (*ListResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) ListUsersByGroup(ctx context.Context, groupID string, filter UserFilter) (*ListResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) CreateGroup(ctx context.Context, group *Group) error {
	return nil
}

func (m *MockLifecycleRepository) GetGroup(ctx context.Context, id string) (*Group, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) GetGroupByDisplayName(ctx context.Context, displayName string) (*Group, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) GetGroupByExternalID(ctx context.Context, externalID string) (*Group, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) UpdateGroup(ctx context.Context, group *Group) error {
	return nil
}

func (m *MockLifecycleRepository) DeleteGroup(ctx context.Context, id string) error {
	return nil
}

func (m *MockLifecycleRepository) ListGroups(ctx context.Context, filter GroupFilter) (*ListResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) ListGroupsByUser(ctx context.Context, userID string, filter GroupFilter) (*ListResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) AddGroupMember(ctx context.Context, groupID, userID string) error {
	return nil
}

func (m *MockLifecycleRepository) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	return nil
}

func (m *MockLifecycleRepository) CreateOrganization(ctx context.Context, org *Organization) error {
	return nil
}

func (m *MockLifecycleRepository) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) GetOrganizationByName(ctx context.Context, name string) (*Organization, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) GetOrganizationByExternalID(ctx context.Context, externalID string) (*Organization, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) UpdateOrganization(ctx context.Context, org *Organization) error {
	return nil
}

func (m *MockLifecycleRepository) DeleteOrganization(ctx context.Context, id string) error {
	return nil
}

func (m *MockLifecycleRepository) ListOrganizations(ctx context.Context, filter OrganizationFilter) (*ListResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockLifecycleRepository) Ping(ctx context.Context) error {
	return nil
}

type MockSessionRevoker struct {
	sessionsRevoked bool
}

func (m *MockSessionRevoker) RevokeAllUserSessions(ctx context.Context, userID string) error {
	m.sessionsRevoked = true
	return nil
}

type MockEmailService struct {
	welcomeEmailSent bool
}

func (m *MockEmailService) SendWelcomeEmail(ctx context.Context, to, userName string) error {
	m.welcomeEmailSent = true
	return nil
}

// Helper functions for tests
func timePtr(t time.Time) *time.Time {
	return &t
}
