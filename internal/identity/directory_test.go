// Package identity provides tests for directory synchronization
package identity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/events"
)

func TestDefaultLDAPConfig(t *testing.T) {
	config := DefaultLDAPConfig()

	assert.Equal(t, 389, config.Port, "Default port should be 389")
	assert.False(t, config.UseTLS, "UseTLS should be false by default")
	assert.False(t, config.UseStartTLS, "UseStartTLS should be false by default")
	assert.Equal(t, "(objectClass=person)", config.UserFilter, "User filter should be set")
	assert.Equal(t, "(objectClass=group)", config.GroupFilter, "Group filter should be set")
	assert.Equal(t, 30*time.Second, config.Timeout, "Timeout should be 30 seconds")
}

func TestDefaultAttributeMapping(t *testing.T) {
	mapping := DefaultAttributeMapping()

	assert.Equal(t, "uid", mapping.Username, "Username should map to uid")
	assert.Equal(t, "mail", mapping.Email, "Email should map to mail")
	assert.Equal(t, "givenName", mapping.FirstName, "FirstName should map to givenName")
	assert.Equal(t, "sn", mapping.LastName, "LastName should map to sn")
	assert.Equal(t, "cn", mapping.DisplayName, "DisplayName should map to cn")
	assert.NotNil(t, mapping.CustomAttributes, "CustomAttributes should be initialized")
}

func TestNewDirectory(t *testing.T) {
	dir := NewDirectory("Corporate AD", "active_directory")

	assert.NotEmpty(t, dir.ID, "ID should be generated")
	assert.Equal(t, "Corporate AD", dir.Name, "Name should match")
	assert.Equal(t, "active_directory", dir.Type, "Type should match")
	assert.True(t, dir.Enabled, "Should be enabled by default")
	assert.NotNil(t, dir.Config, "Config should be initialized")
	assert.NotNil(t, dir.AttributeMap, "AttributeMap should be initialized")
	assert.Equal(t, 15*time.Minute, dir.SyncInterval, "Default sync interval should be 15 minutes")
}

func TestLDAPEntryToUser(t *testing.T) {
	tests := []struct {
		name        string
		entry       LDAPEntry
		wantUser    func(*User)
		expectError bool
	}{
		{
			name: "Standard user with all attributes",
			entry: LDAPEntry{
				DN: "uid=jdoe,ou=users,dc=example,dc=com",
				Attributes: map[string][]string{
					"uid":         {"jdoe"},
					"mail":        {"john.doe@example.com"},
					"givenName":   {"John"},
					"sn":          {"Doe"},
					"cn":          {"John Doe"},
					"objectClass": {"person", "inetOrgPerson"},
				},
			},
			wantUser: func(u *User) {
				assert.Equal(t, "jdoe", u.UserName)
				assert.Equal(t, "john.doe@example.com", u.GetPrimaryEmail())
				assert.Equal(t, "John", u.GetFirstName())
				assert.Equal(t, "Doe", u.GetLastName())
				assert.NotNil(t, u.DisplayName)
				assert.Equal(t, "John Doe", *u.DisplayName)
			},
			expectError: false,
		},
		{
			name: "Active Directory user with sAMAccountName",
			entry: LDAPEntry{
				DN: "CN=John Doe,CN=Users,DC=example,DC=com",
				Attributes: map[string][]string{
					"sAMAccountName": {"jdoe"},
					"userPrincipalName": {"jdoe@example.com"},
					"givenName":      {"John"},
					"sn":             {"Doe"},
					"displayName":    {"John Doe"},
				},
			},
			wantUser: func(u *User) {
				// Falls back to sAMAccountName when uid is missing
				assert.Equal(t, "jdoe", u.UserName)
				assert.Equal(t, "John", u.GetFirstName())
				assert.Equal(t, "Doe", u.GetLastName())
			},
			expectError: false,
		},
		{
			name: "User with missing username",
			entry: LDAPEntry{
				DN: "uid=missing,ou=users,dc=example,dc=com",
				Attributes: map[string][]string{
					"mail":      {"test@example.com"},
					"givenName": {"Test"},
				},
			},
			wantUser:    nil,
			expectError: true,
		},
		{
			name: "User with custom attributes",
			entry: LDAPEntry{
				DN: "uid=custom,ou=users,dc=example,dc=com",
				Attributes: map[string][]string{
					"uid":           {"custom"},
					"mail":          {"custom@example.com"},
					"givenName":     {"Custom"},
					"sn":            {"User"},
					"employeeNumber": {"12345"},
				},
			},
			wantUser: func(u *User) {
				assert.Equal(t, "custom", u.UserName)
				assert.NotNil(t, u.Attributes)
				assert.Equal(t, "12345", u.Attributes["employeeNumber"])
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a syncer with default config
			dir := NewDirectory("Test", "ldap")
			client := &MockLDAPClient{}
			repo := &MockSyncRepository{}
			syncer := NewLDAPSyncer(dir, client, repo, zap.NewNop(), events.NewMemoryBus(), nil)

			user, err := syncer.mapLDAPEntryToUser(tt.entry)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)
				tt.wantUser(user)
			}
		})
	}
}

func TestLDAPEntryToGroup(t *testing.T) {
	tests := []struct {
		name        string
		entry       LDAPEntry
		wantGroup   func(*Group)
		expectError bool
	}{
		{
			name: "Standard group",
			entry: LDAPEntry{
				DN: "cn=developers,ou=groups,dc=example,dc=com",
				Attributes: map[string][]string{
					"cn":     {"developers"},
					"member": {"uid=user1,ou=users,dc=example,dc=com", "uid=user2,ou=users,dc=example,dc=com"},
				},
			},
			wantGroup: func(g *Group) {
				assert.Equal(t, "developers", g.DisplayName)
				assert.NotNil(t, g.Attributes)
				assert.Contains(t, g.Attributes, "ldap_members")
			},
			expectError: false,
		},
		{
			name: "Group with missing name",
			entry: LDAPEntry{
				DN: "cn=missing,ou=groups,dc=example,dc=com",
				Attributes: map[string][]string{
					"member": {"uid=user1,ou=users,dc=example,dc=com"},
				},
			},
			wantGroup: func(g *Group) {
				// Should fall back to "cn" as group name
				assert.Equal(t, "missing", g.DisplayName)
			},
			expectError: false,
		},
		{
			name:        "Group with no attributes",
			entry: LDAPEntry{
				DN: "cn=empty,ou=groups,dc=example,dc=com",
				Attributes: map[string][]string{},
			},
			wantGroup: func(g *Group) {
				// Still creates group with cn from DN
				assert.Equal(t, "empty", g.DisplayName)
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := NewDirectory("Test", "ldap")
			client := &MockLDAPClient{}
			repo := &MockSyncRepository{}
			syncer := NewLDAPSyncer(dir, client, repo, zap.NewNop(), events.NewMemoryBus(), nil)

			group, err := syncer.mapLDAPEntryToGroup(tt.entry)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, group)
			} else {
				require.NoError(t, err)
				require.NotNil(t, group)
				tt.wantGroup(group)
			}
		})
	}
}

func TestLDAPSyncer_SyncUsers(t *testing.T) {
	tests := []struct {
		name          string
		entries       []LDAPEntry
		existingUsers map[string]*User // Pre-existing users in the repo
		wantResult    func(*testing.T, *DirectorySyncResult)
		expectError   bool
	}{
		{
			name: "Sync new users",
			entries: []LDAPEntry{
				{
					DN: "uid=jdoe,ou=users,dc=example,dc=com",
					Attributes: map[string][]string{
						"uid":       {"jdoe"},
						"mail":      {"john.doe@example.com"},
						"givenName": {"John"},
						"sn":        {"Doe"},
					},
				},
				{
					DN: "uid=asmith,ou=users,dc=example,dc=com",
					Attributes: map[string][]string{
						"uid":       {"asmith"},
						"mail":      {"alice.smith@example.com"},
						"givenName": {"Alice"},
						"sn":        {"Smith"},
					},
				},
			},
			existingUsers: map[string]*User{},
			wantResult: func(t *testing.T, r *DirectorySyncResult) {
				assert.Equal(t, SyncStatusCompleted, r.Status)
				assert.Equal(t, 2, r.UsersCreated)
				assert.Equal(t, 0, r.UsersUpdated)
				assert.Equal(t, 0, r.UsersFailed)
			},
			expectError: false,
		},
		{
			name: "Sync with existing users - should update",
			entries: []LDAPEntry{
				{
					DN: "uid=jdoe,ou=users,dc=example,dc=com",
					Attributes: map[string][]string{
						"uid":       {"jdoe"},
						"mail":      {"john.doe.updated@example.com"},
						"givenName": {"John"},
						"sn":        {"Doe"},
					},
				},
			},
			existingUsers: map[string]*User{
				"jdoe": {
					ID:       uuid.New().String(),
					UserName: "jdoe",
					Emails:   []Email{{Value: "john.doe@example.com"}},
					Active:   true,
					Enabled:  true,
				},
			},
			wantResult: func(t *testing.T, r *DirectorySyncResult) {
				assert.Equal(t, SyncStatusCompleted, r.Status)
				assert.Equal(t, 0, r.UsersCreated)
				assert.Equal(t, 1, r.UsersUpdated)
			},
			expectError: false,
		},
		{
			name: "Sync with invalid entry - should skip",
			entries: []LDAPEntry{
				{
					DN: "uid=invalid,ou=users,dc=example,dc=com",
					Attributes: map[string][]string{
						"mail":      {"invalid@example.com"},
						"givenName": {"Invalid"},
					},
				},
			},
			existingUsers: map[string]*User{},
			wantResult: func(t *testing.T, r *DirectorySyncResult) {
				assert.Equal(t, SyncStatusCompleted, r.Status)
				assert.Equal(t, 0, r.UsersCreated)
				assert.Equal(t, 1, r.UsersFailed)
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := NewDirectory("Test", "ldap")
			client := &MockLDAPClient{Entries: tt.entries}
			repo := &MockSyncRepository{users: tt.existingUsers}
			eventBus := events.NewMemoryBus()
			syncer := NewLDAPSyncer(dir, client, repo, zap.NewNop(), eventBus, nil)

			ctx := context.Background()
			result, err := syncer.SyncUsers(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				tt.wantResult(t, result)
			}
		})
	}
}

func TestLDAPSyncer_SyncUsersIncremental(t *testing.T) {
	entries := []LDAPEntry{
		{
			DN: "uid=jdoe,ou=users,dc=example,dc=com",
			Attributes: map[string][]string{
				"uid":       {"jdoe"},
				"mail":      {"john.doe@example.com"},
				"givenName": {"John"},
				"sn":        {"Doe"},
			},
		},
	}

	dir := NewDirectory("Test", "ldap")
	client := &MockLDAPClient{Entries: entries}
	repo := &MockSyncRepository{users: make(map[string]*User)}
	syncer := NewLDAPSyncer(dir, client, repo, zap.NewNop(), events.NewMemoryBus(), nil)

	ctx := context.Background()

	// First sync with no previous sync should fall back to full sync
	result, err := syncer.SyncUsersIncremental(ctx)
	require.NoError(t, err)
	assert.Equal(t, SyncStatusCompleted, result.Status)

	// Second sync with a timestamp should use incremental
	lastSync := time.Now().Add(-1 * time.Hour)
	dir.LastSyncAt = &lastSync
	result, err = syncer.SyncUsersIncremental(ctx)
	require.NoError(t, err)
	assert.Equal(t, SyncStatusCompleted, result.Status)
}

func TestLDAPSyncer_TestConnection(t *testing.T) {
	tests := []struct {
		name         string
		connectError error
		expectError  bool
	}{
		{
			name:         "Successful connection",
			connectError: nil,
			expectError:  false,
		},
		{
			name:         "Connection failure",
			connectError: assert.AnError,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := NewDirectory("Test", "ldap")
			client := &MockLDAPClient{ConnectError: tt.connectError}
			repo := &MockSyncRepository{}
			syncer := NewLDAPSyncer(dir, client, repo, zap.NewNop(), events.NewMemoryBus(), nil)

			ctx := context.Background()
			err := syncer.TestConnection(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLDAPSyncer_SyncGroups(t *testing.T) {
	entries := []LDAPEntry{
		{
			DN: "cn=developers,ou=groups,dc=example,dc=com",
			Attributes: map[string][]string{
				"cn":     {"developers"},
				"member": {"uid=user1,ou=users,dc=example,dc=com"},
			},
		},
		{
			DN: "cn=admins,ou=groups,dc=example,dc=com",
			Attributes: map[string][]string{
				"cn":     {"admins"},
				"member": {"uid=admin1,ou=users,dc=example,dc=com"},
			},
		},
	}

	dir := NewDirectory("Test", "ldap")
	client := &MockLDAPClient{Entries: entries}
	repo := &MockSyncRepository{groups: make(map[string]*Group)}
	syncer := NewLDAPSyncer(dir, client, repo, zap.NewNop(), events.NewMemoryBus(), nil)

	ctx := context.Background()
	result, err := syncer.SyncGroups(ctx)

	require.NoError(t, err)
	assert.Equal(t, SyncStatusCompleted, result.Status)
	assert.Equal(t, 2, result.GroupsCreated)
	assert.Equal(t, 0, result.GroupsUpdated)
}

func TestLDAPSyncer_SyncAll(t *testing.T) {
	userEntries := []LDAPEntry{
		{
			DN: "uid=jdoe,ou=users,dc=example,dc=com",
			Attributes: map[string][]string{
				"uid":       {"jdoe"},
				"mail":      {"john.doe@example.com"},
				"givenName": {"John"},
				"sn":        {"Doe"},
			},
		},
	}

	groupEntries := []LDAPEntry{
		{
			DN: "cn=developers,ou=groups,dc=example,dc=com",
			Attributes: map[string][]string{
				"cn": {"developers"},
			},
		},
	}

	dir := NewDirectory("Test", "ldap")
	// Create a client that returns different entries based on search type
	client := &MockLDAPClient{Entries: userEntries}
	repo := &MockSyncRepository{
		users:  make(map[string]*User),
		groups: make(map[string]*Group),
	}
	syncer := NewLDAPSyncer(dir, client, repo, zap.NewNop(), events.NewMemoryBus(), nil)

	// Update mock to return group entries for second call
	originalSearchGroups := client.SearchGroups
	client.SearchGroups = func(ctx context.Context, baseDN, filter string, attrs []string) ([]LDAPEntry, error) {
		return groupEntries, nil
	}
	defer func() {
		client.SearchGroups = originalSearchGroups
	}()

	ctx := context.Background()
	result, err := syncer.SyncAll(ctx)

	require.NoError(t, err)
	assert.Equal(t, SyncStatusCompleted, result.Status)
	assert.Equal(t, 1, result.UsersCreated)
	assert.Equal(t, 1, result.GroupsCreated)
	assert.NotNil(t, result.CompletedAt)
}

func TestBuildUserAttributeList(t *testing.T) {
	dir := NewDirectory("Test", "ldap")
	dir.AttributeMap = DefaultAttributeMapping()
	dir.AttributeMap.CustomAttributes = map[string]string{
		"employeeId":   "employeeId",
		"costCenter":   "costCenter",
	}

	client := &MockLDAPClient{}
	repo := &MockSyncRepository{}
	syncer := NewLDAPSyncer(dir, client, repo, zap.NewNop(), events.NewMemoryBus(), nil)

	attrs := syncer.buildUserAttributeList()

	assert.Contains(t, attrs, "dn")
	assert.Contains(t, attrs, "uid")
	assert.Contains(t, attrs, "mail")
	assert.Contains(t, attrs, "givenName")
	assert.Contains(t, attrs, "sn")
	assert.Contains(t, attrs, "cn")
	assert.Contains(t, attrs, "employeeId")
	assert.Contains(t, attrs, "costCenter")
}

// MockSyncRepository is a mock repository for sync testing
type MockSyncRepository struct {
	users  map[string]*User
	groups map[string]*Group
}

func (m *MockSyncRepository) CreateUser(ctx context.Context, user *User) error {
	if m.users == nil {
		m.users = make(map[string]*User)
	}
	m.users[user.UserName] = user
	return nil
}

func (m *MockSyncRepository) GetUser(ctx context.Context, id string) (*User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, assert.AnError
}

func (m *MockSyncRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	if u, ok := m.users[username]; ok {
		return u, nil
	}
	return nil, assert.AnError
}

func (m *MockSyncRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	for _, u := range m.users {
		if u.GetPrimaryEmail() == email {
			return u, nil
		}
	}
	return nil, assert.AnError
}

func (m *MockSyncRepository) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	return nil, assert.AnError
}

func (m *MockSyncRepository) UpdateUser(ctx context.Context, user *User) error {
	if m.users == nil {
		m.users = make(map[string]*User)
	}
	m.users[user.UserName] = user
	return nil
}

func (m *MockSyncRepository) DeleteUser(ctx context.Context, id string) error {
	return nil
}

func (m *MockSyncRepository) ListUsers(ctx context.Context, filter UserFilter) (*ListResponse, error) {
	users := make([]*User, 0, len(m.users))
	for _, u := range m.users {
		users = append(users, u)
	}
	return &ListResponse{Resources: users, TotalResults: len(users)}, nil
}

func (m *MockSyncRepository) ListUsersByGroup(ctx context.Context, groupID string, filter UserFilter) (*ListResponse, error) {
	return &ListResponse{}, nil
}

func (m *MockSyncRepository) CreateGroup(ctx context.Context, group *Group) error {
	if m.groups == nil {
		m.groups = make(map[string]*Group)
	}
	m.groups[group.DisplayName] = group
	return nil
}

func (m *MockSyncRepository) GetGroup(ctx context.Context, id string) (*Group, error) {
	for _, g := range m.groups {
		if g.ID == id {
			return g, nil
		}
	}
	return nil, assert.AnError
}

func (m *MockSyncRepository) GetGroupByDisplayName(ctx context.Context, displayName string) (*Group, error) {
	if g, ok := m.groups[displayName]; ok {
		return g, nil
	}
	return nil, assert.AnError
}

func (m *MockSyncRepository) GetGroupByExternalID(ctx context.Context, externalID string) (*Group, error) {
	return nil, assert.AnError
}

func (m *MockSyncRepository) UpdateGroup(ctx context.Context, group *Group) error {
	if m.groups == nil {
		m.groups = make(map[string]*Group)
	}
	m.groups[group.DisplayName] = group
	return nil
}

func (m *MockSyncRepository) DeleteGroup(ctx context.Context, id string) error {
	return nil
}

func (m *MockSyncRepository) ListGroups(ctx context.Context, filter GroupFilter) (*ListResponse, error) {
	groups := make([]*Group, 0, len(m.groups))
	for _, g := range m.groups {
		groups = append(groups, g)
	}
	return &ListResponse{Resources: groups, TotalResults: len(groups)}, nil
}

func (m *MockSyncRepository) ListGroupsByUser(ctx context.Context, userID string, filter GroupFilter) (*ListResponse, error) {
	return &ListResponse{}, nil
}

func (m *MockSyncRepository) AddGroupMember(ctx context.Context, groupID, userID string) error {
	return nil
}

func (m *MockSyncRepository) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	return nil
}

func (m *MockSyncRepository) CreateOrganization(ctx context.Context, org *Organization) error {
	return nil
}

func (m *MockSyncRepository) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	return nil, assert.AnError
}

func (m *MockSyncRepository) GetOrganizationByName(ctx context.Context, name string) (*Organization, error) {
	return nil, assert.AnError
}

func (m *MockSyncRepository) GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error) {
	return nil, assert.AnError
}

func (m *MockSyncRepository) GetOrganizationByExternalID(ctx context.Context, externalID string) (*Organization, error) {
	return nil, assert.AnError
}

func (m *MockSyncRepository) UpdateOrganization(ctx context.Context, org *Organization) error {
	return nil
}

func (m *MockSyncRepository) DeleteOrganization(ctx context.Context, id string) error {
	return nil
}

func (m *MockSyncRepository) ListOrganizations(ctx context.Context, filter OrganizationFilter) (*ListResponse, error) {
	return &ListResponse{}, nil
}

func (m *MockSyncRepository) Ping(ctx context.Context) error {
	return nil
}
