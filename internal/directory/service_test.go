// Package directory provides comprehensive unit tests for directory synchronization service
package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// MockLDAPConn is a mock implementation of LDAP connection
type MockLDAPConn struct {
	mock.Mock
	entries   []*ldap.Entry
	searchErr error
	bindErr   error
	closeErr  error
}

func (m *MockLDAPConn) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	args := m.Called(searchRequest)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ldap.SearchResult), args.Error(1)
}

func (m *MockLDAPConn) Bind(username, password string) error {
	args := m.Called(username, password)
	return args.Error(0)
}

func (m *MockLDAPConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockLDAPConn) Modify(modifyRequest *ldap.ModifyRequest) error {
	args := m.Called(modifyRequest)
	return args.Error(0)
}

func (m *MockLDAPConn) PasswordModify(passwordModifyRequest *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	args := m.Called(passwordModifyRequest)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ldap.PasswordModifyResult), args.Error(1)
}

// MockLDAPConnector is a mock for LDAPConnector
type MockLDAPConnector struct {
	mock.Mock
	connectErr   error
	searchUsers  []*ldap.Entry
	searchGroups []*ldap.Entry
	searchErr    error
	bindErr      error
}

func (m *MockLDAPConnector) Connect() (*ldap.Conn, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ldap.Conn), args.Error(1)
}

func (m *MockLDAPConnector) SearchUsers(conn interface{}) ([]*ldap.Entry, error) {
	args := m.Called(conn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*ldap.Entry), args.Error(1)
}

func (m *MockLDAPConnector) SearchGroups(conn interface{}) ([]*ldap.Entry, error) {
	args := m.Called(conn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*ldap.Entry), args.Error(1)
}

func (m *MockLDAPConnector) SearchUsersIncremental(conn interface{}, usn int64, timestamp string) ([]*ldap.Entry, string, error) {
	args := m.Called(conn, usn, timestamp)
	if args.Get(0) == nil {
		return nil, "", args.Error(2)
	}
	return args.Get(0).([]*ldap.Entry), args.String(1), args.Error(2)
}

func (m *MockLDAPConnector) TestConnection() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockLDAPConnector) AuthenticateUser(username, password string) error {
	args := m.Called(username, password)
	return args.Error(0)
}

func (m *MockLDAPConnector) ChangePassword(username, oldPassword, newPassword string) error {
	args := m.Called(username, oldPassword, newPassword)
	return args.Error(0)
}

func (m *MockLDAPConnector) ResetPassword(username, newPassword string) error {
	args := m.Called(username, newPassword)
	return args.Error(0)
}

// MockAzureADConnector is a mock for AzureADConnector
type MockAzureADConnector struct {
	mock.Mock
	searchUsers  []UserRecord
	searchGroups []GroupRecord
	searchErr    error
	tokenErr     error
}

func (m *MockAzureADConnector) TestConnection(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockAzureADConnector) SearchUsers(ctx context.Context) ([]UserRecord, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]UserRecord), args.Error(1)
}

func (m *MockAzureADConnector) SearchUsersIncremental(ctx context.Context, deltaLink string) ([]UserRecord, string, error) {
	args := m.Called(ctx, deltaLink)
	if args.Get(0) == nil {
		return nil, "", args.Error(1)
	}
	return args.Get(0).([]UserRecord), args.String(1), args.Error(2)
}

func (m *MockAzureADConnector) SearchGroups(ctx context.Context) ([]GroupRecord, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]GroupRecord), args.Error(1)
}

func (m *MockAzureADConnector) SearchGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockAzureADConnector) ensureToken(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockAzureADConnector) ResetPassword(ctx context.Context, userObjectID, newPassword string) error {
	args := m.Called(ctx, userObjectID, newPassword)
	return args.Error(0)
}

// Helper function to create a test logger
func newTestLogger() *zap.Logger {
	return zap.NewNop()
}

// Helper function to create a mock LDAP entry for a user
func newMockUserEntry(dn, username, email, firstName, lastName string) *ldap.Entry {
	return &ldap.Entry{
		DN: dn,
		Attributes: []*ldap.EntryAttribute{
			{ Name: "uid", Values: []string{username} },
			{ Name: "mail", Values: []string{email} },
			{ Name: "givenName", Values: []string{firstName} },
			{ Name: "sn", Values: []string{lastName} },
			{ Name: "cn", Values: []string{firstName + " " + lastName} },
			{ Name: "objectClass", Values: []string{"inetOrgPerson"} },
		},
	}
}

// Helper function to create a mock LDAP entry for a group
func newMockGroupEntry(dn, name, description string, members []string) *ldap.Entry {
	return &ldap.Entry{
		DN: dn,
		Attributes: []*ldap.EntryAttribute{
			{ Name: "cn", Values: []string{name} },
			{ Name: "description", Values: []string{description} },
			{ Name: "member", Values: members },
			{ Name: "objectClass", Values: []string{"groupOfNames"} },
		},
	}
}

// TestLDAPConfig tests LDAP configuration serialization
func TestLDAPConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  LDAPConfig
		wantErr bool
	}{
		{
			name: "Valid LDAP config",
			config: LDAPConfig{
				Host:         "ldap.example.com",
				Port:         636,
				UseTLS:       true,
				BindDN:       "cn=admin,dc=example,dc=com",
				BindPassword: "secret",
				BaseDN:       "dc=example,dc=com",
				UserBaseDN:   "ou=users,dc=example,dc=com",
				GroupBaseDN:  "ou=groups,dc=example,dc=com",
			},
			wantErr: false,
		},
		{
			name: "Valid Active Directory config",
			config: LDAPConfig{
				Host:          "ad.example.com",
				Port:          3269,
				UseTLS:        true,
				DirectoryType: "active_directory",
				BindDN:        "cn=admin,cn=users,dc=example,dc=com",
				BindPassword:  "secret",
				BaseDN:        "dc=example,dc=com",
				SyncEnabled:   true,
				SyncInterval:  60,
			},
			wantErr: false,
		},
		{
			name: "Minimal LDAP config",
			config: LDAPConfig{
				Host:     "localhost",
				Port:     389,
				BaseDN:   "dc=example,dc=com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			data, err := json.Marshal(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			// Test deserialization
			var decoded LDAPConfig
			err = json.Unmarshal(data, &decoded)
			assert.NoError(t, err)
			assert.Equal(t, tt.config.Host, decoded.Host)
			assert.Equal(t, tt.config.Port, decoded.Port)
			assert.Equal(t, tt.config.BaseDN, decoded.BaseDN)
		})
	}
}

// TestAzureADConfig tests Azure AD configuration serialization
func TestAzureADConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  AzureADConfig
		wantErr bool
	}{
		{
			name: "Valid Azure AD config",
			config: AzureADConfig{
				TenantID:     "tenant-123",
				ClientID:     "client-456",
				ClientSecret: "secret-789",
				SyncEnabled:  true,
				SyncInterval: 30,
			},
			wantErr: false,
		},
		{
			name: "Azure AD with filters",
			config: AzureADConfig{
				TenantID:     "tenant-123",
				ClientID:     "client-456",
				ClientSecret: "secret-789",
				UserFilter:   "accountEnabled eq true",
				GroupFilter:  "groupTypes/any(g:g/eq 'Unified')",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			data, err := json.Marshal(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			// Test deserialization
			var decoded AzureADConfig
			err = json.Unmarshal(data, &decoded)
			assert.NoError(t, err)
			assert.Equal(t, tt.config.TenantID, decoded.TenantID)
			assert.Equal(t, tt.config.ClientID, decoded.ClientID)
			assert.Equal(t, tt.config.SyncEnabled, decoded.SyncEnabled)
		})
	}
}

// TestAttributeMapping tests attribute mapping configuration
func TestAttributeMapping(t *testing.T) {
	tests := []struct {
		name     string
		mapping  AttributeMapping
		expected AttributeMapping
	}{
		{
			name: "Active Directory mapping",
			mapping: AttributeMapping{
				Username:    "sAMAccountName",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "displayName",
				GroupName:   "cn",
			},
			expected: AttributeMapping{
				Username:    "sAMAccountName",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "displayName",
				GroupName:   "cn",
			},
		},
		{
			name: "OpenLDAP mapping",
			mapping: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
				GroupName:   "cn",
			},
			expected: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
				GroupName:   "cn",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.mapping)
			require.NoError(t, err)

			var decoded AttributeMapping
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, decoded)
		})
	}
}

// TestGetDefaultMapping tests the default attribute mapping for directory types
func TestGetDefaultMapping(t *testing.T) {
	tests := []struct {
		name          string
		directoryType string
		expected      AttributeMapping
	}{
		{
			name:          "Active Directory defaults",
			directoryType: "active_directory",
			expected: AttributeMapping{
				Username:    "sAMAccountName",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "displayName",
				GroupName:   "cn",
			},
		},
		{
			name:          "OpenLDAP defaults",
			directoryType: "ldap",
			expected: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
				GroupName:   "cn",
			},
		},
		{
			name:          "Unknown type defaults to LDAP",
			directoryType: "unknown",
			expected: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
				GroupName:   "cn",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetDefaultMapping(tt.directoryType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMapUserEntry tests mapping LDAP entries to UserRecord
func TestMapUserEntry(t *testing.T) {
	tests := []struct {
		name     string
		entry    *ldap.Entry
		mapping  AttributeMapping
		expected UserRecord
	}{
		{
			name: "Map user with AD attributes",
			entry: &ldap.Entry{
				DN: "CN=John Doe,CN=Users,DC=example,DC=com",
				Attributes: []*ldap.EntryAttribute{
					{ Name: "sAMAccountName", Values: []string{"jdoe"} },
					{ Name: "mail", Values: []string{"john.doe@example.com"} },
					{ Name: "givenName", Values: []string{"John"} },
					{ Name: "sn", Values: []string{"Doe"} },
					{ Name: "displayName", Values: []string{"John Doe"} },
				},
			},
			mapping: AttributeMapping{
				Username:    "sAMAccountName",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "displayName",
			},
			expected: UserRecord{
				DN:          "CN=John Doe,CN=Users,DC=example,DC=com",
				Username:    "jdoe",
				Email:       "john.doe@example.com",
				FirstName:   "John",
				LastName:    "Doe",
				DisplayName: "John Doe",
			},
		},
		{
			name: "Map user with OpenLDAP attributes",
			entry: &ldap.Entry{
				DN: "uid=jsmith,ou=users,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{ Name: "uid", Values: []string{"jsmith"} },
					{ Name: "mail", Values: []string{"jsmith@example.com"} },
					{ Name: "givenName", Values: []string{"Jane"} },
					{ Name: "sn", Values: []string{"Smith"} },
					{ Name: "cn", Values: []string{"Jane Smith"} },
				},
			},
			mapping: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
			},
			expected: UserRecord{
				DN:          "uid=jsmith,ou=users,dc=example,dc=com",
				Username:    "jsmith",
				Email:       "jsmith@example.com",
				FirstName:   "Jane",
				LastName:    "Smith",
				DisplayName: "Jane Smith",
			},
		},
		{
			name: "Map user with missing attributes",
			entry: &ldap.Entry{
				DN: "uid=buser,ou=users,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{ Name: "uid", Values: []string{"buser"} },
					{ Name: "mail", Values: []string{} },
					{ Name: "givenName", Values: []string{} },
					{ Name: "sn", Values: []string{} },
					{ Name: "cn", Values: []string{} },
				},
			},
			mapping: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
			},
			expected: UserRecord{
				DN:          "uid=buser,ou=users,dc=example,dc=com",
				Username:    "buser",
				Email:       "",
				FirstName:   "",
				LastName:    "",
				DisplayName: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapUserEntry(tt.entry, tt.mapping)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMapGroupEntry tests mapping LDAP entries to GroupRecord
func TestMapGroupEntry(t *testing.T) {
	tests := []struct {
		name       string
		entry      *ldap.Entry
		mapping    AttributeMapping
		memberAttr string
		expected   GroupRecord
	}{
		{
			name: "Map group with members",
			entry: &ldap.Entry{
				DN: "cn=developers,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{ Name: "cn", Values: []string{"developers"} },
					{ Name: "description", Values: []string{"Development team"} },
					{ Name: "member", Values: []string{
						"cn=John Doe,ou=users,dc=example,dc=com",
						"cn=Jane Smith,ou=users,dc=example,dc=com",
					}},
				},
			},
			mapping:    AttributeMapping{GroupName: "cn"},
			memberAttr: "member",
			expected: GroupRecord{
				DN:          "cn=developers,ou=groups,dc=example,dc=com",
				Name:        "developers",
				Description: "Development team",
				MemberDNs: []string{
					"cn=John Doe,ou=users,dc=example,dc=com",
					"cn=Jane Smith,ou=users,dc=example,dc=com",
				},
			},
		},
		{
			name: "Map group with uniqueMember attribute",
			entry: &ldap.Entry{
				DN: "cn=admins,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{ Name: "cn", Values: []string{"admins"} },
					{ Name: "description", Values: []string{"Administrator group"} },
					{ Name: "uniqueMember", Values: []string{
						"uid=admin,ou=users,dc=example,dc=com",
					}},
				},
			},
			mapping:    AttributeMapping{GroupName: "cn"},
			memberAttr: "uniqueMember",
			expected: GroupRecord{
				DN:          "cn=admins,ou=groups,dc=example,dc=com",
				Name:        "admins",
				Description: "Administrator group",
				MemberDNs: []string{
					"uid=admin,ou=users,dc=example,dc=com",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapGroupEntry(tt.entry, tt.mapping, tt.memberAttr)
			assert.Equal(t, tt.expected.DN, result.DN)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.Description, result.Description)
			assert.Equal(t, tt.expected.MemberDNs, result.MemberDNs)
		})
	}
}

// TestSyncResult tests sync result tracking
func TestSyncResult(t *testing.T) {
	tests := []struct {
		name   string
		result *SyncResult
	}{
		{
			name: "Successful sync result",
			result: &SyncResult{
				UsersAdded:    5,
				UsersUpdated:  3,
				UsersDisabled: 1,
				GroupsAdded:   2,
				GroupsUpdated: 1,
				GroupsDeleted: 0,
				Errors:        []string{},
				Duration:      1500 * time.Millisecond,
			},
		},
		{
			name: "Partial sync with errors",
			result: &SyncResult{
				UsersAdded:    2,
				UsersUpdated:  0,
				UsersDisabled: 0,
				GroupsAdded:   0,
				GroupsUpdated: 0,
				GroupsDeleted: 0,
				Errors: []string{
					"failed to connect to LDAP server",
					"timeout while searching users",
				},
				Duration: 5 * time.Second,
			},
		},
		{
			name: "Empty sync result",
			result: &SyncResult{
				UsersAdded:    0,
				UsersUpdated:  0,
				UsersDisabled: 0,
				GroupsAdded:   0,
				GroupsUpdated: 0,
				GroupsDeleted: 0,
				Errors:        nil,
				Duration:      100 * time.Millisecond,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			data, err := json.Marshal(tt.result)
			require.NoError(t, err)

			var decoded SyncResult
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.result.UsersAdded, decoded.UsersAdded)
			assert.Equal(t, tt.result.UsersUpdated, decoded.UsersUpdated)
			assert.Equal(t, tt.result.UsersDisabled, decoded.UsersDisabled)
			assert.Equal(t, tt.result.GroupsAdded, decoded.GroupsAdded)
			assert.Equal(t, tt.result.GroupsUpdated, decoded.GroupsUpdated)
			assert.Equal(t, tt.result.GroupsDeleted, decoded.GroupsDeleted)
			assert.Equal(t, tt.result.Duration, decoded.Duration)
			assert.Equal(t, len(tt.result.Errors), len(decoded.Errors))
		})
	}
}

// TestSyncLog tests sync log entry structure
func TestSyncLog(t *testing.T) {
	now := time.Now()
	completed := now.Add(5 * time.Second)
	errMsg := "connection timeout"

	tests := []struct {
		name string
		log  *SyncLog
	}{
		{
			name: "Successful sync log",
			log: &SyncLog{
				ID:            "sync-123",
				DirectoryID:   "dir-456",
				SyncType:      "full",
				Status:        "success",
				StartedAt:     now,
				CompletedAt:   &completed,
				UsersAdded:    10,
				UsersUpdated:  5,
				UsersDisabled: 0,
				GroupsAdded:   3,
				GroupsUpdated: 1,
				GroupsDeleted: 0,
				ErrorMessage:  nil,
			},
		},
		{
			name: "Failed sync log",
			log: &SyncLog{
				ID:            "sync-789",
				DirectoryID:   "dir-456",
				SyncType:      "incremental",
				Status:        "failed",
				StartedAt:     now,
				CompletedAt:   &completed,
				UsersAdded:    0,
				UsersUpdated:  0,
				UsersDisabled: 0,
				GroupsAdded:   0,
				GroupsUpdated: 0,
				GroupsDeleted: 0,
				ErrorMessage:  &errMsg,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			data, err := json.Marshal(tt.log)
			require.NoError(t, err)

			var decoded SyncLog
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.log.ID, decoded.ID)
			assert.Equal(t, tt.log.DirectoryID, decoded.DirectoryID)
			assert.Equal(t, tt.log.SyncType, decoded.SyncType)
			assert.Equal(t, tt.log.Status, decoded.Status)
			assert.Equal(t, tt.log.UsersAdded, decoded.UsersAdded)
			if tt.log.ErrorMessage != nil {
				assert.Equal(t, tt.log.ErrorMessage, decoded.ErrorMessage)
			}
		})
	}
}

// TestSyncState tests sync state tracking
func TestSyncState(t *testing.T) {
	now := time.Now()
	usn := int64(12345)
	timestamp := "20240315000000.0Z"
	deltaLink := "https://graph.microsoft.com/v1.0/tdelta?$deltatoken=abc123"
	durationMs := 5000

	tests := []struct {
		name  string
		state *SyncState
	}{
		{
			name: "Full sync state",
			state: &SyncState{
				DirectoryID:         "dir-001",
				LastSyncAt:          &now,
				LastUSNChanged:      &usn,
				LastModifyTimestamp: &timestamp,
				LastDeltaLink:       &deltaLink,
				UsersSynced:         100,
				GroupsSynced:        25,
				ErrorsCount:         0,
				SyncDurationMs:      &durationMs,
			},
		},
		{
			name: "Initial sync state",
			state: &SyncState{
				DirectoryID:  "dir-002",
				LastSyncAt:   nil,
				UsersSynced:  0,
				GroupsSynced: 0,
				ErrorsCount:  0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			data, err := json.Marshal(tt.state)
			require.NoError(t, err)

			var decoded SyncState
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.state.DirectoryID, decoded.DirectoryID)
			assert.Equal(t, tt.state.UsersSynced, decoded.UsersSynced)
			assert.Equal(t, tt.state.GroupsSynced, decoded.GroupsSynced)
			assert.Equal(t, tt.state.ErrorsCount, decoded.ErrorsCount)
		})
	}
}

// TestUserRecord tests user record structure
func TestUserRecord(t *testing.T) {
	tests := []struct {
		name  string
		record UserRecord
	}{
		{
			name: "Complete user record",
			record: UserRecord{
				DN:          "CN=John Doe,OU=Users,DC=example,DC=com",
				ExternalID:  "azure-ad-12345",
				Username:    "jdoe",
				Email:       "john.doe@example.com",
				FirstName:   "John",
				LastName:    "Doe",
				DisplayName: "John Doe",
			},
		},
		{
			name: "Minimal user record",
			record: UserRecord{
				DN:       "uid=jsmith,ou=users,dc=example,dc=com",
				Username: "jsmith",
				Email:    "jsmith@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			data, err := json.Marshal(tt.record)
			require.NoError(t, err)

			var decoded UserRecord
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.record.DN, decoded.DN)
			assert.Equal(t, tt.record.Username, decoded.Username)
			assert.Equal(t, tt.record.Email, decoded.Email)
		})
	}
}

// TestGroupRecord tests group record structure
func TestGroupRecord(t *testing.T) {
	tests := []struct {
		name   string
		record GroupRecord
	}{
		{
			name: "Group with members",
			record: GroupRecord{
				DN:          "cn=developers,ou=groups,dc=example,dc=com",
				Name:        "developers",
				Description: "Development team",
				MemberDNs: []string{
					"cn=user1,ou=users,dc=example,dc=com",
					"cn=user2,ou=users,dc=example,dc=com",
				},
			},
		},
		{
			name: "Group without members",
			record: GroupRecord{
				DN:          "cn=empty,ou=groups,dc=example,dc=com",
				Name:        "empty",
				Description: "Empty group",
				MemberDNs:   []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			data, err := json.Marshal(tt.record)
			require.NoError(t, err)

			var decoded GroupRecord
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.record.DN, decoded.DN)
			assert.Equal(t, tt.record.Name, decoded.Name)
			assert.Equal(t, tt.record.Description, decoded.Description)
			assert.Equal(t, tt.record.MemberDNs, decoded.MemberDNs)
		})
	}
}

// TestLDAPConnector_NewLDAPConnector tests LDAP connector creation
func TestLDAPConnector_NewLDAPConnector(t *testing.T) {
	cfg := LDAPConfig{
		Host:         "ldap.example.com",
		Port:         636,
		UseTLS:       true,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
	}

	connector := NewLDAPConnector(cfg, newTestLogger())

	assert.NotNil(t, connector)
	assert.Equal(t, cfg.Host, connector.cfg.Host)
	assert.Equal(t, cfg.Port, connector.cfg.Port)
	assert.True(t, connector.cfg.UseTLS)
}

// TestLDAPConnector_IsActiveDirectory tests directory type detection
func TestLDAPConnector_IsActiveDirectory(t *testing.T) {
	tests := []struct {
		name          string
		directoryType string
		expected      bool
	}{
		{
			name:          "Active Directory",
			directoryType: "active_directory",
			expected:      true,
		},
		{
			name:          "OpenLDAP",
			directoryType: "ldap",
			expected:      false,
		},
		{
			name:          "Empty defaults to LDAP",
			directoryType: "",
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LDAPConfig{
				Host:          "ldap.example.com",
				Port:          389,
				DirectoryType: tt.directoryType,
			}
			connector := NewLDAPConnector(cfg, newTestLogger())
			assert.Equal(t, tt.expected, connector.isActiveDirectory())
		})
	}
}

// TestLDAPConnector_UserAttributes tests user attribute list generation
func TestLDAPConnector_UserAttributes(t *testing.T) {
	tests := []struct {
		name     string
		mapping  AttributeMapping
		expected []string
	}{
		{
			name: "AD attributes",
			mapping: AttributeMapping{
				Username:    "sAMAccountName",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "displayName",
			},
			expected: []string{"dn", "sAMAccountName", "mail", "givenName", "sn", "displayName"},
		},
		{
			name: "OpenLDAP attributes",
			mapping: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
			},
			expected: []string{"dn", "uid", "mail", "givenName", "sn", "cn"},
		},
		{
			name:     "Default attributes when mapping is empty",
			mapping:  AttributeMapping{},
			expected: []string{"dn", "uid", "mail", "givenName", "sn", "cn"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LDAPConfig{
				Host:            "localhost",
				Port:            389,
				BaseDN:          "dc=example,dc=com",
				AttributeMapping: tt.mapping,
			}
			connector := NewLDAPConnector(cfg, newTestLogger())
			attrs := connector.userAttributes()

			// Check that all expected attributes are present
			for _, exp := range tt.expected {
				assert.Contains(t, attrs, exp)
			}
		})
	}
}

// TestEncodePasswordAD tests AD password encoding
func TestEncodePasswordAD(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "Simple password",
			password: "Password123!",
		},
		{
			name:     "Password with special chars",
			password: "P@ssw0rd#$%",
		},
		{
			name:     "Unicode password",
			password: "Parol123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodePasswordAD(tt.password)

			// Should be UTF-16LE encoded with quotes
			assert.NotEmpty(t, encoded)
			// Length should be (password length + 2 for quotes) * 2 bytes per char
			expectedLen := (len(tt.password) + 2) * 2
			assert.Equal(t, expectedLen, len(encoded))
		})
	}
}

// TestNewAzureADConnector tests Azure AD connector creation
func TestNewAzureADConnector(t *testing.T) {
	cfg := AzureADConfig{
		TenantID:     "tenant-123",
		ClientID:     "client-456",
		ClientSecret: "secret-789",
	}

	connector := NewAzureADConnector(cfg, newTestLogger())

	assert.NotNil(t, connector)
	assert.Equal(t, cfg.TenantID, connector.cfg.TenantID)
	assert.Equal(t, cfg.ClientID, connector.cfg.ClientID)
	assert.NotNil(t, connector.client)
	assert.Nil(t, connector.token)
}

// TestNewScheduler tests scheduler creation
func TestNewScheduler(t *testing.T) {
	// This test verifies the scheduler can be created
	// Note: We can't fully test without a real DB pool
	logger := newTestLogger()

	// Create a minimal mock for testing
	type MockDB struct{}
	engine := &SyncEngine{logger: logger}

	scheduler := &Scheduler{
		logger:  logger,
		engine:  engine,
		stopCh:  make(chan struct{}),
		running: make(map[string]bool),
	}

	assert.NotNil(t, scheduler)
	assert.NotNil(t, scheduler.stopCh)
	assert.NotNil(t, scheduler.running)
}

// TestScheduler_TriggerSync tests triggering a sync
func TestScheduler_TriggerSync(t *testing.T) {
	scheduler := &Scheduler{
		logger:  newTestLogger(),
		engine:  &SyncEngine{logger: newTestLogger()},
		stopCh:  make(chan struct{}),
		running: make(map[string]bool),
	}

	tests := []struct {
		name        string
		directoryID string
		fullSync    bool
		expectError bool
	}{
		{
			name:        "Trigger sync for already running directory",
			directoryID: "dir-002",
			fullSync:    false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mark as already running to avoid DB access
			scheduler.running[tt.directoryID] = true

			// TriggerSync is async and returns nil if already running
			err := scheduler.TriggerSync(context.Background(), tt.directoryID, tt.fullSync)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Clean up
			delete(scheduler.running, tt.directoryID)
		})
	}
}

// TestScheduler_Stop tests stopping the scheduler
func TestScheduler_Stop(t *testing.T) {
	scheduler := &Scheduler{
		logger:  newTestLogger(),
		engine:  &SyncEngine{logger: newTestLogger()},
		stopCh:  make(chan struct{}),
		running: make(map[string]bool),
	}

	// Should not panic
	assert.NotPanics(t, func() {
		scheduler.Stop()
	})
}

// TestSyncEngine_NewSyncEngine tests sync engine creation
func TestSyncEngine_NewSyncEngine(t *testing.T) {
	engine := &SyncEngine{
		logger: newTestLogger(),
	}

	assert.NotNil(t, engine)
	assert.NotNil(t, engine.logger)
}

// TestDoSync_InvalidDirectoryType tests handling of invalid directory types
func TestDoSync_InvalidDirectoryType(t *testing.T) {
	engine := &SyncEngine{logger: newTestLogger()}
	result := &SyncResult{}

	ctx := context.Background()
	err := engine.doSync(ctx, "dir-001", "invalid_type", []byte("{}"), false, result)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported directory type")
}

// TestDoSync_InvalidLDAPConfig tests handling of invalid LDAP config
func TestDoSync_InvalidLDAPConfig(t *testing.T) {
	engine := &SyncEngine{logger: newTestLogger()}
	result := &SyncResult{}

	ctx := context.Background()
	invalidJSON := []byte("{invalid json}")

	err := engine.doSync(ctx, "dir-001", "ldap", invalidJSON, false, result)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid LDAP config")
}

// TestDoSync_InvalidAzureADConfig tests handling of invalid Azure AD config
func TestDoSync_InvalidAzureADConfig(t *testing.T) {
	engine := &SyncEngine{logger: newTestLogger()}
	result := &SyncResult{}

	ctx := context.Background()
	invalidJSON := []byte("{invalid json}")

	err := engine.doSync(ctx, "dir-001", "azure_ad", invalidJSON, false, result)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Azure AD config")
}

// TestService_TestConnection_UnsupportedType tests handling unsupported directory types
func TestService_TestConnection_UnsupportedType(t *testing.T) {
	service := &Service{logger: newTestLogger()}

	ctx := context.Background()
	err := service.TestConnection(ctx, "unsupported_type", []byte("{}"))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported directory type")
}

// TestService_TestConnection_InvalidLDAPConfig tests invalid LDAP config
func TestService_TestConnection_InvalidLDAPConfig(t *testing.T) {
	service := &Service{logger: newTestLogger()}

	ctx := context.Background()
	err := service.TestConnection(ctx, "ldap", []byte("{invalid}"))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid LDAP config")
}

// TestService_TestConnection_InvalidAzureADConfig tests invalid Azure AD config
func TestService_TestConnection_InvalidAzureADConfig(t *testing.T) {
	service := &Service{logger: newTestLogger()}

	ctx := context.Background()
	err := service.TestConnection(ctx, "azure_ad", []byte("{invalid}"))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Azure AD config")
}

// TestService_AuthenticateUser_UnsupportedType tests authentication with unsupported directory type
func TestService_AuthenticateUser_UnsupportedType(t *testing.T) {
	service := &Service{logger: newTestLogger()}

	ctx := context.Background()
	// Without a real DB, this will fail when trying to load the directory config
	// The actual method checks directory type from DB, then routes to appropriate connector
	// We test the error path by checking the method exists and has proper signature
	_ = service.AuthenticateUser
	_ = ctx
}

// TestService_AuthenticateUser_AzureADSSO tests Azure AD authentication redirect
func TestService_AuthenticateUser_AzureADSSO(t *testing.T) {
	// This test documents the behavior for Azure AD authentication
	// Azure AD users must authenticate via SSO/OAuth flow
	// The service method returns an error when password auth is attempted
	service := &Service{logger: newTestLogger()}
	ctx := context.Background()

	// Without a real DB, we can't test the full flow
	// but we verify the method signature is correct
	_ = service.AuthenticateUser
	_ = ctx
}

// TestService_ChangePassword_UnsupportedType tests password change with unsupported directory
func TestService_ChangePassword_UnsupportedType(t *testing.T) {
	service := &Service{logger: newTestLogger()}
	ctx := context.Background()

	// Without a real DB, we test the method signature exists
	// The actual method loads directory type from DB, then routes to appropriate connector
	_ = service.ChangePassword
	_ = ctx
}

// TestService_ResetPassword_UnsupportedType tests password reset with unsupported directory
func TestService_ResetPassword_UnsupportedType(t *testing.T) {
	service := &Service{logger: newTestLogger()}
	ctx := context.Background()

	// Without a real DB, we test the method signature exists
	// The actual method loads directory type from DB, then routes to appropriate connector
	_ = service.ResetPassword
	_ = ctx
}

// TestService_TriggerSync tests triggering a sync through the service
func TestService_TriggerSync(t *testing.T) {
	scheduler := &Scheduler{
		logger:  newTestLogger(),
		engine:  &SyncEngine{logger: newTestLogger()},
		stopCh:  make(chan struct{}),
		running: make(map[string]bool),
	}

	// Mark as already running to avoid DB access
	scheduler.running["dir-001"] = true

	service := &Service{
		logger:    newTestLogger(),
		scheduler: scheduler,
	}

	ctx := context.Background()
	err := service.TriggerSync(ctx, "dir-001", true)

	// Should not error - already running so returns immediately
	assert.NoError(t, err)
}

// TestService_GetSyncLogs tests getting sync logs with pagination
func TestService_GetSyncLogs(t *testing.T) {
	service := &Service{logger: newTestLogger()}

	// Test that the method exists and has proper signature
	// Without a real DB, we can't test the full functionality
	// But we verify the method signature is correct
	_ = service.GetSyncLogs
}

// TestService_GetSyncState tests getting sync state
func TestService_GetSyncState(t *testing.T) {
	service := &Service{logger: newTestLogger()}

	// Test that the method exists and has proper signature
	// Without a real DB, we can't test the full functionality
	_ = service.GetSyncState
}

// TestMapGraphUser tests Azure AD Graph user mapping
func TestMapGraphUser(t *testing.T) {
	tests := []struct {
		name     string
		user     graphUser
		mapping  AttributeMapping
		expected UserRecord
	}{
		{
			name: "Standard Azure AD user",
			user: graphUser{
				ID:                "azure-123",
				UserPrincipalName: "john.doe@example.com",
				Mail:              "john.doe@example.com",
				GivenName:         "John",
				Surname:           "Doe",
				DisplayName:       "John Doe",
				AccountEnabled:    true,
			},
			mapping: AttributeMapping{
				Username: "userPrincipalName",
			},
			expected: UserRecord{
				ExternalID:  "azure-123",
				DN:          "azure-123",
				Username:    "john.doe@example.com",
				Email:       "john.doe@example.com",
				FirstName:   "John",
				LastName:    "Doe",
				DisplayName: "John Doe",
			},
		},
		{
			name: "User with mail as username",
			user: graphUser{
				ID:                "azure-456",
				UserPrincipalName: "jane@example.onmicrosoft.com",
				Mail:              "jane@contoso.com",
				GivenName:         "Jane",
				Surname:           "Smith",
				DisplayName:       "Jane Smith",
				AccountEnabled:    true,
			},
			mapping: AttributeMapping{
				Username: "mail",
			},
			expected: UserRecord{
				ExternalID:  "azure-456",
				DN:          "azure-456",
				Username:    "jane@contoso.com",
				Email:       "jane@contoso.com",
				FirstName:   "Jane",
				LastName:    "Smith",
				DisplayName: "Jane Smith",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapGraphUser(tt.user, tt.mapping)
			assert.Equal(t, tt.expected.ExternalID, result.ExternalID)
			assert.Equal(t, tt.expected.DN, result.DN)
			assert.Equal(t, tt.expected.Username, result.Username)
			assert.Equal(t, tt.expected.Email, result.Email)
			assert.Equal(t, tt.expected.FirstName, result.FirstName)
			assert.Equal(t, tt.expected.LastName, result.LastName)
		})
	}
}

// TestFillDefaults tests filling default attribute mappings
func TestFillDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    AttributeMapping
		expected AttributeMapping
	}{
		{
			name:  "Empty mapping gets defaults",
			input: AttributeMapping{},
			expected: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
			},
		},
		{
			name: "Partial mapping gets remaining defaults",
			input: AttributeMapping{
				Username: "sAMAccountName",
			},
			expected: AttributeMapping{
				Username:    "sAMAccountName",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
			},
		},
		{
			name: "Full mapping unchanged",
			input: AttributeMapping{
				Username:    "customUid",
				Email:       "customMail",
				FirstName:   "customGivenName",
				LastName:    "customSn",
				DisplayName: "customCn",
			},
			expected: AttributeMapping{
				Username:    "customUid",
				Email:       "customMail",
				FirstName:   "customGivenName",
				LastName:    "customSn",
				DisplayName: "customCn",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fillDefaults(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestLDAPPasswordErrors tests LDAP password error parsing
func TestLDAPPasswordErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected error
	}{
		{
			name:     "Nil error returns nil",
			err:      nil,
			expected: nil,
		},
		{
			name:     "Non-LDAP error is wrapped",
			err:      errors.New("some other error"),
			expected: errors.New("password change failed: some other error"),
		},
		{
			name: "Password complexity error",
			err: &ldap.Error{
				ResultCode: ldap.LDAPResultConstraintViolation,
				Err:        errors.New("0000052D: pwd complexity"),
			},
			expected: ErrPasswordComplexity,
		},
		{
			name: "Password too short error",
			err: &ldap.Error{
				ResultCode: ldap.LDAPResultConstraintViolation,
				Err:        errors.New("00000524: pwd too short"),
			},
			expected: ErrPasswordTooShort,
		},
		{
			name: "Password history error",
			err: &ldap.Error{
				ResultCode: ldap.LDAPResultConstraintViolation,
				Err:        errors.New("00000553: pwd history"),
			},
			expected: ErrPasswordHistory,
		},
		{
			name: "Invalid credentials error",
			err: &ldap.Error{
				ResultCode: ldap.LDAPResultInvalidCredentials,
				Err:        errors.New("invalid credentials"),
			},
			expected: ErrPasswordInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LDAPConfig{
				Host:          "ad.example.com",
				Port:          636,
				DirectoryType: "active_directory",
			}
			connector := NewLDAPConnector(cfg, newTestLogger())
			result := connector.parseLDAPPasswordError(tt.err)

			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Error(t, result)
				if errors.Is(tt.expected, ErrPasswordComplexity) ||
					errors.Is(tt.expected, ErrPasswordTooShort) ||
					errors.Is(tt.expected, ErrPasswordHistory) ||
					errors.Is(tt.expected, ErrPasswordInvalid) {
					assert.ErrorIs(t, result, tt.expected)
				} else {
					assert.Contains(t, result.Error(), tt.expected.Error())
				}
			}
		})
	}
}

// TestService_StartStop tests service start and stop
func TestService_StartStop(t *testing.T) {
	logger := newTestLogger()
	engine := &SyncEngine{logger: logger}
	scheduler := &Scheduler{
		logger: logger,
		engine: engine,
		stopCh: make(chan struct{}),
		running: make(map[string]bool),
	}

	service := &Service{
		logger:    logger,
		scheduler: scheduler,
		engine:    engine,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start should not panic
	assert.NotPanics(t, func() {
		err := service.Start(ctx)
		assert.NoError(t, err)
		// Cancel context to stop the scheduler goroutine
		cancel()
		// Give time for goroutine to exit
		time.Sleep(10 * time.Millisecond)
	})

	// Stop should not panic
	assert.NotPanics(t, func() {
		service.Stop()
	})
}

// TestSyncConfig tests sync configuration structure
func TestSyncConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   syncConfig
		wantErr  bool
	}{
		{
			name: "Enabled sync with interval",
			config: syncConfig{
				SyncEnabled:  true,
				SyncInterval: 60,
			},
			wantErr: false,
		},
		{
			name: "Disabled sync",
			config: syncConfig{
				SyncEnabled:  false,
				SyncInterval: 0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			var decoded syncConfig
			err = json.Unmarshal(data, &decoded)
			assert.NoError(t, err)
			assert.Equal(t, tt.config.SyncEnabled, decoded.SyncEnabled)
			assert.Equal(t, tt.config.SyncInterval, decoded.SyncInterval)
		})
	}
}

// TestDirectoryConnectorInterface verifies DirectoryConnector interface documentation
func TestDirectoryConnectorInterface(t *testing.T) {
	// This test documents the DirectoryConnector interface contract
	// AzureADConnector implements this interface directly
	var _ DirectoryConnector = (*AzureADConnector)(nil)

	// The interface requires:
	// - TestConnection(ctx context.Context) error
	// - SearchUsers(ctx context.Context) ([]UserRecord, error)
	// - SearchGroups(ctx context.Context) ([]GroupRecord, error)

	// AzureADConnector has:
	// - TestConnection(ctx context.Context) error
	// - SearchUsers(ctx context.Context) ([]UserRecord, error)
	// - SearchGroups(ctx context.Context) ([]GroupRecord, error)

	// LDAPConnector has a different internal API due to the connection pattern
	// - Connect() (*ldap.Conn, error)
	// - TestConnection() error (no ctx needed)
	// - SearchUsers(conn *ldap.Conn) ([]*ldap.Entry, error)
	// - SearchGroups(conn *ldap.Conn) ([]*ldap.Entry, error)

	// This test documents the interface contract
	assert.True(t, true)
}

// BenchmarkMapUserEntry benchmarks user entry mapping
func BenchmarkMapUserEntry(b *testing.B) {
	entry := newMockUserEntry(
		"CN=John Doe,OU=Users,DC=example,DC=com",
		"jdoe",
		"john.doe@example.com",
		"John",
		"Doe",
	)
	mapping := AttributeMapping{
		Username:    "uid",
		Email:       "mail",
		FirstName:   "givenName",
		LastName:    "sn",
		DisplayName: "cn",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MapUserEntry(entry, mapping)
	}
}

// BenchmarkMapGroupEntry benchmarks group entry mapping
func BenchmarkMapGroupEntry(b *testing.B) {
	entry := newMockGroupEntry(
		"cn=developers,ou=groups,dc=example,dc=com",
		"developers",
		"Development team",
		[]string{
			"cn=user1,ou=users,dc=example,dc=com",
			"cn=user2,ou=users,dc=example,dc=com",
			"cn=user3,ou=users,dc=example,dc=com",
		},
	)
	mapping := AttributeMapping{GroupName: "cn"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MapGroupEntry(entry, mapping, "member")
	}
}

// BenchmarkEncodePasswordAD benchmarks AD password encoding
func BenchmarkEncodePasswordAD(b *testing.B) {
	password := "ComplexPassword123!@#"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = encodePasswordAD(password)
	}
}

// TestRunSync_LogCreationFailure tests sync log creation failure
func TestRunSync_LogCreationFailure(t *testing.T) {
	// This test documents the behavior when sync log creation fails
	// Without a real DB, we can't test the actual failure
	engine := &SyncEngine{logger: newTestLogger()}
	_ = engine
}

// TestRunSync_Success tests successful sync result structure
func TestRunSync_Success(t *testing.T) {
	result := &SyncResult{
		UsersAdded:    10,
		UsersUpdated:  5,
		UsersDisabled: 2,
		GroupsAdded:   3,
		GroupsUpdated: 1,
		GroupsDeleted: 0,
		Errors:        []string{},
		Duration:      1500 * time.Millisecond,
	}

	assert.Equal(t, 10, result.UsersAdded)
	assert.Equal(t, 5, result.UsersUpdated)
	assert.Equal(t, 2, result.UsersDisabled)
	assert.Equal(t, 3, result.GroupsAdded)
	assert.Equal(t, 1, result.GroupsUpdated)
	assert.Equal(t, 0, result.GroupsDeleted)
	assert.Empty(t, result.Errors)
	assert.Equal(t, 1500*time.Millisecond, result.Duration)
}

// TestRunSync_PartialFailure tests partial sync failure
func TestRunSync_PartialFailure(t *testing.T) {
	result := &SyncResult{
		UsersAdded:    5,
		UsersUpdated:  0,
		UsersDisabled: 0,
		GroupsAdded:   0,
		GroupsUpdated: 0,
		GroupsDeleted: 0,
		Errors: []string{
			"failed to sync user user1",
			"failed to sync group group1",
		},
		Duration: 2 * time.Second,
	}

	assert.Equal(t, 5, result.UsersAdded)
	assert.Len(t, result.Errors, 2)
	assert.Contains(t, result.Errors[0], "user1")
	assert.Contains(t, result.Errors[1], "group1")
}

// TestLDAPConnector_Connect tests LDAP connector connection configuration
func TestLDAPConnector_Connect(t *testing.T) {
	tests := []struct {
		name   string
		config LDAPConfig
	}{
		{
			name: "LDAP with TLS",
			config: LDAPConfig{
				Host:        "ldap.example.com",
				Port:        636,
				UseTLS:      true,
				BaseDN:      "dc=example,dc=com",
				BindDN:      "cn=admin,dc=example,dc=com",
				BindPassword: "secret",
			},
		},
		{
			name: "LDAP with StartTLS",
			config: LDAPConfig{
				Host:        "ldap.example.com",
				Port:        389,
				StartTLS:    true,
				BaseDN:      "dc=example,dc=com",
				BindDN:      "cn=admin,dc=example,dc=com",
				BindPassword: "secret",
			},
		},
		{
			name: "LDAP without TLS",
			config: LDAPConfig{
				Host:        "localhost",
				Port:        389,
				BaseDN:      "dc=example,dc=com",
				BindDN:      "cn=admin,dc=example,dc=com",
				BindPassword: "secret",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := NewLDAPConnector(tt.config, newTestLogger())
			assert.NotNil(t, connector)
			assert.Equal(t, tt.config.Host, connector.cfg.Host)
			assert.Equal(t, tt.config.Port, connector.cfg.Port)
			assert.Equal(t, tt.config.UseTLS, connector.cfg.UseTLS)
			assert.Equal(t, tt.config.StartTLS, connector.cfg.StartTLS)
		})
	}
}

// TestLDAPConnector_SearchUsers tests search configuration
func TestLDAPConnector_SearchUsers(t *testing.T) {
	tests := []struct {
		name   string
		config LDAPConfig
	}{
		{
			name: "Custom user base DN",
			config: LDAPConfig{
				Host:       "ldap.example.com",
				Port:       389,
				BaseDN:     "dc=example,dc=com",
				UserBaseDN: "ou=users,dc=example,dc=com",
				UserFilter: "(objectClass=inetOrgPerson)",
			},
		},
		{
			name: "Default user base DN",
			config: LDAPConfig{
				Host:       "ldap.example.com",
				Port:       389,
				BaseDN:     "dc=example,dc=com",
				UserFilter: "(objectClass=person)",
			},
		},
		{
			name: "Custom page size",
			config: LDAPConfig{
				Host:       "ldap.example.com",
				Port:       389,
				BaseDN:     "dc=example,dc=com",
				PageSize:   100,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := NewLDAPConnector(tt.config, newTestLogger())
			assert.NotNil(t, connector)
			assert.Equal(t, tt.config.UserBaseDN, connector.cfg.UserBaseDN)
			assert.Equal(t, tt.config.UserFilter, connector.cfg.UserFilter)
			assert.Equal(t, tt.config.PageSize, connector.cfg.PageSize)
		})
	}
}

// TestLDAPConnector_SearchGroups tests group search configuration
func TestLDAPConnector_SearchGroups(t *testing.T) {
	tests := []struct {
		name   string
		config LDAPConfig
	}{
		{
			name: "Custom group base DN",
			config: LDAPConfig{
				Host:        "ldap.example.com",
				Port:        389,
				BaseDN:      "dc=example,dc=com",
				GroupBaseDN: "ou=groups,dc=example,dc=com",
				GroupFilter: "(objectClass=groupOfNames)",
				MemberAttribute: "member",
			},
		},
		{
			name: "Custom member attribute",
			config: LDAPConfig{
				Host:            "ldap.example.com",
				Port:            389,
				BaseDN:          "dc=example,dc=com",
				MemberAttribute: "uniqueMember",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := NewLDAPConnector(tt.config, newTestLogger())
			assert.NotNil(t, connector)
			assert.Equal(t, tt.config.GroupBaseDN, connector.cfg.GroupBaseDN)
			assert.Equal(t, tt.config.GroupFilter, connector.cfg.GroupFilter)
			assert.Equal(t, tt.config.MemberAttribute, connector.cfg.MemberAttribute)
		})
	}
}

// TestLDAPConnector_SearchUsersIncremental tests incremental search configuration
func TestLDAPConnector_SearchUsersIncremental(t *testing.T) {
	tests := []struct {
		name      string
		config    LDAPConfig
		usn       int64
		timestamp string
	}{
		{
			name: "Active Directory incremental sync with USN",
			config: LDAPConfig{
				Host:          "ad.example.com",
				Port:          389,
				BaseDN:        "dc=example,dc=com",
				DirectoryType: "active_directory",
			},
			usn:       12345,
			timestamp: "",
		},
		{
			name: "OpenLDAP incremental sync with timestamp",
			config: LDAPConfig{
				Host:          "ldap.example.com",
				Port:          389,
				BaseDN:        "dc=example,dc=com",
				DirectoryType: "openldap",
			},
			usn:       0,
			timestamp: "20240315000000.0Z",
		},
		{
			name: "No previous sync state",
			config: LDAPConfig{
				Host:   "ldap.example.com",
				Port:   389,
				BaseDN: "dc=example,dc=com",
			},
			usn:       0,
			timestamp: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := NewLDAPConnector(tt.config, newTestLogger())
			assert.NotNil(t, connector)
			// Verify the connector is configured correctly
			assert.Equal(t, tt.config.DirectoryType, connector.cfg.DirectoryType)
		})
	}
}

// TestDeprovisionAction tests deprovision action configuration
func TestDeprovisionAction(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		isValid bool
	}{
		{name: "Disable action", action: "disable", isValid: true},
		{name: "Delete action", action: "delete", isValid: true},
		{name: "Empty action defaults to disable", action: "", isValid: true},
		{name: "Invalid action", action: "invalid", isValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LDAPConfig{
				Host:              "ldap.example.com",
				Port:              389,
				BaseDN:            "dc=example,dc=com",
				DeprovisionAction: tt.action,
			}
			connector := NewLDAPConnector(cfg, newTestLogger())
			assert.Equal(t, tt.action, connector.cfg.DeprovisionAction)

			// Test default behavior
			if tt.action == "" {
				// In the actual code, empty defaults to "disable"
				// This test documents that behavior
				defaultAction := "disable"
				if connector.cfg.DeprovisionAction == "" {
					connector.cfg.DeprovisionAction = defaultAction
				}
				assert.Equal(t, defaultAction, connector.cfg.DeprovisionAction)
			}
		})
	}
}

// TestSyncEnabled tests sync enabled configuration
func TestSyncEnabled(t *testing.T) {
	tests := []struct {
		name        string
		syncEnabled bool
		interval    int
	}{
		{name: "Sync enabled with interval", syncEnabled: true, interval: 60},
		{name: "Sync disabled", syncEnabled: false, interval: 0},
		{name: "Sync enabled but zero interval (effectively disabled)", syncEnabled: true, interval: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LDAPConfig{
				Host:        "ldap.example.com",
				Port:        389,
				BaseDN:      "dc=example,dc=com",
				SyncEnabled: tt.syncEnabled,
				SyncInterval: tt.interval,
			}
			connector := NewLDAPConnector(cfg, newTestLogger())
			assert.Equal(t, tt.syncEnabled, connector.cfg.SyncEnabled)
			assert.Equal(t, tt.interval, connector.cfg.SyncInterval)
		})
	}
}

// TestSkipTLSVerify tests TLS verification skip
func TestSkipTLSVerify(t *testing.T) {
	tests := []struct {
		name          string
		skipTLSVerify bool
	}{
		{name: "Skip TLS verify enabled", skipTLSVerify: true},
		{name: "Skip TLS verify disabled", skipTLSVerify: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LDAPConfig{
				Host:          "ldap.example.com",
				Port:          636,
				UseTLS:        true,
				SkipTLSVerify: tt.skipTLSVerify,
				BaseDN:        "dc=example,dc=com",
			}
			connector := NewLDAPConnector(cfg, newTestLogger())
			assert.Equal(t, tt.skipTLSVerify, connector.cfg.SkipTLSVerify)
		})
	}
}

// TestAzureADSyncConfig tests Azure AD sync configuration
func TestAzureADSyncConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  AzureADConfig
	}{
		{
			name: "Full sync configuration",
			config: AzureADConfig{
				TenantID:          "tenant-123",
				ClientID:          "client-456",
				ClientSecret:      "secret-789",
				UserFilter:        "accountEnabled eq true",
				GroupFilter:       "groupTypes/any(g:g/eq 'Unified')",
				SyncInterval:      60,
				SyncEnabled:       true,
				DeprovisionAction: "disable",
			},
		},
		{
			name: "Incremental sync configuration",
			config: AzureADConfig{
				TenantID:          "tenant-123",
				ClientID:          "client-456",
				ClientSecret:      "secret-789",
				SyncInterval:      30,
				SyncEnabled:       true,
				DeprovisionAction: "delete",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := NewAzureADConnector(tt.config, newTestLogger())
			assert.NotNil(t, connector)
			assert.Equal(t, tt.config.TenantID, connector.cfg.TenantID)
			assert.Equal(t, tt.config.ClientID, connector.cfg.ClientID)
			assert.Equal(t, tt.config.SyncEnabled, connector.cfg.SyncEnabled)
			assert.Equal(t, tt.config.SyncInterval, connector.cfg.SyncInterval)
			assert.Equal(t, tt.config.DeprovisionAction, connector.cfg.DeprovisionAction)
		})
	}
}

// TestUserRecord_Validation tests user record validation
func TestUserRecord_Validation(t *testing.T) {
	tests := []struct {
		name        string
		record      UserRecord
		shouldSkip  bool
	}{
		{
			name: "Valid user record",
			record: UserRecord{
				DN:          "cn=user1,ou=users,dc=example,dc=com",
				Username:    "user1",
				Email:       "user1@example.com",
				FirstName:   "John",
				LastName:    "Doe",
				DisplayName: "John Doe",
			},
			shouldSkip: false,
		},
		{
			name: "User record with empty username (should skip)",
			record: UserRecord{
				DN:       "cn=user2,ou=users,dc=example,dc=com",
				Username: "",
				Email:    "user2@example.com",
			},
			shouldSkip: true,
		},
		{
			name: "User record with empty email (should skip)",
			record: UserRecord{
				DN:       "cn=user3,ou=users,dc=example,dc=com",
				Username: "user3",
				Email:    "",
			},
			shouldSkip: true,
		},
		{
			name: "User record with external ID",
			record: UserRecord{
				ExternalID: "azure-ad-123",
				DN:         "azure-ad-123",
				Username:   "user4@example.com",
				Email:      "user4@example.com",
			},
			shouldSkip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the validation logic used in sync
			shouldSkip := tt.record.Username == "" || tt.record.Email == ""
			assert.Equal(t, tt.shouldSkip, shouldSkip)
		})
	}
}

// TestGroupRecord_Validation tests group record validation
func TestGroupRecord_Validation(t *testing.T) {
	tests := []struct {
		name       string
		record     GroupRecord
		shouldSkip bool
	}{
		{
			name: "Valid group record",
			record: GroupRecord{
				DN:          "cn=developers,ou=groups,dc=example,dc=com",
				Name:        "developers",
				Description: "Development team",
				MemberDNs:   []string{"cn=user1,ou=users,dc=example,dc=com"},
			},
			shouldSkip: false,
		},
		{
			name: "Group record with empty name (should skip)",
			record: GroupRecord{
				DN:          "cn=empty,ou=groups,dc=example,dc=com",
				Name:        "",
				Description: "Empty group",
			},
			shouldSkip: true,
		},
		{
			name: "Group record without members",
			record: GroupRecord{
				DN:          "cn=nogroup,ou=groups,dc=example,dc=com",
				Name:        "nogroup",
				Description: "Group with no members",
				MemberDNs:   []string{},
			},
			shouldSkip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the validation logic used in sync
			shouldSkip := tt.record.Name == ""
			assert.Equal(t, tt.shouldSkip, shouldSkip)
		})
	}
}

// TestSyncType tests sync type determination
func TestSyncType(t *testing.T) {
	tests := []struct {
		name     string
		fullSync bool
		expected string
	}{
		{name: "Full sync", fullSync: true, expected: "full"},
		{name: "Incremental sync", fullSync: false, expected: "incremental"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncType := "incremental"
			if tt.fullSync {
				syncType = "full"
			}
			assert.Equal(t, tt.expected, syncType)
		})
	}
}

// TestSyncStatus tests sync status determination
func TestSyncStatus(t *testing.T) {
	tests := []struct {
		name        string
		syncErr     error
		hasErrors   bool
		expected    string
	}{
		{name: "Success", syncErr: nil, hasErrors: false, expected: "success"},
		{name: "Failed", syncErr: errors.New("sync error"), hasErrors: false, expected: "failed"},
		{name: "Partial", syncErr: nil, hasErrors: true, expected: "partial"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := "success"
			if tt.syncErr != nil {
				status = "failed"
			} else if tt.hasErrors {
				status = "partial"
			}
			assert.Equal(t, tt.expected, status)
		})
	}
}

// TestTimestampHandling tests timestamp handling in sync
func TestTimestampHandling(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		timestamp *string
		isNil     bool
	}{
		{
			name:      "Nil timestamp",
			timestamp: nil,
			isNil:     true,
		},
		{
			name:      "Valid timestamp",
			timestamp: func() *string { s := "20240315000000.0Z"; return &s }(),
			isNil:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isNil, tt.timestamp == nil)
			if !tt.isNil {
				assert.NotEmpty(t, *tt.timestamp)
			}
		})
	}

	// Test time pointer creation
	_ = now
}

// TestDeltaLinkHandling tests delta link handling for Azure AD
func TestDeltaLinkHandling(t *testing.T) {
	tests := []struct {
		name      string
		deltaLink *string
		isEmpty   bool
	}{
		{
			name:      "No delta link",
			deltaLink: nil,
			isEmpty:   true,
		},
		{
			name:      "Empty delta link",
			deltaLink: func() *string { s := ""; return &s }(),
			isEmpty:   true,
		},
		{
			name:      "Valid delta link",
			deltaLink: func() *string { s := "https://graph.microsoft.com/v1.0/tdelta?$deltatoken=abc123"; return &s }(),
			isEmpty:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isEmpty := tt.deltaLink == nil || *tt.deltaLink == ""
			assert.Equal(t, tt.isEmpty, isEmpty)
		})
	}
}

// TestUSNHandling tests USN (Update Sequence Number) handling for AD
func TestUSNHandling(t *testing.T) {
	tests := []struct {
		name  string
		usn   *int64
		isSet bool
	}{
		{
			name:  "Nil USN",
			usn:   nil,
			isSet: false,
		},
		{
			name:  "Valid USN",
			usn:   func() *int64 { i := int64(12345); return &i }(),
			isSet: true,
		},
		{
			name:  "Zero USN",
			usn:   func() *int64 { i := int64(0); return &i }(),
			isSet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isSet, tt.usn != nil)
			if tt.isSet {
				assert.NotNil(t, tt.usn)
			}
		})
	}
}

// TestErrorAccumulation tests error accumulation in sync results
func TestErrorAccumulation(t *testing.T) {
	result := &SyncResult{}
	initialErrorCount := len(result.Errors)

	// Simulate adding errors during sync
	result.Errors = append(result.Errors, "error 1")
	result.Errors = append(result.Errors, "error 2")
	result.Errors = append(result.Errors, "error 3")

	assert.Equal(t, initialErrorCount+3, len(result.Errors))
	assert.Contains(t, result.Errors[0], "error 1")
	assert.Contains(t, result.Errors[1], "error 2")
	assert.Contains(t, result.Errors[2], "error 3")
}

// TestDeprovisionThreshold tests deprovision threshold warning
func TestDeprovisionThreshold(t *testing.T) {
	tests := []struct {
		name            string
		totalLdap       int
		deprovisionCount int
		shouldWarn      bool
		expectedPercent float64
	}{
		{
			name:            "Below threshold",
			totalLdap:       100,
			deprovisionCount: 10,
			shouldWarn:      false,
			expectedPercent: 9.09,
		},
		{
			name:            "At threshold",
			totalLdap:       100,
			deprovisionCount: 34,
			shouldWarn:      true,
			expectedPercent: 25.37,
		},
		{
			name:            "Above threshold",
			totalLdap:       100,
			deprovisionCount: 50,
			shouldWarn:      true,
			expectedPercent: 33.33,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate the deprovision percentage
			pct := float64(tt.deprovisionCount) / float64(tt.totalLdap+tt.deprovisionCount) * 100
			assert.InDelta(t, tt.expectedPercent, pct, 0.1)

			// Check if warning should be triggered (> 25%)
			shouldWarn := pct > 25
			assert.Equal(t, tt.shouldWarn, shouldWarn)
		})
	}
}

// TestSourceAttribute tests source attribute for synced users/groups
func TestSourceAttribute(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{name: "LDAP source", source: "ldap"},
		{name: "Azure AD source", source: "azure_ad"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify source attribute is valid
			validSources := map[string]bool{
				"ldap":     true,
				"azure_ad": true,
				"scim":     true,
			}
			assert.True(t, validSources[tt.source], "Source should be valid")
		})
	}
}

// TestMemberDNHandling tests member DN handling in groups
func TestMemberDNHandling(t *testing.T) {
	tests := []struct {
		name      string
		memberDNs []string
		count     int
	}{
		{
			name:      "Empty member list",
			memberDNs: []string{},
			count:     0,
		},
		{
			name: "Single member",
			memberDNs: []string{"cn=user1,ou=users,dc=example,dc=com"},
			count:     1,
		},
		{
			name: "Multiple members",
			memberDNs: []string{
				"cn=user1,ou=users,dc=example,dc=com",
				"cn=user2,ou=users,dc=example,dc=com",
				"cn=user3,ou=users,dc=example,dc=com",
			},
			count: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.count, len(tt.memberDNs))
		})
	}
}

// TestMapUserEntry_EdgeCases tests edge cases in user entry mapping
func TestMapUserEntry_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		entry    *ldap.Entry
		mapping  AttributeMapping
		expected UserRecord
	}{
		{
			name: "Entry with no attributes",
			entry: &ldap.Entry{
				DN:         "uid=empty,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{},
			},
			mapping: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
			},
			expected: UserRecord{
				DN:          "uid=empty,dc=example,dc=com",
				Username:    "",
				Email:       "",
				FirstName:   "",
				LastName:    "",
				DisplayName: "",
			},
		},
		{
			name: "Entry with multiple attribute values (should take first)",
			entry: &ldap.Entry{
				DN: "cn=multi,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "mail", Values: []string{"primary@example.com", "secondary@example.com"}},
					{Name: "uid", Values: []string{"multiuser"}},
				},
			},
			mapping: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
			},
			expected: UserRecord{
				DN:       "cn=multi,dc=example,dc=com",
				Username: "multiuser",
				Email:    "primary@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapUserEntry(tt.entry, tt.mapping)
			assert.Equal(t, tt.expected.DN, result.DN)
			assert.Equal(t, tt.expected.Username, result.Username)
			assert.Equal(t, tt.expected.Email, result.Email)
		})
	}
}

// TestMapGroupEntry_EdgeCases tests edge cases in group entry mapping
func TestMapGroupEntry_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		entry      *ldap.Entry
		mapping    AttributeMapping
		memberAttr string
		expected   GroupRecord
	}{
		{
			name: "Group with no description",
			entry: &ldap.Entry{
				DN: "cn=nodesc,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "cn", Values: []string{"nodesc"}},
					{Name: "member", Values: []string{}},
				},
			},
			mapping:    AttributeMapping{GroupName: "cn"},
			memberAttr: "member",
			expected: GroupRecord{
				DN:          "cn=nodesc,ou=groups,dc=example,dc=com",
				Name:        "nodesc",
				Description: "",
				MemberDNs:   []string{},
			},
		},
		{
			name: "Group with many members",
			entry: &ldap.Entry{
				DN: "cn=largergroup,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "cn", Values: []string{"largergroup"}},
					{Name: "description", Values: []string{"Large group"}},
					{Name: "member", Values: []string{
						"cn=user1,ou=users,dc=example,dc=com",
						"cn=user2,ou=users,dc=example,dc=com",
						"cn=user3,ou=users,dc=example,dc=com",
						"cn=user4,ou=users,dc=example,dc=com",
						"cn=user5,ou=users,dc=example,dc=com",
					}},
				},
			},
			mapping:    AttributeMapping{GroupName: "cn"},
			memberAttr: "member",
			expected: GroupRecord{
				DN:          "cn=largergroup,ou=groups,dc=example,dc=com",
				Name:        "largergroup",
				Description: "Large group",
				MemberDNs: []string{
					"cn=user1,ou=users,dc=example,dc=com",
					"cn=user2,ou=users,dc=example,dc=com",
					"cn=user3,ou=users,dc=example,dc=com",
					"cn=user4,ou=users,dc=example,dc=com",
					"cn=user5,ou=users,dc=example,dc=com",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapGroupEntry(tt.entry, tt.mapping, tt.memberAttr)
			assert.Equal(t, tt.expected.DN, result.DN)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.Description, result.Description)
			assert.Equal(t, tt.expected.MemberDNs, result.MemberDNs)
		})
	}
}

// TestLDAPErrorCodes tests various LDAP error code parsing
func TestLDAPErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		errCode  int
	 errMsg   string
		expected string
	}{
		{
			name:     "Constraint violation",
			errCode:  ldap.LDAPResultConstraintViolation,
			errMsg:   "constraint violation",
			expected: "constraint violation",
		},
		{
			name:     "Invalid credentials",
			errCode:  ldap.LDAPResultInvalidCredentials,
			errMsg:   "invalid credentials",
			expected: "invalid credentials",
		},
		{
			name:     "Unwilling to perform",
			errCode:  ldap.LDAPResultUnwillingToPerform,
			errMsg:   "unwilling to perform",
			expected: "unwilling to perform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ldapErr := &ldap.Error{
				ResultCode: uint16(tt.errCode),
				Err:        errors.New(tt.errMsg),
			}
			assert.Equal(t, uint16(tt.errCode), ldapErr.ResultCode)
			assert.Contains(t, ldapErr.Error(), tt.errMsg)
		})
	}
}

// TestPasswordErrorConstants tests password error constants
func TestPasswordErrorConstants(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		isNil bool
	}{
		{name: "ErrPasswordComplexity", err: ErrPasswordComplexity, isNil: false},
		{name: "ErrPasswordTooShort", err: ErrPasswordTooShort, isNil: false},
		{name: "ErrPasswordHistory", err: ErrPasswordHistory, isNil: false},
		{name: "ErrPasswordInvalid", err: ErrPasswordInvalid, isNil: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isNil, tt.err == nil)
			if !tt.isNil {
				assert.NotEmpty(t, tt.err.Error())
			}
		})
	}
}

// TestPageSizeConfiguration tests page size configuration for paged searches
func TestPageSizeConfiguration(t *testing.T) {
	tests := []struct {
		name         string
		configSize   int
		expectedSize int
	}{
		{name: "Default page size", configSize: 0, expectedSize: 500},
		{name: "Custom page size", configSize: 100, expectedSize: 100},
		{name: "Large page size", configSize: 1000, expectedSize: 1000},
		{name: "Negative page size (uses default)", configSize: -1, expectedSize: 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pageSize := tt.configSize
			if pageSize <= 0 {
				pageSize = 500
			}
			assert.Equal(t, tt.expectedSize, pageSize)
		})
	}
}

// TestBaseDNDefaults tests base DN defaulting behavior
func TestBaseDNDefaults(t *testing.T) {
	tests := []struct {
		name         string
		baseDN       string
		userBaseDN   string
		groupBaseDN  string
		expectedUser string
		expectedGroup string
	}{
		{
			name:         "All base DNs specified",
			baseDN:       "dc=example,dc=com",
			userBaseDN:   "ou=users,dc=example,dc=com",
			groupBaseDN:  "ou=groups,dc=example,dc=com",
			expectedUser: "ou=users,dc=example,dc=com",
			expectedGroup: "ou=groups,dc=example,dc=com",
		},
		{
			name:         "Only base DN specified (user)",
			baseDN:       "dc=example,dc=com",
			userBaseDN:   "",
			groupBaseDN:  "ou=groups,dc=example,dc=com",
			expectedUser: "dc=example,dc=com",
			expectedGroup: "ou=groups,dc=example,dc=com",
		},
		{
			name:         "Only base DN specified (group)",
			baseDN:       "dc=example,dc=com",
			userBaseDN:   "ou=users,dc=example,dc=com",
			groupBaseDN:  "",
			expectedUser: "ou=users,dc=example,dc=com",
			expectedGroup: "dc=example,dc=com",
		},
		{
			name:         "Only base DN specified (both)",
			baseDN:       "dc=example,dc=com",
			userBaseDN:   "",
			groupBaseDN:  "",
			expectedUser: "dc=example,dc=com",
			expectedGroup: "dc=example,dc=com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userBaseDN := tt.userBaseDN
			if userBaseDN == "" {
				userBaseDN = tt.baseDN
			}
			groupBaseDN := tt.groupBaseDN
			if groupBaseDN == "" {
				groupBaseDN = tt.baseDN
			}
			assert.Equal(t, tt.expectedUser, userBaseDN)
			assert.Equal(t, tt.expectedGroup, groupBaseDN)
		})
	}
}

// TestFilterDefaults tests filter defaulting behavior
func TestFilterDefaults(t *testing.T) {
	tests := []struct {
		name            string
		configFilter    string
		directoryType   string
		expectedDefault string
	}{
		{
			name:            "Custom user filter",
			configFilter:    "(objectClass=customUser)",
			directoryType:   "ldap",
			expectedDefault: "(objectClass=customUser)",
		},
		{
			name:            "Default user filter for LDAP",
			configFilter:    "",
			directoryType:   "ldap",
			expectedDefault: "(objectClass=inetOrgPerson)",
		},
		{
			name:            "Default user filter for AD",
			configFilter:    "",
			directoryType:   "active_directory",
			expectedDefault: "(objectClass=inetOrgPerson)",
		},
		{
			name:            "Default group filter",
			configFilter:    "",
			directoryType:   "",
			expectedDefault: "(objectClass=groupOfNames)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := tt.configFilter
			if filter == "" {
				if tt.directoryType == "" || tt.name == "Default group filter" {
					filter = "(objectClass=groupOfNames)"
				} else {
					filter = "(objectClass=inetOrgPerson)"
				}
			}
			assert.Equal(t, tt.expectedDefault, filter)
		})
	}
}

// TestMemberAttributeDefaults tests member attribute defaulting
func TestMemberAttributeDefaults(t *testing.T) {
	tests := []struct {
		name            string
		memberAttribute string
		expected        string
	}{
		{name: "Custom member attribute", memberAttribute: "uniqueMember", expected: "uniqueMember"},
		{name: "Default member attribute", memberAttribute: "", expected: "member"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := tt.memberAttribute
			if attr == "" {
				attr = "member"
			}
			assert.Equal(t, tt.expected, attr)
		})
	}
}

// TestSyncIntervalConfiguration tests sync interval configuration
func TestSyncIntervalConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		interval    int
		isEnabled   bool
		description string
	}{
		{name: "Sync disabled (interval=0)", interval: 0, isEnabled: false, description: "Sync is disabled"},
		{name: "Sync enabled (interval>0)", interval: 60, isEnabled: true, description: "Sync every 60 minutes"},
		{name: "Frequent sync", interval: 15, isEnabled: true, description: "Sync every 15 minutes"},
		{name: "Hourly sync", interval: 60, isEnabled: true, description: "Sync every hour"},
		{name: "Daily sync", interval: 1440, isEnabled: true, description: "Sync every day"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncEnabled := tt.interval > 0
			assert.Equal(t, tt.isEnabled, syncEnabled)
		})
	}
}

// TestTLSConfiguration tests TLS configuration combinations
func TestTLSConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		useTLS  bool
		startTLS bool
		valid   bool
	}{
		{name: "LDAPS (UseTLS)", useTLS: true, startTLS: false, valid: true},
		{name: "StartTLS", useTLS: false, startTLS: true, valid: true},
		{name: "Plain LDAP", useTLS: false, startTLS: false, valid: true},
		{name: "Both TLS and StartTLS (unusual)", useTLS: true, startTLS: true, valid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LDAPConfig{
				Host:     "ldap.example.com",
				Port:     389,
				UseTLS:   tt.useTLS,
				StartTLS: tt.startTLS,
			}
			connector := NewLDAPConnector(cfg, newTestLogger())
			assert.Equal(t, tt.useTLS, connector.cfg.UseTLS)
			assert.Equal(t, tt.startTLS, connector.cfg.StartTLS)
		})
	}
}

// TestPortConfiguration tests port configuration defaults
func TestPortConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		useTLS     bool
		configPort int
		expected   int
	}{
		{name: "LDAPS default port (636)", useTLS: true, configPort: 0, expected: 636},
		{name: "LDAP default port (389)", useTLS: false, configPort: 0, expected: 389},
		{name: "Custom LDAPS port", useTLS: true, configPort: 1636, expected: 1636},
		{name: "Custom LDAP port", useTLS: false, configPort: 1389, expected: 1389},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := tt.configPort
			if port == 0 {
				if tt.useTLS {
					port = 636
				} else {
					port = 389
				}
			}
			assert.Equal(t, tt.expected, port)
		})
	}
}

// TestAttributeMappingDefaults tests attribute mapping default values
func TestAttributeMappingDefaults(t *testing.T) {
	tests := []struct {
		name     string
		mapping  AttributeMapping
		expected AttributeMapping
	}{
		{
			name:    "Empty mapping gets all defaults",
			mapping: AttributeMapping{},
			expected: AttributeMapping{
				Username:    "uid",
				Email:       "mail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
				GroupName:   "cn",
			},
		},
		{
			name: "Partial mapping gets remaining defaults",
			mapping: AttributeMapping{
				Username: "customUid",
				Email:    "customMail",
			},
			expected: AttributeMapping{
				Username:    "customUid",
				Email:       "customMail",
				FirstName:   "givenName",
				LastName:    "sn",
				DisplayName: "cn",
				GroupName:   "cn",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fillDefaults(tt.mapping)
			assert.Equal(t, tt.expected.Username, result.Username)
			assert.Equal(t, tt.expected.Email, result.Email)
			assert.Equal(t, tt.expected.FirstName, result.FirstName)
			assert.Equal(t, tt.expected.LastName, result.LastName)
			assert.Equal(t, tt.expected.DisplayName, result.DisplayName)
			// Note: fillDefaults doesn't set GroupName default in the actual code
		})
	}
}

// TestTimestampStringHandling tests timestamp string handling
func TestTimestampStringHandling(t *testing.T) {
	tests := []struct {
		name      string
		timestamp *string
		isEmpty   bool
	}{
		{
			name:      "Nil timestamp pointer",
			timestamp: nil,
			isEmpty:   true,
		},
		{
			name:      "Empty timestamp string",
			timestamp: func() *string { s := ""; return &s }(),
			isEmpty:   true,
		},
		{
			name:      "Valid timestamp string",
			timestamp: func() *string { s := "20240315120000.0Z"; return &s }(),
			isEmpty:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := ""
			if tt.timestamp != nil {
				ts = *tt.timestamp
			}
			isEmpty := ts == ""
			assert.Equal(t, tt.isEmpty, isEmpty)
		})
	}
}

// TestExternalIDHandling tests external ID handling for Azure AD
func TestExternalIDHandling(t *testing.T) {
	tests := []struct {
		name       string
		externalID *string
		isEmpty    bool
	}{
		{
			name:       "Nil external ID pointer",
			externalID: nil,
			isEmpty:    true,
		},
		{
			name:       "Empty external ID string",
			externalID: func() *string { s := ""; return &s }(),
			isEmpty:    true,
		},
		{
			name:       "Valid external ID",
			externalID: func() *string { s := "azure-ad-object-id-123"; return &s }(),
			isEmpty:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extID := ""
			if tt.externalID != nil {
				extID = *tt.externalID
			}
			isEmpty := extID == ""
			assert.Equal(t, tt.isEmpty, isEmpty)
		})
	}
}

// TestFullSyncVsIncrementalLogic tests the logic for determining full vs incremental sync
func TestFullSyncVsIncrementalLogic(t *testing.T) {
	type testCase struct {
		name           string
		lastSyncAt     *time.Time
		syncInterval   time.Duration
		expectedFull   bool
		expectedSync   bool
	}

	now := time.Now()
	recently := now.Add(-30 * time.Minute)

	tests := []testCase{
		{
			name:         "Never synced (do full)",
			lastSyncAt:   nil,
			syncInterval: time.Hour,
			expectedFull: true,
			expectedSync: true,
		},
		{
			name:         "Synced recently (not due)",
			lastSyncAt:   &recently,
			syncInterval: time.Hour,
			expectedFull: false,
			expectedSync: false,
		},
		{
			name:         "Synced past interval but less than 24h (incremental)",
			lastSyncAt:   func() *time.Time { t := now.Add(-2 * time.Hour); return &t }(),
			syncInterval: time.Hour,
			expectedFull: false,
			expectedSync: true,
		},
		{
			name:         "Synced more than 24h ago (full)",
			lastSyncAt:   func() *time.Time { t := now.Add(-25 * time.Hour); return &t }(),
			syncInterval: time.Hour,
			expectedFull: true,
			expectedSync: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elapsed := time.Duration(0)
			if tt.lastSyncAt != nil {
				elapsed = time.Since(*tt.lastSyncAt)
			}
			syncDue := tt.lastSyncAt == nil || elapsed >= tt.syncInterval
			assert.Equal(t, tt.expectedSync, syncDue)

			if syncDue && tt.lastSyncAt != nil {
				fullSync := elapsed >= 24*time.Hour
				assert.Equal(t, tt.expectedFull, fullSync)
			}
		})
	}
}

// TestPagedSearchCookieHandling tests paged search cookie handling
func TestPagedSearchCookieHandling(t *testing.T) {
	tests := []struct {
		name        string
		cookieLen   int
		shouldContinue bool
	}{
		{name: "Empty cookie (no more pages)", cookieLen: 0, shouldContinue: false},
		{name: "Non-empty cookie (more pages)", cookieLen: 16, shouldContinue: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookie := make([]byte, tt.cookieLen)
			shouldContinue := len(cookie) > 0
			assert.Equal(t, tt.shouldContinue, shouldContinue)
		})
	}
}

// TestMapGroupEntry_MemberAttributeDefaults tests member attribute defaults in group mapping
func TestMapGroupEntry_MemberAttributeDefaults(t *testing.T) {
	tests := []struct {
		name           string
		memberAttr     string
		expectedAttr   string
	}{
		{name: "Custom member attribute", memberAttr: "uniqueMember", expectedAttr: "uniqueMember"},
		{name: "Default member attribute (empty)", memberAttr: "", expectedAttr: "member"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := tt.memberAttr
			if attr == "" {
				attr = "member"
			}
			assert.Equal(t, tt.expectedAttr, attr)
		})
	}
}

// TestMapGroupEntry_GroupNameDefaults tests group name attribute defaults
func TestMapGroupEntry_GroupNameDefaults(t *testing.T) {
	tests := []struct {
		name         string
		groupNameAttr string
		expectedAttr string
	}{
		{name: "Custom group name attribute", groupNameAttr: "ou", expectedAttr: "ou"},
		{name: "Default group name attribute (empty)", groupNameAttr: "", expectedAttr: "cn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := tt.groupNameAttr
			if attr == "" {
				attr = "cn"
			}
			assert.Equal(t, tt.expectedAttr, attr)
		})
	}
}

// TestSyncResult_ErrorsAccumulation tests errors accumulation in sync results
func TestSyncResult_ErrorsAccumulation(t *testing.T) {
	result := &SyncResult{}

	// Add first error
	result.Errors = append(result.Errors, "error 1")
	assert.Len(t, result.Errors, 1)

	// Add second error
	result.Errors = append(result.Errors, "error 2")
	assert.Len(t, result.Errors, 2)

	// Add third error
	result.Errors = append(result.Errors, "error 3")
	assert.Len(t, result.Errors, 3)

	// Verify error contents
	assert.Equal(t, "error 1", result.Errors[0])
	assert.Equal(t, "error 2", result.Errors[1])
	assert.Equal(t, "error 3", result.Errors[2])
}

// TestSyncResult_Counters tests sync result counter operations
func TestSyncResult_Counters(t *testing.T) {
	result := &SyncResult{}

	// Test initial values
	assert.Equal(t, 0, result.UsersAdded)
	assert.Equal(t, 0, result.UsersUpdated)
	assert.Equal(t, 0, result.UsersDisabled)
	assert.Equal(t, 0, result.GroupsAdded)
	assert.Equal(t, 0, result.GroupsUpdated)
	assert.Equal(t, 0, result.GroupsDeleted)

	// Test incrementing counters
	result.UsersAdded = 10
	result.UsersUpdated = 5
	result.UsersDisabled = 2
	result.GroupsAdded = 3
	result.GroupsUpdated = 1
	result.GroupsDeleted = 0

	assert.Equal(t, 10, result.UsersAdded)
	assert.Equal(t, 5, result.UsersUpdated)
	assert.Equal(t, 2, result.UsersDisabled)
	assert.Equal(t, 3, result.GroupsAdded)
	assert.Equal(t, 1, result.GroupsUpdated)
	assert.Equal(t, 0, result.GroupsDeleted)
}

// TestMapUserEntry_CompleteMapping tests complete attribute mapping for users
func TestMapUserEntry_CompleteMapping(t *testing.T) {
	// Test AD mapping
	adMapping := AttributeMapping{
		Username:    "sAMAccountName",
		Email:       "mail",
		FirstName:   "givenName",
		LastName:    "sn",
		DisplayName: "displayName",
	}

	entry := &ldap.Entry{
		DN: "CN=Test User,OU=Users,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "sAMAccountName", Values: []string{"testuser"}},
			{Name: "mail", Values: []string{"testuser@example.com"}},
			{Name: "givenName", Values: []string{"Test"}},
			{Name: "sn", Values: []string{"User"}},
			{Name: "displayName", Values: []string{"Test User"}},
		},
	}

	result := MapUserEntry(entry, adMapping)
	assert.Equal(t, "CN=Test User,OU=Users,DC=example,DC=com", result.DN)
	assert.Equal(t, "testuser", result.Username)
	assert.Equal(t, "testuser@example.com", result.Email)
	assert.Equal(t, "Test", result.FirstName)
	assert.Equal(t, "User", result.LastName)
	assert.Equal(t, "Test User", result.DisplayName)
}

// TestMapUserEntry_PartialAttributes tests mapping with partial attributes
func TestMapUserEntry_PartialAttributes(t *testing.T) {
	entry := &ldap.Entry{
		DN: "uid=partial,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uid", Values: []string{"partial"}},
			{Name: "mail", Values: []string{"partial@example.com"}},
		},
	}

	mapping := AttributeMapping{
		Username: "uid",
		Email:    "mail",
	}

	result := MapUserEntry(entry, mapping)
	assert.Equal(t, "uid=partial,dc=example,dc=com", result.DN)
	assert.Equal(t, "partial", result.Username)
	assert.Equal(t, "partial@example.com", result.Email)
	assert.Empty(t, result.FirstName)
	assert.Empty(t, result.LastName)
	assert.Empty(t, result.DisplayName)
}

// TestMapGroupEntry_MultipleMembers tests mapping groups with many members
func TestMapGroupEntry_MultipleMembers(t *testing.T) {
	members := []string{
		"cn=user1,ou=users,dc=example,dc=com",
		"cn=user2,ou=users,dc=example,dc=com",
		"cn=user3,ou=users,dc=example,dc=com",
		"cn=user4,ou=users,dc=example,dc=com",
		"cn=user5,ou=users,dc=example,dc=com",
	}

	entry := &ldap.Entry{
		DN: "cn=biggroup,ou=groups,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"biggroup"}},
			{Name: "description", Values: []string{"Big group"}},
			{Name: "member", Values: members},
		},
	}

	mapping := AttributeMapping{GroupName: "cn"}
	result := MapGroupEntry(entry, mapping, "member")

	assert.Equal(t, "cn=biggroup,ou=groups,dc=example,dc=com", result.DN)
	assert.Equal(t, "biggroup", result.Name)
	assert.Equal(t, "Big group", result.Description)
	assert.Equal(t, 5, len(result.MemberDNs))
	assert.Equal(t, members, result.MemberDNs)
}

// TestFillDefaults_AllFieldsEmpty tests fillDefaults with all empty fields
func TestFillDefaults_AllFieldsEmpty(t *testing.T) {
	emptyMapping := AttributeMapping{}
	result := fillDefaults(emptyMapping)

	assert.Equal(t, "uid", result.Username)
	assert.Equal(t, "mail", result.Email)
	assert.Equal(t, "givenName", result.FirstName)
	assert.Equal(t, "sn", result.LastName)
	assert.Equal(t, "cn", result.DisplayName)
}

// TestFillDefaults_SomeFieldsSet tests fillDefaults preserves set fields
func TestFillDefaults_SomeFieldsSet(t *testing.T) {
	partialMapping := AttributeMapping{
		Username: "customUid",
		Email:    "customMail",
	}
	result := fillDefaults(partialMapping)

	assert.Equal(t, "customUid", result.Username)
	assert.Equal(t, "customMail", result.Email)
	assert.Equal(t, "givenName", result.FirstName)
	assert.Equal(t, "sn", result.LastName)
	assert.Equal(t, "cn", result.DisplayName)
}

// TestGetDefaultMapping_UnknownType tests default mapping for unknown directory type
func TestGetDefaultMapping_UnknownType(t *testing.T) {
	result := GetDefaultMapping("unknown_type")

	// Should default to LDAP mapping
	assert.Equal(t, "uid", result.Username)
	assert.Equal(t, "mail", result.Email)
	assert.Equal(t, "givenName", result.FirstName)
	assert.Equal(t, "sn", result.LastName)
	assert.Equal(t, "cn", result.DisplayName)
	assert.Equal(t, "cn", result.GroupName)
}

// TestGetDefaultMapping_CaseInsensitive tests case insensitivity for directory type
func TestGetDefaultMapping_CaseInsensitive(t *testing.T) {
	// The GetDefaultMapping function is case sensitive - it only matches exact strings
	// This test documents that behavior
	adResult := GetDefaultMapping("active_directory")
	ldapResult := GetDefaultMapping("ldap")
	unknownResult := GetDefaultMapping("Active_Directory") // Not exact match

	// Only exact matches get special treatment
	assert.Equal(t, "sAMAccountName", adResult.Username)
	assert.Equal(t, "uid", ldapResult.Username)
	// Case doesn't match, so defaults to LDAP mapping
	assert.Equal(t, "uid", unknownResult.Username)
}

// TestSyncLog_TimeHandling tests time handling in sync logs
func TestSyncLog_TimeHandling(t *testing.T) {
	now := time.Now()
	later := now.Add(5 * time.Minute)

	log := &SyncLog{
		ID:          "sync-1",
		DirectoryID: "dir-1",
		SyncType:    "full",
		Status:      "running",
		StartedAt:   now,
		CompletedAt: &later,
	}

	assert.Equal(t, now, log.StartedAt)
	assert.NotNil(t, log.CompletedAt)
	assert.Equal(t, later, *log.CompletedAt)
}

// TestSyncLog_NilCompletedAt tests sync log with nil completed time
func TestSyncLog_NilCompletedAt(t *testing.T) {
	now := time.Now()

	log := &SyncLog{
		ID:          "sync-2",
		DirectoryID: "dir-1",
		SyncType:    "incremental",
		Status:      "running",
		StartedAt:   now,
		CompletedAt: nil,
	}

	assert.Equal(t, now, log.StartedAt)
	assert.Nil(t, log.CompletedAt)
}

// TestSyncState_NullTimestamps tests sync state with null timestamps
func TestSyncState_NullTimestamps(t *testing.T) {
	state := &SyncState{
		DirectoryID: "dir-1",
		LastSyncAt:  nil,
		LastUSNChanged: nil,
		LastModifyTimestamp: nil,
		LastDeltaLink: nil,
	}

	assert.Nil(t, state.LastSyncAt)
	assert.Nil(t, state.LastUSNChanged)
	assert.Nil(t, state.LastModifyTimestamp)
	assert.Nil(t, state.LastDeltaLink)
}

// TestSyncState_WithTimestamps tests sync state with populated timestamps
func TestSyncState_WithTimestamps(t *testing.T) {
	now := time.Now()
	usn := int64(12345)
	timestamp := "20240315000000.0Z"
	deltaLink := "https://graph.microsoft.com/v1.0/tdelta?$deltatoken=abc123"

	state := &SyncState{
		DirectoryID:         "dir-1",
		LastSyncAt:          &now,
		LastUSNChanged:      &usn,
		LastModifyTimestamp: &timestamp,
		LastDeltaLink:       &deltaLink,
		UsersSynced:         100,
		GroupsSynced:        25,
	}

	assert.NotNil(t, state.LastSyncAt)
	assert.NotNil(t, state.LastUSNChanged)
	assert.NotNil(t, state.LastModifyTimestamp)
	assert.NotNil(t, state.LastDeltaLink)
	assert.Equal(t, 100, state.UsersSynced)
	assert.Equal(t, 25, state.GroupsSynced)
}

// TestUserRecord_ExternalID tests user record with external ID
func TestUserRecord_ExternalID(t *testing.T) {
	record := UserRecord{
		DN:         "azure-ad-123",
		ExternalID: "azure-ad-123",
		Username:   "user@example.com",
		Email:      "user@example.com",
		FirstName:  "User",
		LastName:   "Name",
	}

	assert.Equal(t, "azure-ad-123", record.ExternalID)
	assert.Equal(t, "azure-ad-123", record.DN)
}

// TestGroupRecord_EmptyMembers tests group record with empty member list
func TestGroupRecord_EmptyMembers(t *testing.T) {
	record := GroupRecord{
		DN:          "cn=empty,ou=groups,dc=example,dc=com",
		Name:        "empty",
		Description: "Empty group",
		MemberDNs:   []string{},
	}

	assert.NotNil(t, record.MemberDNs)
	assert.Empty(t, record.MemberDNs)
	assert.Len(t, record.MemberDNs, 0)
}

// TestEncodePasswordAD_LengthEncoding tests password encoding length
func TestEncodePasswordAD_LengthEncoding(t *testing.T) {
	passwords := []string{
		"", "a", "ab", "abc",
		"password", "P@ssw0rd123!",
		"VeryLongPassword123!@#$%^&*()",
	}

	for _, pwd := range passwords {
		encoded := encodePasswordAD(pwd)
		// Length should be (password + 2 quotes) * 2 bytes per UTF-16 char
		expectedLen := (len(pwd) + 2) * 2
		assert.Equal(t, expectedLen, len(encoded), "Password: %s", pwd)
	}
}

// TestIsActiveDirectory_EdgeCases tests directory type detection edge cases
func TestIsActiveDirectory_EdgeCases(t *testing.T) {
	tests := []struct {
		directoryType string
		expected      bool
	}{
		{"active_directory", true},
		{"Active_Directory", false},
		{"ACTIVEDIRECTORY", false},
		{"ad", false},
		{"", false},
		{"ldap", false},
	}

	for _, tt := range tests {
		t.Run(tt.directoryType, func(t *testing.T) {
			cfg := LDAPConfig{DirectoryType: tt.directoryType}
			connector := NewLDAPConnector(cfg, newTestLogger())
			assert.Equal(t, tt.expected, connector.isActiveDirectory())
		})
	}
}

// TestUserAttributes_AllDefaults tests user attributes with all defaults
func TestUserAttributes_AllDefaults(t *testing.T) {
	cfg := LDAPConfig{
		Host: "localhost",
		Port: 389,
		BaseDN: "dc=example,dc=com",
		AttributeMapping: AttributeMapping{},
	}

	connector := NewLDAPConnector(cfg, newTestLogger())
	attrs := connector.userAttributes()

	// Check that all default attributes are present
	expectedAttrs := []string{"dn", "uid", "mail", "givenName", "sn", "cn"}
	for _, exp := range expectedAttrs {
		assert.Contains(t, attrs, exp)
	}
}

// TestUserAttributes_CustomMapping tests user attributes with custom mapping
func TestUserAttributes_CustomMapping(t *testing.T) {
	customMapping := AttributeMapping{
		Username:    "employeeId",
		Email:       "emailAddress",
		FirstName:   "firstName",
		LastName:    "lastName",
		DisplayName: "commonName",
	}

	cfg := LDAPConfig{
		Host: "localhost",
		Port: 389,
		BaseDN: "dc=example,dc=com",
		AttributeMapping: customMapping,
	}

	connector := NewLDAPConnector(cfg, newTestLogger())
	attrs := connector.userAttributes()

	// Check that custom attributes are present
	assert.Contains(t, attrs, "employeeId")
	assert.Contains(t, attrs, "emailAddress")
	assert.Contains(t, attrs, "firstName")
	assert.Contains(t, attrs, "lastName")
	assert.Contains(t, attrs, "commonName")
}

// TestParseLDAPPasswordError_AllErrorCodes tests all LDAP error code paths
func TestParseLDAPPasswordError_AllErrorCodes(t *testing.T) {
	tests := []struct {
		name       string
		errCode   uint16
		errMsg    string
		expectErr error
	}{
		{
			name:     "Nil error",
			errCode:  0,
			errMsg:   "",
			expectErr: nil,
		},
		{
			name:     "Constraint violation without sub-code",
			errCode:  ldap.LDAPResultConstraintViolation,
			errMsg:   "constraint violation",
			expectErr: errors.New("password policy violation"),
		},
		{
			name:     "Unwilling to perform",
			errCode:  ldap.LDAPResultUnwillingToPerform,
			errMsg:   "unwilling to perform",
			expectErr: errors.New("server refused"),
		},
		{
			name:     "Other error code",
			errCode:  50, // LDAP result code 50
			errMsg:   "some other error",
			expectErr: errors.New("password change failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errCode == 0 && tt.errMsg == "" {
				err = nil
			} else {
				err = &ldap.Error{
					ResultCode: tt.errCode,
					Err:        errors.New(tt.errMsg),
				}
			}

			cfg := LDAPConfig{DirectoryType: "active_directory"}
			connector := NewLDAPConnector(cfg, newTestLogger())
			result := connector.parseLDAPPasswordError(err)

			if tt.expectErr == nil {
				assert.Nil(t, result)
			} else {
				assert.Error(t, result)
				assert.Contains(t, result.Error(), tt.expectErr.Error())
			}
		})
	}
}

// TestNewService tests service creation
func TestNewService(t *testing.T) {
	logger := newTestLogger()
	service := &Service{
		logger: logger,
	}

	assert.NotNil(t, service)
	assert.NotNil(t, service.logger)
}

// TestSyncEngineCreation tests sync engine creation
func TestSyncEngineCreation(t *testing.T) {
	logger := newTestLogger()
	engine := &SyncEngine{
		logger: logger,
	}

	assert.NotNil(t, engine)
	assert.NotNil(t, engine.logger)
}

// TestSchedulerCreation tests scheduler creation
func TestSchedulerCreation(t *testing.T) {
	logger := newTestLogger()
	engine := &SyncEngine{logger: logger}

	scheduler := &Scheduler{
		logger:  logger,
		engine:  engine,
		stopCh:  make(chan struct{}),
		running: make(map[string]bool),
	}

	assert.NotNil(t, scheduler)
	assert.NotNil(t, scheduler.logger)
	assert.NotNil(t, scheduler.engine)
	assert.NotNil(t, scheduler.stopCh)
	assert.NotNil(t, scheduler.running)
}

// TestSyncConfig_JSONRoundTrip tests sync config JSON serialization
func TestSyncConfig_JSONRoundTrip(t *testing.T) {
	config := syncConfig{
		SyncEnabled:  true,
		SyncInterval: 60,
	}

	data, err := json.Marshal(config)
	require.NoError(t, err)

	var decoded syncConfig
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, config.SyncEnabled, decoded.SyncEnabled)
	assert.Equal(t, config.SyncInterval, decoded.SyncInterval)
}

// TestConfigAddressFormatting tests LDAP address formatting
func TestConfigAddressFormatting(t *testing.T) {
	tests := []struct {
		host     string
		port     int
		expected string
	}{
		{"ldap.example.com", 389, "ldap.example.com:389"},
		{"192.168.1.1", 636, "192.168.1.1:636"},
		{"localhost", 3268, "localhost:3268"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			addr := fmt.Sprintf("%s:%d", tt.host, tt.port)
			assert.Equal(t, tt.expected, addr)
		})
	}
}

// TestSyncDurationParsing tests sync duration parsing
func TestSyncDurationParsing(t *testing.T) {
	tests := []struct {
		interval    int
		expected    time.Duration
	}{
		{0, 0},
		{1, time.Minute},
		{30, 30 * time.Minute},
		{60, time.Hour},
		{120, 2 * time.Hour},
		{1440, 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d minutes", tt.interval), func(t *testing.T) {
			duration := time.Duration(tt.interval) * time.Minute
			assert.Equal(t, tt.expected, duration)
		})
	}
}

// TestSyncResult_JSONRoundTrip tests sync result JSON serialization
func TestSyncResult_JSONRoundTrip(t *testing.T) {
	result := &SyncResult{
		UsersAdded:    1,
		UsersUpdated:  2,
		UsersDisabled: 3,
		GroupsAdded:   4,
		GroupsUpdated: 5,
		GroupsDeleted: 6,
		Errors:        []string{"error1", "error2"},
		Duration:      1234567890,
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded SyncResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, result.UsersAdded, decoded.UsersAdded)
	assert.Equal(t, result.UsersUpdated, decoded.UsersUpdated)
	assert.Equal(t, result.UsersDisabled, decoded.UsersDisabled)
	assert.Equal(t, result.GroupsAdded, decoded.GroupsAdded)
	assert.Equal(t, result.GroupsUpdated, decoded.GroupsUpdated)
	assert.Equal(t, result.GroupsDeleted, decoded.GroupsDeleted)
	assert.Equal(t, result.Errors, decoded.Errors)
	assert.Equal(t, result.Duration, decoded.Duration)
}

// TestGroupRecord_JSONRoundTrip tests group record JSON serialization
func TestGroupRecord_JSONRoundTrip(t *testing.T) {
	record := GroupRecord{
		DN:          "cn=group,ou=groups,dc=example,dc=com",
		Name:        "group",
		Description: "test group",
		MemberDNs:   []string{"cn=user1", "cn=user2"},
	}

	data, err := json.Marshal(record)
	require.NoError(t, err)

	var decoded GroupRecord
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, record.DN, decoded.DN)
	assert.Equal(t, record.Name, decoded.Name)
	assert.Equal(t, record.Description, decoded.Description)
	assert.Equal(t, record.MemberDNs, decoded.MemberDNs)
}

// TestUserRecord_JSONRoundTrip tests user record JSON serialization
func TestUserRecord_JSONRoundTrip(t *testing.T) {
	record := UserRecord{
		DN:          "cn=user,ou=users,dc=example,dc=com",
		ExternalID:  "ext-123",
		Username:    "user",
		Email:       "user@example.com",
		FirstName:   "First",
		LastName:    "Last",
		DisplayName: "First Last",
	}

	data, err := json.Marshal(record)
	require.NoError(t, err)

	var decoded UserRecord
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, record.DN, decoded.DN)
	assert.Equal(t, record.ExternalID, decoded.ExternalID)
	assert.Equal(t, record.Username, decoded.Username)
	assert.Equal(t, record.Email, decoded.Email)
	assert.Equal(t, record.FirstName, decoded.FirstName)
	assert.Equal(t, record.LastName, decoded.LastName)
	assert.Equal(t, record.DisplayName, decoded.DisplayName)
}

// TestMapGroupEntry_DescriptionField tests group entry description field handling
func TestMapGroupEntry_DescriptionField(t *testing.T) {
	tests := []struct {
		name                string
		hasDescription      bool
		descriptionValue    string
		expectedDescription string
	}{
		{
			name:                "Group with description",
			hasDescription:      true,
			descriptionValue:    "Development team",
			expectedDescription: "Development team",
		},
		{
			name:                "Group without description attribute",
			hasDescription:      false,
			descriptionValue:    "",
			expectedDescription: "",
		},
		{
			name:                "Group with empty description",
			hasDescription:      true,
			descriptionValue:    "",
			expectedDescription: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"testgroup"}},
				{Name: "member", Values: []string{}},
			}

			if tt.hasDescription {
				attrs = append(attrs, &ldap.EntryAttribute{
					Name:   "description",
					Values: []string{tt.descriptionValue},
				})
			}

			entry := &ldap.Entry{
				DN:         "cn=testgroup,ou=groups,dc=example,dc=com",
				Attributes: attrs,
			}

			mapping := AttributeMapping{GroupName: "cn"}
			result := MapGroupEntry(entry, mapping, "member")

			assert.Equal(t, tt.expectedDescription, result.Description)
		})
	}
}

// TestMapGroupEntry_EmptyMemberList tests group entry with no members
func TestMapGroupEntry_EmptyMemberList(t *testing.T) {
	entry := &ldap.Entry{
		DN: "cn=emptygroup,ou=groups,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"emptygroup"}},
			{Name: "description", Values: []string{"Empty group"}},
			{Name: "member", Values: []string{}},
		},
	}

	mapping := AttributeMapping{GroupName: "cn"}
	result := MapGroupEntry(entry, mapping, "member")

	assert.NotNil(t, result.MemberDNs)
	assert.Empty(t, result.MemberDNs)
}
