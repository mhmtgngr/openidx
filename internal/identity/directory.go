// Package identity provides directory synchronization functionality
package identity

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/events"
)

// IdentityState represents the lifecycle state of an identity
type IdentityState string

const (
	// StateCreated is the initial state when a user is first created
	StateCreated IdentityState = "created"
	// StateActive is the normal operational state
	StateActive IdentityState = "active"
	// StateSuspended means the user is temporarily disabled
	StateSuspended IdentityState = "suspended"
	// StateDeprovisioned means the user has been deleted/anonymized
	StateDeprovisioned IdentityState = "deprovisioned"
)

// ValidStateTransitions defines allowed state transitions
var ValidStateTransitions = map[IdentityState][]IdentityState{
	StateCreated:        {StateActive, StateDeprovisioned},
	StateActive:         {StateSuspended, StateDeprovisioned},
	StateSuspended:      {StateActive, StateDeprovisioned},
	StateDeprovisioned: {}, // Terminal state - no transitions out
}

// DirectorySyncStatus represents the status of a directory sync
type DirectorySyncStatus string

const (
	SyncStatusPending   DirectorySyncStatus = "pending"
	SyncStatusRunning   DirectorySyncStatus = "running"
	SyncStatusCompleted DirectorySyncStatus = "completed"
	SyncStatusFailed    DirectorySyncStatus = "failed"
)

// LDAPConfig contains configuration for LDAP directory connection
type LDAPConfig struct {
	// Connection settings
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	UseTLS       bool          `json:"use_tls"`
	UseStartTLS  bool          `json:"use_start_tls"`
	InsecureSkip bool          `json:"insecure_skip_verify"`
	Timeout      time.Duration `json:"timeout"`

	// Bind credentials
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`

	// Search configuration
	BaseDN          string   `json:"base_dn"`
	UserSearchBase  string   `json:"user_search_base,omitempty"`  // Falls back to BaseDN
	GroupSearchBase string   `json:"group_search_base,omitempty"` // Falls back to BaseDN
	UserFilter      string   `json:"user_filter"`                  // e.g., "(objectClass=person)"
	GroupFilter     string   `json:"group_filter"`                 // e.g., "(objectClass=group)"
	UserObjectClass []string `json:"user_object_class,omitempty"`
	GroupObjectClass []string `json:"group_object_class,omitempty"`
}

// DefaultLDAPConfig returns a config with sensible defaults
func DefaultLDAPConfig() *LDAPConfig {
	return &LDAPConfig{
		Port:           389,
		UseTLS:         false,
		UseStartTLS:    false,
		InsecureSkip:   false,
		Timeout:        30 * time.Second,
		UserFilter:     "(objectClass=person)",
		GroupFilter:    "(objectClass=group)",
		UserObjectClass: []string{"person", "organizationalPerson", "inetOrgPerson", "user"},
		GroupObjectClass: []string{"group", "groupOfNames", "groupOfUniqueNames"},
	}
}

// AttributeMapping defines how LDAP attributes map to OpenIDX User fields
type AttributeMapping struct {
	// User attribute mappings
	Username        string `json:"username"`         // e.g., "uid" or "sAMAccountName"
	Email           string `json:"email"`            // e.g., "mail"
	FirstName       string `json:"first_name"`       // e.g., "givenName"
	LastName        string `json:"last_name"`        // e.g., "sn"
	DisplayName     string `json:"display_name"`     // e.g., "cn" or "displayName"
	Phone           string `json:"phone,omitempty"`  // e.g., "telephoneNumber"
	Department      string `json:"department,omitempty"` // e.g., "department"
	Title           string `json:"title,omitempty"`  // e.g., "title"

	// Group attribute mappings
	GroupName       string `json:"group_name"`       // e.g., "cn"
	GroupMember     string `json:"group_member"`     // e.g., "member" or "uniqueMember"
	GroupMemberDN   string `json:"group_member_dn"`  // Whether member is a full DN

	// Custom attribute mappings to User.Attributes
	CustomAttributes map[string]string `json:"custom_attributes,omitempty"`
}

// DefaultAttributeMapping returns the default LDAP attribute mappings
func DefaultAttributeMapping() *AttributeMapping {
	return &AttributeMapping{
		Username:     "uid",
		Email:        "mail",
		FirstName:    "givenName",
		LastName:     "sn",
		DisplayName:  "cn",
		Phone:        "telephoneNumber",
		Department:   "departmentNumber",
		Title:        "title",
		GroupName:    "cn",
		GroupMember:  "member",
		GroupMemberDN: "true", // String value indicating member is DN
		CustomAttributes: map[string]string{
			"employeeNumber": "employeeNumber",
			"manager":        "manager",
		},
	}
}

// Directory represents an external directory for synchronization
type Directory struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Type            string            `json:"type"` // ldap, active_directory, okta
	Enabled         bool              `json:"enabled"`
	Config          *LDAPConfig       `json:"config,omitempty"`
	AttributeMap    *AttributeMapping `json:"attribute_map,omitempty"`
	OrganizationID  *string           `json:"organization_id,omitempty"`

	// Sync settings
	SyncInterval    time.Duration     `json:"sync_interval"`
	LastSyncAt      *time.Time        `json:"last_sync_at,omitempty"`
	LastSyncStatus  DirectorySyncStatus `json:"last_sync_status,omitempty"`
	LastSyncError   *string           `json:"last_sync_error,omitempty"`

	// Timestamps
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// DirectorySyncResult contains the results of a directory synchronization
type DirectorySyncResult struct {
	DirectoryID     string            `json:"directory_id"`
	StartedAt       time.Time         `json:"started_at"`
	CompletedAt     *time.Time        `json:"completed_at,omitempty"`
	Status          DirectorySyncStatus `json:"status"`
	Error           *string           `json:"error,omitempty"`

	UsersCreated    int               `json:"users_created"`
	UsersUpdated    int               `json:"users_updated"`
	UsersDeleted    int               `json:"users_deleted"`
	UsersFailed     int               `json:"users_failed"`

	GroupsCreated   int               `json:"groups_created"`
	GroupsUpdated   int               `json:"groups_updated"`
	GroupsDeleted   int               `json:"groups_deleted"`
	GroupsFailed    int               `json:"groups_failed"`

	Timestamp       time.Time         `json:"timestamp"`
}

// LDAPEntry represents a generic LDAP entry
type LDAPEntry struct {
	DN         string
	Attributes map[string][]string
}

// LDAPClient is the interface for LDAP directory operations
type LDAPClient interface {
	// Connect binds to the LDAP server
	Connect(ctx context.Context) error

	// Close closes the LDAP connection
	Close() error

	// SearchUsers searches for users in the directory
	SearchUsers(ctx context.Context, baseDN, filter string, attrs []string) ([]LDAPEntry, error)

	// SearchGroups searches for groups in the directory
	SearchGroups(ctx context.Context, baseDN, filter string, attrs []string) ([]LDAPEntry, error)

	// SearchUsersModifiedSince searches for users modified since a given time
	SearchUsersModifiedSince(ctx context.Context, baseDN, filter string, since time.Time) ([]LDAPEntry, error)
}

// SyncableDirectory is the interface for directory synchronization
type SyncableDirectory interface {
	// SyncUsers performs a full sync of users from the directory
	SyncUsers(ctx context.Context) (*DirectorySyncResult, error)

	// SyncUsersIncremental performs an incremental sync since the last sync
	SyncUsersIncremental(ctx context.Context) (*DirectorySyncResult, error)

	// SyncGroups performs a full sync of groups from the directory
	SyncGroups(ctx context.Context) (*DirectorySyncResult, error)

	// SyncAll performs a full sync of both users and groups
	SyncAll(ctx context.Context) (*DirectorySyncResult, error)

	// TestConnection tests the directory connection
	TestConnection(ctx context.Context) error
}

// LDAPSyncer implements directory synchronization for LDAP/AD
type LDAPSyncer struct {
	directory      *Directory
	client         LDAPClient
	repo           Repository
	logger         *zap.Logger
	eventBus       events.Bus
	webhookURL     *string
	retentionDays  int // Days before anonymizing deprovisioned users
}

// NewLDAPSyncer creates a new LDAP directory syncer
func NewLDAPSyncer(
	directory *Directory,
	client LDAPClient,
	repo Repository,
	logger *zap.Logger,
	eventBus events.Bus,
	webhookURL *string,
) *LDAPSyncer {
	if directory.AttributeMap == nil {
		directory.AttributeMap = DefaultAttributeMapping()
	}
	return &LDAPSyncer{
		directory:     directory,
		client:        client,
		repo:          repo,
		logger:        logger.With(zap.String("directory_id", directory.ID)),
		eventBus:      eventBus,
		webhookURL:    webhookURL,
		retentionDays: 90, // Default 90-day retention
	}
}

// SetRetentionDays sets the retention period for deprovisioned users
func (s *LDAPSyncer) SetRetentionDays(days int) {
	s.retentionDays = days
}

// TestConnection tests the LDAP directory connection
func (s *LDAPSyncer) TestConnection(ctx context.Context) error {
	if err := s.client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer s.client.Close()

	s.logger.Info("LDAP connection test successful",
		zap.String("directory", s.directory.Name),
		zap.String("host", s.directory.Config.Host),
	)

	return nil
}

// SyncUsers performs a full synchronization of users from LDAP
func (s *LDAPSyncer) SyncUsers(ctx context.Context) (*DirectorySyncResult, error) {
	result := &DirectorySyncResult{
		DirectoryID: s.directory.ID,
		StartedAt:   time.Now(),
		Status:      SyncStatusRunning,
	}

	if err := s.client.Connect(ctx); err != nil {
		result.Status = SyncStatusFailed
		errMsg := err.Error()
		result.Error = &errMsg
		return result, fmt.Errorf("failed to connect: %w", err)
	}
	defer s.client.Close()

	baseDN := s.directory.Config.UserSearchBase
	if baseDN == "" {
		baseDN = s.directory.Config.BaseDN
	}

	attrs := s.buildUserAttributeList()

	entries, err := s.client.SearchUsers(ctx, baseDN, s.directory.Config.UserFilter, attrs)
	if err != nil {
		result.Status = SyncStatusFailed
		errMsg := err.Error()
		result.Error = &errMsg
		return result, fmt.Errorf("failed to search users: %w", err)
	}

	s.logger.Info("LDAP user search completed",
		zap.Int("entries_found", len(entries)),
		zap.String("base_dn", baseDN),
	)

	for _, entry := range entries {
		user, err := s.mapLDAPEntryToUser(entry)
		if err != nil {
			s.logger.Warn("Failed to map LDAP entry to user",
				zap.String("dn", entry.DN),
				zap.Error(err),
			)
			result.UsersFailed++
			continue
		}

		// Check if user exists
		existing, err := s.repo.GetUserByUsername(ctx, user.UserName)
		if err != nil {
			// User doesn't exist, create new one
			user.SetState(StateCreated)
			if err := s.repo.CreateUser(ctx, user); err != nil {
				s.logger.Warn("Failed to create user",
					zap.String("username", user.UserName),
					zap.Error(err),
				)
				result.UsersFailed++
				continue
			}
			result.UsersCreated++

			// Publish event
			s.publishUserEvent(ctx, events.EventUserCreated, user)
		} else {
			// Update existing user
			user.ID = existing.ID
			user.CreatedAt = existing.CreatedAt
			existingState := existing.GetState()
			user.SetState(existingState)
			if existingState == StateCreated {
				user.SetState(StateActive) // Auto-transition to Active on sync
			}
			if err := s.repo.UpdateUser(ctx, user); err != nil {
				s.logger.Warn("Failed to update user",
					zap.String("username", user.UserName),
					zap.Error(err),
				)
				result.UsersFailed++
				continue
			}
			result.UsersUpdated++

			// Publish event
			s.publishUserEvent(ctx, events.EventUserUpdated, user)
		}
	}

	now := time.Now()
	result.CompletedAt = &now
	result.Status = SyncStatusCompleted

	// Update directory sync status
	s.directory.LastSyncAt = &now
	s.directory.LastSyncStatus = SyncStatusCompleted
	s.directory.LastSyncError = nil

	return result, nil
}

// SyncUsersIncremental performs an incremental sync since the last sync
func (s *LDAPSyncer) SyncUsersIncremental(ctx context.Context) (*DirectorySyncResult, error) {
	result := &DirectorySyncResult{
		DirectoryID: s.directory.ID,
		StartedAt:   time.Now(),
		Status:      SyncStatusRunning,
	}

	if s.directory.LastSyncAt == nil {
		// No previous sync, fall back to full sync
		s.logger.Info("No previous sync found, performing full sync instead")
		return s.SyncUsers(ctx)
	}

	if err := s.client.Connect(ctx); err != nil {
		result.Status = SyncStatusFailed
		errMsg := err.Error()
		result.Error = &errMsg
		return result, fmt.Errorf("failed to connect: %w", err)
	}
	defer s.client.Close()

	baseDN := s.directory.Config.UserSearchBase
	if baseDN == "" {
		baseDN = s.directory.Config.BaseDN
	}

	// Search for users modified since last sync
	entries, err := s.client.SearchUsersModifiedSince(ctx, baseDN, s.directory.Config.UserFilter, *s.directory.LastSyncAt)
	if err != nil {
		result.Status = SyncStatusFailed
		errMsg := err.Error()
		result.Error = &errMsg
		return result, fmt.Errorf("failed to search modified users: %w", err)
	}

	s.logger.Info("LDAP incremental user search completed",
		zap.Int("entries_found", len(entries)),
		zap.Time("since", *s.directory.LastSyncAt),
	)

	for _, entry := range entries {
		user, err := s.mapLDAPEntryToUser(entry)
		if err != nil {
			s.logger.Warn("Failed to map LDAP entry to user",
				zap.String("dn", entry.DN),
				zap.Error(err),
			)
			result.UsersFailed++
			continue
		}

		existing, err := s.repo.GetUserByUsername(ctx, user.UserName)
		if err != nil {
			// New user
			user.SetState(StateCreated)
			if err := s.repo.CreateUser(ctx, user); err != nil {
				result.UsersFailed++
				continue
			}
			result.UsersCreated++
			s.publishUserEvent(ctx, events.EventUserCreated, user)
		} else {
			// Update existing user - preserve state
			user.ID = existing.ID
			user.CreatedAt = existing.CreatedAt
			user.SetState(existing.GetState())
			if err := s.repo.UpdateUser(ctx, user); err != nil {
				result.UsersFailed++
				continue
			}
			result.UsersUpdated++
			s.publishUserEvent(ctx, events.EventUserUpdated, user)
		}
	}

	now := time.Now()
	result.CompletedAt = &now
	result.Status = SyncStatusCompleted
	s.directory.LastSyncAt = &now
	s.directory.LastSyncStatus = SyncStatusCompleted

	return result, nil
}

// SyncGroups performs a full synchronization of groups from LDAP
func (s *LDAPSyncer) SyncGroups(ctx context.Context) (*DirectorySyncResult, error) {
	result := &DirectorySyncResult{
		DirectoryID: s.directory.ID,
		StartedAt:   time.Now(),
		Status:      SyncStatusRunning,
	}

	if err := s.client.Connect(ctx); err != nil {
		result.Status = SyncStatusFailed
		errMsg := err.Error()
		result.Error = &errMsg
		return result, fmt.Errorf("failed to connect: %w", err)
	}
	defer s.client.Close()

	baseDN := s.directory.Config.GroupSearchBase
	if baseDN == "" {
		baseDN = s.directory.Config.BaseDN
	}

	attrs := []string{
		s.directory.AttributeMap.GroupName,
		s.directory.AttributeMap.GroupMember,
		"cn", "dn",
	}

	entries, err := s.client.SearchGroups(ctx, baseDN, s.directory.Config.GroupFilter, attrs)
	if err != nil {
		result.Status = SyncStatusFailed
		errMsg := err.Error()
		result.Error = &errMsg
		return result, fmt.Errorf("failed to search groups: %w", err)
	}

	s.logger.Info("LDAP group search completed",
		zap.Int("entries_found", len(entries)),
		zap.String("base_dn", baseDN),
	)

	for _, entry := range entries {
		group, err := s.mapLDAPEntryToGroup(entry)
		if err != nil {
			s.logger.Warn("Failed to map LDAP entry to group",
				zap.String("dn", entry.DN),
				zap.Error(err),
			)
			result.GroupsFailed++
			continue
		}

		existing, err := s.repo.GetGroupByDisplayName(ctx, group.DisplayName)
		if err != nil {
			// New group
			if err := s.repo.CreateGroup(ctx, group); err != nil {
				result.GroupsFailed++
				continue
			}
			result.GroupsCreated++
			s.publishGroupEvent(ctx, events.EventGroupCreated, group)
		} else {
			// Update existing group
			group.ID = existing.ID
			group.CreatedAt = existing.CreatedAt
			if err := s.repo.UpdateGroup(ctx, group); err != nil {
				result.GroupsFailed++
				continue
			}
			result.GroupsUpdated++
			s.publishGroupEvent(ctx, events.EventGroupUpdated, group)
		}
	}

	now := time.Now()
	result.CompletedAt = &now
	result.Status = SyncStatusCompleted

	return result, nil
}

// SyncAll performs a full synchronization of both users and groups
func (s *LDAPSyncer) SyncAll(ctx context.Context) (*DirectorySyncResult, error) {
	s.logger.Info("Starting full directory sync",
		zap.String("directory", s.directory.Name),
	)

	usersResult, err := s.SyncUsers(ctx)
	if err != nil {
		return usersResult, err
	}

	groupsResult, err := s.SyncGroups(ctx)
	if err != nil {
		return groupsResult, err
	}

	// Combine results
	result := &DirectorySyncResult{
		DirectoryID:  s.directory.ID,
		StartedAt:    usersResult.StartedAt,
		CompletedAt:  groupsResult.CompletedAt,
		Status:       SyncStatusCompleted,
		UsersCreated: usersResult.UsersCreated,
		UsersUpdated: usersResult.UsersUpdated,
		UsersDeleted: usersResult.UsersDeleted,
		UsersFailed:  usersResult.UsersFailed,
		GroupsCreated: groupsResult.GroupsCreated,
		GroupsUpdated: groupsResult.GroupsUpdated,
		GroupsDeleted: groupsResult.GroupsDeleted,
		GroupsFailed:  groupsResult.GroupsFailed,
		Timestamp:    time.Now(),
	}

	s.logger.Info("Full directory sync completed",
		zap.Int("users_created", result.UsersCreated),
		zap.Int("users_updated", result.UsersUpdated),
		zap.Int("groups_created", result.GroupsCreated),
		zap.Int("groups_updated", result.GroupsUpdated),
	)

	return result, nil
}

// buildUserAttributeList builds the list of LDAP attributes to fetch for users
func (s *LDAPSyncer) buildUserAttributeList() []string {
	m := s.directory.AttributeMap
	attrs := []string{
		"dn", m.Username, m.Email, m.FirstName, m.LastName,
		m.DisplayName, m.Phone, m.Department, m.Title,
		"objectClass", "cn", "uid", "sAMAccountName",
	}

	// Add custom attributes
	for _, ldapAttr := range m.CustomAttributes {
		attrs = append(attrs, ldapAttr)
	}

	return attrs
}

// mapLDAPEntryToUser converts an LDAP entry to a User
func (s *LDAPSyncer) mapLDAPEntryToUser(entry LDAPEntry) (*User, error) {
	user := NewUser("")
	user.Source = stringPtr("ldap")
	user.DirectoryID = &s.directory.ID
	user.LdapDN = &entry.DN
	user.Enabled = true
	user.Active = true

	m := s.directory.AttributeMap
	getFirst := func(attr string) string {
		if vals, ok := entry.Attributes[attr]; ok && len(vals) > 0 {
			return vals[0]
		}
		return ""
	}

	// Map standard attributes
	if username := getFirst(m.Username); username != "" {
		user.UserName = username
	} else if username := getFirst("uid"); username != "" {
		user.UserName = username
	} else if username := getFirst("sAMAccountName"); username != "" {
		user.UserName = username
	}

	if email := getFirst(m.Email); email != "" {
		user.SetEmail(email)
	}

	if firstName := getFirst(m.FirstName); firstName != "" {
		user.SetFirstName(firstName)
	}

	if lastName := getFirst(m.LastName); lastName != "" {
		user.SetLastName(lastName)
	}

	if displayName := getFirst(m.DisplayName); displayName != "" {
		user.DisplayName = &displayName
	}

	// Map custom attributes
	user.Attributes = make(map[string]string)
	for localAttr, ldapAttr := range m.CustomAttributes {
		if val := getFirst(ldapAttr); val != "" {
			user.Attributes[localAttr] = val
		}
	}

	// Ensure username is set
	if user.UserName == "" {
		return nil, fmt.Errorf("username attribute not found for DN: %s", entry.DN)
	}

	return user, nil
}

// mapLDAPEntryToGroup converts an LDAP entry to a Group
func (s *LDAPSyncer) mapLDAPEntryToGroup(entry LDAPEntry) (*Group, error) {
	group := NewGroup("")
	group.Source = stringPtr("ldap")
	group.DirectoryID = &s.directory.ID

	m := s.directory.AttributeMap
	getFirst := func(attr string) string {
		if vals, ok := entry.Attributes[attr]; ok && len(vals) > 0 {
			return vals[0]
		}
		return ""
	}

	if name := getFirst(m.GroupName); name != "" {
		group.DisplayName = name
	} else if name := getFirst("cn"); name != "" {
		group.DisplayName = name
	}

	if group.DisplayName == "" {
		return nil, fmt.Errorf("group name not found for DN: %s", entry.DN)
	}

	// Map members - need to resolve DNs to user IDs
	members := getFirst(m.GroupMember)
	if members != "" {
		// For now, store the member DNs in attributes
		// Resolution to user IDs happens in a second pass
		if group.Attributes == nil {
			group.Attributes = make(map[string]string)
		}
		group.Attributes["ldap_members"] = members
	}

	return group, nil
}

// publishUserEvent publishes a user lifecycle event
func (s *LDAPSyncer) publishUserEvent(ctx context.Context, eventType string, user *User) {
	event := events.NewEvent(eventType, "directory.sync", map[string]interface{}{
		"user_id":      user.ID,
		"username":     user.UserName,
		"email":        user.GetPrimaryEmail(),
		"directory_id": s.directory.ID,
		"sync_time":    time.Now().UTC(),
	})

	if s.eventBus != nil {
		s.eventBus.PublishAsync(ctx, event)
	}

	// Send webhook if configured
	if s.webhookURL != nil {
		s.sendWebhook(ctx, eventType, event)
	}
}

// publishGroupEvent publishes a group lifecycle event
func (s *LDAPSyncer) publishGroupEvent(ctx context.Context, eventType string, group *Group) {
	event := events.NewEvent(eventType, "directory.sync", map[string]interface{}{
		"group_id":     group.ID,
		"group_name":   group.DisplayName,
		"directory_id": s.directory.ID,
		"sync_time":    time.Now().UTC(),
	})

	if s.eventBus != nil {
		s.eventBus.PublishAsync(ctx, event)
	}

	if s.webhookURL != nil {
		s.sendWebhook(ctx, eventType, event)
	}
}

// sendWebhook sends a webhook notification (placeholder implementation)
func (s *LDAPSyncer) sendWebhook(ctx context.Context, eventType string, event events.Event) {
	s.logger.Debug("Webhook notification",
		zap.String("event_type", eventType),
		zap.String("event_id", event.ID),
	)
	// In a real implementation, this would make an HTTP POST request
	// to the configured webhook URL
}

// MockLDAPClient is a mock implementation for testing
type MockLDAPClient struct {
	Entries         []LDAPEntry
	ConnectError    error
	SearchError     error
	ShouldDelay     bool
	DelayDuration   time.Duration
	Connected       bool
}

// Connect establishes a connection
func (m *MockLDAPClient) Connect(ctx context.Context) error {
	if m.ConnectError != nil {
		return m.ConnectError
	}
	m.Connected = true
	return nil
}

// Close closes the connection
func (m *MockLDAPClient) Close() error {
	m.Connected = false
	return nil
}

// SearchUsers searches for users
func (m *MockLDAPClient) SearchUsers(ctx context.Context, baseDN, filter string, attrs []string) ([]LDAPEntry, error) {
	if m.SearchError != nil {
		return nil, m.SearchError
	}
	if m.ShouldDelay {
		time.Sleep(m.DelayDuration)
	}
	return m.Entries, nil
}

// SearchGroups searches for groups
func (m *MockLDAPClient) SearchGroups(ctx context.Context, baseDN, filter string, attrs []string) ([]LDAPEntry, error) {
	if m.SearchError != nil {
		return nil, m.SearchError
	}
	return m.Entries, nil
}

// SearchUsersModifiedSince searches for users modified since a time
func (m *MockLDAPClient) SearchUsersModifiedSince(ctx context.Context, baseDN, filter string, since time.Time) ([]LDAPEntry, error) {
	if m.SearchError != nil {
		return nil, m.SearchError
	}
	// Return all entries for mock - in real implementation would filter
	return m.Entries, nil
}

// TLSConfig returns a TLS config for LDAP connections
func TLSConfig(insecureSkipVerify bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
}

// NewDirectory creates a new Directory with generated ID
func NewDirectory(name, dirType string) *Directory {
	now := time.Now()
	return &Directory{
		ID:            uuid.New().String(),
		Name:          name,
		Type:          dirType,
		Enabled:       true,
		Config:        DefaultLDAPConfig(),
		AttributeMap:  DefaultAttributeMapping(),
		SyncInterval:  15 * time.Minute,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}
