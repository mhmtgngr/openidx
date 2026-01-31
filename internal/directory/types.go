// Package directory provides LDAP/Active Directory synchronization
package directory

import "time"

// LDAPConfig holds LDAP connection and search configuration
type LDAPConfig struct {
	Host              string           `json:"host"`
	Port              int              `json:"port"`
	UseTLS            bool             `json:"use_tls"`
	StartTLS          bool             `json:"start_tls"`
	SkipTLSVerify     bool             `json:"skip_tls_verify"`
	BindDN            string           `json:"bind_dn"`
	BindPassword      string           `json:"bind_password"`
	BaseDN            string           `json:"base_dn"`
	UserBaseDN        string           `json:"user_base_dn"`
	GroupBaseDN       string           `json:"group_base_dn"`
	UserFilter        string           `json:"user_filter"`
	GroupFilter       string           `json:"group_filter"`
	MemberAttribute   string           `json:"member_attribute"`
	PageSize          int              `json:"page_size"`
	SyncInterval      int              `json:"sync_interval"` // minutes, 0=disabled
	SyncEnabled       bool             `json:"sync_enabled"`
	DeprovisionAction string           `json:"deprovision_action"` // "disable" or "delete"
	AttributeMapping  AttributeMapping `json:"attribute_mapping"`
}

// AttributeMapping maps LDAP attributes to OpenIDX user fields
type AttributeMapping struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	DisplayName string `json:"display_name"`
	GroupName   string `json:"group_name"`
}

// UserRecord represents a user extracted from LDAP
type UserRecord struct {
	DN          string
	Username    string
	Email       string
	FirstName   string
	LastName    string
	DisplayName string
}

// GroupRecord represents a group extracted from LDAP
type GroupRecord struct {
	DN          string
	Name        string
	Description string
	MemberDNs   []string
}

// SyncResult holds the results of a directory sync operation
type SyncResult struct {
	UsersAdded    int           `json:"users_added"`
	UsersUpdated  int           `json:"users_updated"`
	UsersDisabled int           `json:"users_disabled"`
	GroupsAdded   int           `json:"groups_added"`
	GroupsUpdated int           `json:"groups_updated"`
	GroupsDeleted int           `json:"groups_deleted"`
	Errors        []string      `json:"errors,omitempty"`
	Duration      time.Duration `json:"duration_ms"`
}

// SyncLog represents a sync log entry from the database
type SyncLog struct {
	ID            string     `json:"id"`
	DirectoryID   string     `json:"directory_id"`
	SyncType      string     `json:"sync_type"`
	Status        string     `json:"status"`
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	UsersAdded    int        `json:"users_added"`
	UsersUpdated  int        `json:"users_updated"`
	UsersDisabled int        `json:"users_disabled"`
	GroupsAdded   int        `json:"groups_added"`
	GroupsUpdated int        `json:"groups_updated"`
	GroupsDeleted int        `json:"groups_deleted"`
	ErrorMessage  *string    `json:"error_message,omitempty"`
}

// SyncState represents the current sync state for a directory
type SyncState struct {
	DirectoryID        string     `json:"directory_id"`
	LastSyncAt         *time.Time `json:"last_sync_at,omitempty"`
	LastUSNChanged     *int64     `json:"last_usn_changed,omitempty"`
	LastModifyTimestamp *string   `json:"last_modify_timestamp,omitempty"`
	UsersSynced        int        `json:"users_synced"`
	GroupsSynced       int        `json:"groups_synced"`
	ErrorsCount        int        `json:"errors_count"`
	SyncDurationMs     *int       `json:"sync_duration_ms,omitempty"`
}
