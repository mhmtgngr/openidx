// Package identity provides identity management functionality with SCIM-compatible models
package identity

import (
	"strconv"
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system with SCIM-compatible fields
type User struct {
	// SCIM Core Fields
	ID          string    `json:"id" db:"id"`
	ExternalID  *string   `json:"externalId,omitempty" db:"external_id"`
	UserName    string    `json:"userName" db:"username"` // Required by SCIM
	DisplayName *string   `json:"displayName,omitempty" db:"display_name"`
	Active      bool      `json:"active" db:"active"`
	Name        *Name     `json:"name,omitempty" db:"name"`
	Emails      []Email   `json:"emails,omitempty" db:"emails"`
	PhoneNumbers []PhoneNumber `json:"phoneNumbers,omitempty" db:"phone_numbers"`
	Photos      []Photo   `json:"photos,omitempty" db:"photos"`
	Addresses   []Address `json:"addresses,omitempty" db:"addresses"`
	Groups      []string  `json:"groups,omitempty" db:"groups"` // Group IDs
	Entitlements []string `json:"entitlements,omitempty" db:"entitlements"`
	Roles       []string  `json:"roles,omitempty" db:"roles"`

	// OpenIDX Extension Fields
	Enabled       bool              `json:"enabled" db:"enabled"`
	EmailVerified bool              `json:"emailVerified" db:"email_verified"`
	Attributes    map[string]string `json:"attributes,omitempty" db:"attributes"`
	OrganizationID *string          `json:"organizationId,omitempty" db:"organization_id"`
	DirectoryID   *string           `json:"directoryId,omitempty" db:"directory_id"` // For external sync
	LdapDN        *string           `json:"ldapDN,omitempty" db:"ldap_dn"`
	Source        *string           `json:"source,omitempty" db:"source"` // e.g., "ldap", "scim", "manual"

	// Password & Security Fields
	PasswordHash         *string    `json:"-" db:"password_hash"` // Never expose in JSON
	PasswordChangedAt    *time.Time `json:"passwordChangedAt,omitempty" db:"password_changed_at"`
	PasswordMustChange   bool       `json:"passwordMustChange" db:"password_must_change"`
	FailedLoginCount     int        `json:"failedLoginCount" db:"failed_login_count"`
	LastFailedLoginAt    *time.Time `json:"lastFailedLoginAt,omitempty" db:"last_failed_login_at"`
	LockedUntil          *time.Time `json:"lockedUntil,omitempty" db:"locked_until"`

	// Timestamps
	CreatedAt     time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt     time.Time  `json:"updatedAt" db:"updated_at"`
	DeletedAt     *time.Time `json:"deletedAt,omitempty" db:"deleted_at"` // Soft delete
	LastLoginAt   *time.Time `json:"lastLoginAt,omitempty" db:"last_login_at"`

	// SCIM Meta
	Meta *Meta `json:"meta,omitempty" db:"meta"`
}

// GetUsername returns the username (for backward compatibility)
func (u *User) GetUsername() string {
	return u.UserName
}

// SetUsername sets the username (for backward compatibility)
func (u *User) SetUsername(username string) {
	u.UserName = username
}

// GetEmail returns the primary email (for backward compatibility)
func (u *User) GetEmail() string {
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

// SetEmail sets the primary email (for backward compatibility)
func (u *User) SetEmail(email string) {
	if len(u.Emails) == 0 {
		u.Emails = []Email{{Value: email, Primary: boolPtr(true)}}
	} else {
		u.Emails[0].Value = email
	}
}

// GetFirstName returns the first name (for backward compatibility)
func (u *User) GetFirstName() string {
	if u.Name != nil && u.Name.GivenName != nil {
		return *u.Name.GivenName
	}
	return ""
}

// SetFirstName sets the first name (for backward compatibility)
func (u *User) SetFirstName(firstName string) {
	if u.Name == nil {
		u.Name = &Name{}
	}
	u.Name.GivenName = &firstName
}

// GetLastName returns the last name (for backward compatibility)
func (u *User) GetLastName() string {
	if u.Name != nil && u.Name.FamilyName != nil {
		return *u.Name.FamilyName
	}
	return ""
}

// SetLastName sets the last name (for backward compatibility)
func (u *User) SetLastName(lastName string) {
	if u.Name == nil {
		u.Name = &Name{}
	}
	u.Name.FamilyName = &lastName
}

// SetEmailVerified sets the email verified status (for backward compatibility)
func (u *User) SetEmailVerified(verified bool) {
	if len(u.Emails) == 0 {
		u.Emails = []Email{{Value: "", Primary: boolPtr(true)}}
	}
	u.Emails[0].Verified = boolPtr(verified)
}

// Helper function for bool pointers
func boolPtr(b bool) *bool {
	return &b
}

// Helper function for string pointers
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Name represents a user's name with SCIM-compatible structure
type Name struct {
	GivenName     *string `json:"givenName,omitempty" db:"given_name"`
	MiddleName    *string `json:"middleName,omitempty" db:"middle_name"`
	FamilyName    *string `json:"familyName,omitempty" db:"family_name"`
	HonorificPrefix *string `json:"honorificPrefix,omitempty" db:"honorific_prefix"`
	HonorificSuffix *string `json:"honorificSuffix,omitempty" db:"honorific_suffix"`
	Formatted      *string `json:"formatted,omitempty" db:"formatted"`
}

// Email represents an email address with SCIM-compatible structure
type Email struct {
	Value      string  `json:"value" db:"value"`
	Type       *string `json:"type,omitempty" db:"type"` // work, home, other
	Primary    *bool   `json:"primary,omitempty" db:"primary"`
	Display    *string `json:"display,omitempty" db:"display"`
	Verified   *bool   `json:"verified,omitempty" db:"verified"`
}

// PhoneNumber represents a phone number with SCIM-compatible structure
type PhoneNumber struct {
	Value   string  `json:"value" db:"value"`
	Type    *string `json:"type,omitempty" db:"type"` // work, home, mobile, fax, pager, other
	Primary *bool   `json:"primary,omitempty" db:"primary"`
}

// Photo represents a user photo
type Photo struct {
	Value string `json:"value" db:"value"` // URL
	Type  *string `json:"type,omitempty" db:"type"` // photo, thumbnail
}

// Address represents a postal address
type Address struct {
	StreetAddress  *string `json:"streetAddress,omitempty" db:"street_address"`
	Locality       *string `json:"locality,omitempty" db:"locality"`
	Region         *string `json:"region,omitempty" db:"region"`
	PostalCode     *string `json:"postalCode,omitempty" db:"postal_code"`
	Country        *string `json:"country,omitempty" db:"country"`
	Formatted      *string `json:"formatted,omitempty" db:"formatted"`
	Type           *string `json:"type,omitempty" db:"type"`
	Primary        *bool   `json:"primary,omitempty" db:"primary"`
}

// Meta contains SCIM metadata
type Meta struct {
	ResourceType string     `json:"resourceType" db:"resource_type"` // User, Group
	Location     string     `json:"location" db:"location"` // URI to resource
	Created      time.Time  `json:"created" db:"created"`
	LastModified time.Time  `json:"lastModified" db:"last_modified"`
	Version      string     `json:"version" db:"version"` // ETag version
}

// Group represents a group in the system with SCIM-compatible fields
type Group struct {
	ID          string     `json:"id" db:"id"`
	ExternalID  *string    `json:"externalId,omitempty" db:"external_id"`
	DisplayName string     `json:"displayName" db:"display_name"` // Required by SCIM
	Members     []Member   `json:"members,omitempty" db:"members"`

	// OpenIDX Extension Fields
	OrganizationID *string          `json:"organizationId,omitempty" db:"organization_id"`
	Attributes     map[string]string `json:"attributes,omitempty" db:"attributes"`
	DirectoryID    *string          `json:"directoryId,omitempty" db:"directory_id"` // For external sync
	Source         *string          `json:"source,omitempty" db:"source"`

	// Timestamps
	CreatedAt time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time  `json:"updatedAt" db:"updated_at"`
	DeletedAt *time.Time `json:"deletedAt,omitempty" db:"deleted_at"` // Soft delete

	// SCIM Meta
	Meta *Meta `json:"meta,omitempty" db:"meta"`
}

// Member represents a group member reference
type Member struct {
	Value   string `json:"value" db:"value"` // User ID
	Display *string `json:"display,omitempty" db:"display"` // User display name
	Type    string `json:"type" db:"type"` // User or Group
	Ref     *string `json:"$ref,omitempty" db:"ref"` // URI to member
}

// Helper methods for Group to access legacy flat fields from Attributes map

// GetName returns the group name (DisplayName for backward compatibility)
func (g *Group) GetName() string {
	return g.DisplayName
}

// SetName sets the group display name
func (g *Group) SetName(name string) {
	g.DisplayName = name
}

// GetDescription returns the group description from Attributes
func (g *Group) GetDescription() *string {
	if g.Attributes == nil {
		return nil
	}
	if desc, ok := g.Attributes["description"]; ok {
		return &desc
	}
	return nil
}

// SetDescription sets the group description in Attributes
func (g *Group) SetDescription(desc string) {
	if g.Attributes == nil {
		g.Attributes = make(map[string]string)
	}
	g.Attributes["description"] = desc
}

// GetParentID returns the parent group ID from Attributes
func (g *Group) GetParentID() *string {
	if g.Attributes == nil {
		return nil
	}
	if parentID, ok := g.Attributes["parentId"]; ok {
		return &parentID
	}
	return nil
}

// SetParentID sets the parent group ID in Attributes
func (g *Group) SetParentID(parentID string) {
	if g.Attributes == nil {
		g.Attributes = make(map[string]string)
	}
	g.Attributes["parentId"] = parentID
}

// GetAllowSelfJoin returns whether users can self-join from Attributes
func (g *Group) GetAllowSelfJoin() bool {
	if g.Attributes == nil {
		return false
	}
	if val, ok := g.Attributes["allowSelfJoin"]; ok {
		return val == "true"
	}
	return false
}

// SetAllowSelfJoin sets whether users can self-join in Attributes
func (g *Group) SetAllowSelfJoin(allow bool) {
	if g.Attributes == nil {
		g.Attributes = make(map[string]string)
	}
	if allow {
		g.Attributes["allowSelfJoin"] = "true"
	} else {
		g.Attributes["allowSelfJoin"] = "false"
	}
}

// GetRequireApproval returns whether approval is required from Attributes
func (g *Group) GetRequireApproval() bool {
	if g.Attributes == nil {
		return false
	}
	if val, ok := g.Attributes["requireApproval"]; ok {
		return val == "true"
	}
	return false
}

// SetRequireApproval sets whether approval is required in Attributes
func (g *Group) SetRequireApproval(require bool) {
	if g.Attributes == nil {
		g.Attributes = make(map[string]string)
	}
	if require {
		g.Attributes["requireApproval"] = "true"
	} else {
		g.Attributes["requireApproval"] = "false"
	}
}

// GetMaxMembers returns the maximum members from Attributes
func (g *Group) GetMaxMembers() *int {
	if g.Attributes == nil {
		return nil
	}
	if maxStr, ok := g.Attributes["maxMembers"]; ok {
		if maxInt, err := strconv.Atoi(maxStr); err == nil {
			return &maxInt
		}
	}
	return nil
}

// SetMaxMembers sets the maximum members in Attributes
func (g *Group) SetMaxMembers(max int) {
	if g.Attributes == nil {
		g.Attributes = make(map[string]string)
	}
	g.Attributes["maxMembers"] = strconv.Itoa(max)
}

// Organization represents an organization/tenant
type Organization struct {
	ID          string             `json:"id" db:"id"`
	ExternalID  *string            `json:"externalId,omitempty" db:"external_id"`
	Name        string             `json:"name" db:"name"`
	DisplayName string             `json:"displayName" db:"display_name"`
	Description *string            `json:"description,omitempty" db:"description"`
	Active      bool               `json:"active" db:"active"`

	// Domain & Branding
	Domain      *string            `json:"domain,omitempty" db:"domain"` // Primary domain
	Branding    *OrganizationBranding `json:"branding,omitempty" db:"branding"`

	// Settings
	Attributes  map[string]string  `json:"attributes,omitempty" db:"attributes"`
	Settings    map[string]interface{} `json:"settings,omitempty" db:"settings"`

	// Timestamps
	CreatedAt   time.Time          `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time          `json:"updatedAt" db:"updated_at"`
	DeletedAt   *time.Time         `json:"deletedAt,omitempty" db:"deleted_at"` // Soft delete

	// SCIM Meta
	Meta *Meta `json:"meta,omitempty" db:"meta"`
}

// OrganizationBranding contains branding settings for an organization
type OrganizationBranding struct {
	LogoURL      *string `json:"logoUrl,omitempty" db:"logo_url"`
	PrimaryColor *string `json:"primaryColor,omitempty" db:"primary_color"`
	SecondaryColor *string `json:"secondaryColor,omitempty" db:"secondary_color"`
	Theme        *string `json:"theme,omitempty" db:"theme"` // light, dark, auto
	CustomCSS    *string `json:"customCSS,omitempty" db:"custom_css"`
}

// PaginationParams contains pagination parameters
type PaginationParams struct {
	Offset      int    `json:"offset,omitempty"` // Offset for pagination
	Limit       int    `json:"limit,omitempty"`  // Limit for pagination (max 100)
	SortBy      string `json:"sortBy,omitempty"` // Field to sort by
	SortOrder   string `json:"sortOrder,omitempty"` // asc or desc
}

// UserFilter contains filter parameters for listing users
type UserFilter struct {
	PaginationParams
	Query         *string  `json:"query,omitempty"` // Search in username, email, display name
	Active        *bool    `json:"active,omitempty"`
	OrganizationID *string `json:"organizationId,omitempty"`
	DirectoryID   *string  `json:"directoryId,omitempty"`
	Source        *string  `json:"source,omitempty"`
	GroupID       *string  `json:"groupId,omitempty"` // Filter by group membership
	Email         *string  `json:"email,omitempty"`
	UserName      *string  `json:"userName,omitempty"`
}

// GroupFilter contains filter parameters for listing groups
type GroupFilter struct {
	PaginationParams
	Query         *string `json:"query,omitempty"` // Search in display name
	Active        *bool   `json:"active,omitempty"`
	OrganizationID *string `json:"organizationId,omitempty"`
	DirectoryID   *string `json:"directoryId,omitempty"`
	Source        *string `json:"source,omitempty"`
}

// OrganizationFilter contains filter parameters for listing organizations
type OrganizationFilter struct {
	PaginationParams
	Query  *string `json:"query,omitempty"` // Search in name, display name
	Active *bool   `json:"active,omitempty"`
	Domain *string `json:"domain,omitempty"`
}

// ListResponse is a generic paginated list response with SCIM formatting
type ListResponse struct {
	TotalResults int           `json:"totalResults"`
	ItemsPerPage int           `json:"itemsPerPage"`
	StartIndex   int           `json:"startIndex"`
	Resources    interface{}   `json:"resources"` // []User, []Group, or []Organization
}

// NewUser creates a new User instance with a generated ID
func NewUser(username string) *User {
	now := time.Now()
	return &User{
		ID:        uuid.New().String(),
		UserName:  username,
		Active:    true,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
		Meta: &Meta{
			ResourceType: "User",
			Created:      now,
			LastModified: now,
			Version:      "1",
		},
	}
}

// NewGroup creates a new Group instance with a generated ID
func NewGroup(displayName string) *Group {
	now := time.Now()
	return &Group{
		ID:          uuid.New().String(),
		DisplayName: displayName,
		CreatedAt:   now,
		UpdatedAt:   now,
		Meta: &Meta{
			ResourceType: "Group",
			Created:      now,
			LastModified: now,
			Version:      "1",
		},
	}
}

// NewOrganization creates a new Organization instance with a generated ID
func NewOrganization(name, displayName string) *Organization {
	now := time.Now()
	return &Organization{
		ID:          uuid.New().String(),
		Name:        name,
		DisplayName: displayName,
		Active:      true,
		CreatedAt:   now,
		UpdatedAt:   now,
		Meta: &Meta{
			ResourceType: "Organization",
			Created:      now,
			LastModified: now,
			Version:      "1",
		},
	}
}

// GetPrimaryEmail returns the primary email address or the first email if none marked as primary
func (u *User) GetPrimaryEmail() string {
	if len(u.Emails) == 0 {
		return ""
	}
	for _, email := range u.Emails {
		if email.Primary != nil && *email.Primary {
			return email.Value
		}
	}
	return u.Emails[0].Value
}

// GetPrimaryPhoneNumber returns the primary phone number or the first one if none marked as primary
func (u *User) GetPrimaryPhoneNumber() string {
	if len(u.PhoneNumbers) == 0 {
		return ""
	}
	for _, phone := range u.PhoneNumbers {
		if phone.Primary != nil && *phone.Primary {
			return phone.Value
		}
	}
	return u.PhoneNumbers[0].Value
}

// GetFormattedName returns the formatted full name
func (u *User) GetFormattedName() string {
	if u.Name != nil && u.Name.Formatted != nil && *u.Name.Formatted != "" {
		return *u.Name.Formatted
	}

	var parts []string
	if u.Name != nil {
		if u.Name.GivenName != nil && *u.Name.GivenName != "" {
			parts = append(parts, *u.Name.GivenName)
		}
		if u.Name.FamilyName != nil && *u.Name.FamilyName != "" {
			parts = append(parts, *u.Name.FamilyName)
		}
	}

	if len(parts) > 0 {
		return parts[0] + " " + parts[1]
	}

	if u.DisplayName != nil && *u.DisplayName != "" {
		return *u.DisplayName
	}

	return u.UserName
}

// IsLocked returns true if the user account is currently locked
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return u.LockedUntil.After(time.Now())
}

// UpdateMeta updates the meta information for the user
func (u *User) UpdateMeta(baseURL string) {
	now := time.Now()
	u.UpdatedAt = now
	if u.Meta == nil {
		u.Meta = &Meta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			Version:      "1",
		}
	}
	u.Meta.LastModified = now
	u.Meta.Version = uuid.New().String()
	if baseURL != "" {
		u.Meta.Location = baseURL + "/Users/" + u.ID
	}
}

// UpdateMeta updates the meta information for the group
func (g *Group) UpdateMeta(baseURL string) {
	now := time.Now()
	g.UpdatedAt = now
	if g.Meta == nil {
		g.Meta = &Meta{
			ResourceType: "Group",
			Created:      g.CreatedAt,
			Version:      "1",
		}
	}
	g.Meta.LastModified = now
	g.Meta.Version = uuid.New().String()
	if baseURL != "" {
		g.Meta.Location = baseURL + "/Groups/" + g.ID
	}
}

// UpdateMeta updates the meta information for the organization
func (o *Organization) UpdateMeta(baseURL string) {
	now := time.Now()
	o.UpdatedAt = now
	if o.Meta == nil {
		o.Meta = &Meta{
			ResourceType: "Organization",
			Created:      o.CreatedAt,
			Version:      "1",
		}
	}
	o.Meta.LastModified = now
	o.Meta.Version = uuid.New().String()
	if baseURL != "" {
		o.Meta.Location = baseURL + "/Organizations/" + o.ID
	}
}
