# Identity Models and Repository

This package provides SCIM 2.0 compatible data models and PostgreSQL repository implementation for the OpenIDX Identity Service.

## Overview

The identity package includes:

- **SCIM 2.0 compatible models** for Users, Groups, and Organizations
- **PostgreSQL repository** with full CRUD operations
- **Pagination and filtering** support for all list operations
- **Soft delete** functionality for data retention
- **External ID mapping** for SCIM/LDAP synchronization
- **Flexible attributes** using JSONB for extensibility

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Identity Service                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Repository Interface                    │   │
│  │  - CreateUser, GetUser, UpdateUser, DeleteUser       │   │
│  │  - CreateGroup, GetGroup, UpdateGroup, DeleteGroup   │   │
│  │  - CreateOrganization, GetOrganization, etc.          │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │         PostgreSQLRepository                        │   │
│  │  - Connection pooling with pgx/v5                   │   │
│  │  - Prepared statements with WHERE clause builders   │   │
│  │  - JSON marshaling for complex fields               │   │
│  │  - Pagination with offset/limit                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Models

### User

SCIM 2.0 compatible user model with the following fields:

**Core SCIM Fields:**
- `id` - Unique identifier (UUID)
- `externalId` - External identifier from identity provider
- `userName` - Unique username (required)
- `displayName` - Human-readable display name
- `active` - Account active status
- `name` - Name object (givenName, familyName, etc.)
- `emails` - Email addresses array
- `phoneNumbers` - Phone numbers array
- `photos` - Profile photos
- `addresses` - Postal addresses
- `groups` - Group membership array
- `entitlements` - Entitlements array
- `roles` - Role assignments

**OpenIDX Extensions:**
- `enabled` - Account enabled flag
- `emailVerified` - Email verification status
- `attributes` - Flexible key-value attributes
- `organizationId` - Organization reference
- `directoryId` - External directory reference (LDAP/SCIM)
- `source` - Source system ('ldap', 'scim', 'manual')

**Security Fields:**
- `passwordHash` - Bcrypt password hash (never exposed in JSON)
- `passwordChangedAt` - Last password change timestamp
- `passwordMustChange` - Force password change flag
- `failedLoginCount` - Failed login attempts
- `lastFailedLoginAt` - Last failed login timestamp
- `lockedUntil` - Account lock expiration

### Group

SCIM 2.0 compatible group model:

**Core SCIM Fields:**
- `id` - Unique identifier (UUID)
- `externalId` - External identifier
- `displayName` - Group display name (required)
- `members` - Array of member references

**OpenIDX Extensions:**
- `organizationId` - Organization reference
- `attributes` - Flexible attributes
- `directoryId` - External directory reference
- `source` - Source system

### Organization

Organization/tenant model:

**Core Fields:**
- `id` - Unique identifier (UUID)
- `externalId` - External identifier
- `name` - Unique organization name
- `displayName` - Human-readable name
- `description` - Organization description
- `active` - Organization active status

**Branding:**
- `domain` - Primary domain
- `branding` - Logo, colors, theme, custom CSS

**Settings:**
- `attributes` - Flexible key-value attributes
- `settings` - Organization settings (JSON)

## Repository Interface

The Repository interface defines all CRUD operations:

```go
type Repository interface {
    // User operations
    CreateUser(ctx context.Context, user *User) error
    GetUser(ctx context.Context, id string) (*User, error)
    GetUserByUsername(ctx context.Context, username string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)
    GetUserByExternalID(ctx context.Context, externalID string) (*User, error)
    UpdateUser(ctx context.Context, user *User) error
    DeleteUser(ctx context.Context, id string) error
    ListUsers(ctx context.Context, filter UserFilter) (*ListResponse, error)
    ListUsersByGroup(ctx context.Context, groupID string, filter UserFilter) (*ListResponse, error)

    // Group operations
    CreateGroup(ctx context.Context, group *Group) error
    GetGroup(ctx context.Context, id string) (*Group, error)
    GetGroupByDisplayName(ctx context.Context, displayName string) (*Group, error)
    GetGroupByExternalID(ctx context.Context, externalID string) (*Group, error)
    UpdateGroup(ctx context.Context, group *Group) error
    DeleteGroup(ctx context.Context, id string) error
    ListGroups(ctx context.Context, filter GroupFilter) (*ListResponse, error)
    ListGroupsByUser(ctx context.Context, userID string, filter GroupFilter) (*ListResponse, error)
    AddGroupMember(ctx context.Context, groupID, userID string) error
    RemoveGroupMember(ctx context.Context, groupID, userID string) error

    // Organization operations
    CreateOrganization(ctx context.Context, org *Organization) error
    GetOrganization(ctx context.Context, id string) (*Organization, error)
    GetOrganizationByName(ctx context.Context, name string) (*Organization, error)
    GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error)
    GetOrganizationByExternalID(ctx context.Context, externalID string) (*Organization, error)
    UpdateOrganization(ctx context.Context, org *Organization) error
    DeleteOrganization(ctx context.Context, id string) error
    ListOrganizations(ctx context.Context, filter OrganizationFilter) (*ListResponse, error)

    // Health check
    Ping(ctx context.Context) error
}
```

## Usage Examples

### Creating a Repository

```go
import (
    "context"
    "github.com/openidx/openidx/internal/common/database"
    "github.com/openidx/openidx/internal/identity"
)

// Create database connection
db, err := database.NewPostgres("postgres://localhost:5432/openidx?sslmode=disable")
if err != nil {
    log.Fatal(err)
}
defer db.Close()

// Create repository
repo := identity.NewPostgreSQLRepository(db.Pool, "http://localhost:8001/scim/v2")
```

### Creating a User

```go
user := identity.NewUser("john.doe")
user.DisplayName = stringPtr("John Doe")
user.Name = &identity.Name{
    GivenName:  stringPtr("John"),
    FamilyName: stringPtr("Doe"),
}
user.Emails = []identity.Email{
    {
        Value:   "john.doe@example.com",
        Type:    stringPtr("work"),
        Primary: boolPtr(true),
    },
}
user.Active = true
user.Enabled = true
user.EmailVerified = true
user.Source = stringPtr("manual")

err := repo.CreateUser(ctx, user)
if err != nil {
    log.Fatal(err)
}
```

### Listing Users with Pagination

```go
filter := identity.UserFilter{
    PaginationParams: identity.PaginationParams{
        Limit:     50,
        Offset:    0,
        SortBy:    "username",
        SortOrder: "asc",
    },
    Query:   stringPtr("john"),
    Active:  boolPtr(true),
}

result, err := repo.ListUsers(ctx, filter)
if err != nil {
    log.Fatal(err)
}

users := result.Resources.([]*identity.User)
fmt.Printf("Found %d of %d users\n", len(users), result.TotalResults)
```

### SCIM Synchronization

```go
// Check if user exists by external ID
user, err := repo.GetUserByExternalID(ctx, "ext-12345-from-azure-ad")
if err != nil {
    // Create new user
    user := identity.NewUser("jane.smith")
    user.ExternalID = stringPtr("ext-12345-from-azure-ad")
    user.DisplayName = stringPtr("Jane Smith")
    user.Emails = []identity.Email{
        {Value: "jane.smith@example.com", Type: stringPtr("work"), Primary: boolPtr(true)},
    }
    user.Source = stringPtr("scim")
    user.UpdateMeta(repo.baseURL)

    err = repo.CreateUser(ctx, user)
} else {
    // Update existing user
    user.DisplayName = stringPtr("Jane Smith Updated")
    user.UpdateMeta(repo.baseURL)
    err = repo.UpdateUser(ctx, user)
}
```

### Group Management

```go
// Create group
group := identity.NewGroup("Engineering")
group.DisplayName = "Engineering Team"
err := repo.CreateGroup(ctx, group)

// Add user to group
err = repo.AddGroupMember(ctx, group.ID, userID)

// List user's groups
filter := identity.GroupFilter{PaginationParams: identity.PaginationParams{Limit: 10}}
result, err := repo.ListGroupsByUser(ctx, userID, filter)
groups := result.Resources.([]*identity.Group)

// Remove user from group
err = repo.RemoveGroupMember(ctx, group.ID, userID)
```

## Database Schema

The repository uses the following tables (defined in `migrations/008_add_scim_identity_tables.sql`):

### users_v2

- SCIM 2.0 compatible users table
- JSONB fields for emails, phoneNumbers, photos, addresses, groups, roles
- Soft delete support with `deleted_at` column
- Full-text search index on username, display_name, emails
- GIN indexes for JSONB array operations

### groups_v2

- SCIM 2.0 compatible groups table
- JSONB members array with Member objects
- Organization and directory references
- Soft delete support

### organizations_v2

- Organizations/tenants table
- Branding and settings stored as JSONB
- Domain uniqueness constraint
- Soft delete support

## Filtering and Pagination

All list operations support:

**Pagination:**
- `offset` - Number of items to skip
- `limit` - Maximum items per page (max 100)
- `sortBy` - Field to sort by
- `sortOrder` - "asc" or "desc"

**User Filters:**
- `query` - Search in username, display_name, emails
- `active` - Filter by active status
- `organizationId` - Filter by organization
- `directoryId` - Filter by directory
- `source` - Filter by source system
- `groupId` - Filter by group membership
- `email` - Filter by email address
- `userName` - Filter by exact username

**Group Filters:**
- `query` - Search in display_name
- `organizationId` - Filter by organization
- `directoryId` - Filter by directory
- `source` - Filter by source system

**Organization Filters:**
- `query` - Search in name, display_name
- `active` - Filter by active status
- `domain` - Filter by domain

## Helper Methods

### User Methods

```go
// Get primary email
email := user.GetPrimaryEmail()

// Get formatted full name
name := user.GetFormattedName()

// Check if account is locked
if user.IsLocked() {
    // Account is locked
}

// Update SCIM metadata
user.UpdateMeta(baseURL)
```

### Group Methods

```go
// Update SCIM metadata
group.UpdateMeta(baseURL)
```

### Organization Methods

```go
// Update SCIM metadata
org.UpdateMeta(baseURL)
```

## Migration

To use the new identity models with existing data:

1. Run the migration:
```bash
psql -U openidx -d openidx -f migrations/008_add_scim_identity_tables.sql
```

2. Migrate existing users from `users` to `users_v2` (custom script required)

3. Update service code to use new repository

4. Verify data integrity

## Performance Considerations

- **Connection Pooling**: Repository uses pgxpool with configurable pool size
- **Prepared Statements**: All queries use parameterized statements
- **Indexes**: GIN indexes on JSONB fields for fast lookups
- **Pagination**: Always use limit/offset to avoid loading large result sets
- **Context Timeouts**: Queries have 5-10 second timeouts
- **Soft Delete**: Filter out deleted_at IS NULL for performance

## Security

- **Password Hash**: Never exposed in JSON, stored separately
- **Input Validation**: CHECK constraints on NOT NULL fields
- **SQL Injection**: All queries use parameterized statements
- **Soft Delete**: Data retention for audit purposes
- **External ID Mapping**: Supports secure SCIM/LDAP integration

## Testing

See `repository_example_test.go` for usage examples and test patterns.

## SCIM 2.0 Compliance

The models are designed to be SCIM 2.0 compliant (RFC 7643):

- ✅ Core User attributes (userName, name, emails, etc.)
- ✅ Core Group attributes (displayName, members)
- ✅ Meta attributes (resourceType, location, version)
- ✅ Multi-value attributes (emails, phoneNumbers, etc.)
- ✅ Extension schema support (attributes JSONB)
- ✅ External ID mapping for provisioning
- ✅ Bulk operations support (via repository)
- ✅ Filtering and pagination

## Future Enhancements

- [ ] Add database transaction support
- [ ] Add caching layer (Redis)
- [ ] Add audit logging
- [ ] Add bulk import/export
- [ ] Add data validation layer
- [ ] Add event hooks for sync
- [ ] Add GraphQL query support
