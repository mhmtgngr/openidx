// Package identity provides identity repository with PostgreSQL implementation
package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository defines the interface for identity data operations
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

// PostgreSQLRepository implements Repository using PostgreSQL
type PostgreSQLRepository struct {
	pool   *pgxpool.Pool
	baseURL string // Base URL for generating meta.location URLs
}

// NewPostgreSQLRepository creates a new PostgreSQL repository
func NewPostgreSQLRepository(pool *pgxpool.Pool, baseURL string) *PostgreSQLRepository {
	return &PostgreSQLRepository{
		pool:   pool,
		baseURL: baseURL,
	}
}

// Ping checks if the database connection is alive
func (r *PostgreSQLRepository) Ping(ctx context.Context) error {
	return r.pool.Ping(ctx)
}

// CreateUser creates a new user in the database
func (r *PostgreSQLRepository) CreateUser(ctx context.Context, user *User) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Marshal JSON fields
	emailsJSON, err := json.Marshal(user.Emails)
	if err != nil {
		return fmt.Errorf("marshal emails: %w", err)
	}
	phonesJSON, err := json.Marshal(user.PhoneNumbers)
	if err != nil {
		return fmt.Errorf("marshal phone numbers: %w", err)
	}
	photosJSON, err := json.Marshal(user.Photos)
	if err != nil {
		return fmt.Errorf("marshal photos: %w", err)
	}
	addressesJSON, err := json.Marshal(user.Addresses)
	if err != nil {
		return fmt.Errorf("marshal addresses: %w", err)
	}
	groupsJSON, err := json.Marshal(user.Groups)
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}
	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return fmt.Errorf("marshal roles: %w", err)
	}
	entitlementsJSON, err := json.Marshal(user.Entitlements)
	if err != nil {
		return fmt.Errorf("marshal entitlements: %w", err)
	}
	attributesJSON, err := json.Marshal(user.Attributes)
	if err != nil {
		return fmt.Errorf("marshal attributes: %w", err)
	}
	nameJSON, err := json.Marshal(user.Name)
	if err != nil {
		return fmt.Errorf("marshal name: %w", err)
	}
	metaJSON, err := json.Marshal(user.Meta)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}

	query := `
		INSERT INTO users (
			id, external_id, username, display_name, active, name,
			emails, phone_numbers, photos, addresses, groups, roles, entitlements,
			enabled, email_verified, attributes, organization_id, directory_id, ldap_dn, source,
			password_hash, password_changed_at, password_must_change,
			failed_login_count, last_failed_login_at, locked_until,
			created_at, updated_at, deleted_at, last_login_at, meta
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31
		)
	`

	_, err = r.pool.Exec(ctx, query,
		user.ID, user.ExternalID, user.UserName, user.DisplayName, user.Active, nameJSON,
		emailsJSON, phonesJSON, photosJSON, addressesJSON, groupsJSON, rolesJSON, entitlementsJSON,
		user.Enabled, user.EmailVerified, attributesJSON, user.OrganizationID, user.DirectoryID,
		user.LdapDN, user.Source, user.PasswordHash, user.PasswordChangedAt, user.PasswordMustChange,
		user.FailedLoginCount, user.LastFailedLoginAt, user.LockedUntil,
		user.CreatedAt, user.UpdatedAt, user.DeletedAt, user.LastLoginAt, metaJSON,
	)

	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	return nil
}

// GetUser retrieves a user by ID
func (r *PostgreSQLRepository) GetUser(ctx context.Context, id string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, username, display_name, active, name,
			emails, phone_numbers, photos, addresses, groups, roles, entitlements,
			enabled, email_verified, attributes, organization_id, directory_id, ldap_dn, source,
			password_hash, password_changed_at, password_must_change,
			failed_login_count, last_failed_login_at, locked_until,
			created_at, updated_at, deleted_at, last_login_at, meta
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`

	return r.scanUser(r.pool.QueryRow(ctx, query, id))
}

// GetUserByUsername retrieves a user by username
func (r *PostgreSQLRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, username, display_name, active, name,
			emails, phone_numbers, photos, addresses, groups, roles, entitlements,
			enabled, email_verified, attributes, organization_id, directory_id, ldap_dn, source,
			password_hash, password_changed_at, password_must_change,
			failed_login_count, last_failed_login_at, locked_until,
			created_at, updated_at, deleted_at, last_login_at, meta
		FROM users
		WHERE username = $1 AND deleted_at IS NULL
	`

	return r.scanUser(r.pool.QueryRow(ctx, query, username))
}

// GetUserByEmail retrieves a user by email address
func (r *PostgreSQLRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, username, display_name, active, name,
			emails, phone_numbers, photos, addresses, groups, roles, entitlements,
			enabled, email_verified, attributes, organization_id, directory_id, ldap_dn, source,
			password_hash, password_changed_at, password_must_change,
			failed_login_count, last_failed_login_at, locked_until,
			created_at, updated_at, deleted_at, last_login_at, meta
		FROM users
		WHERE emails::jsonb ? $1 AND deleted_at IS NULL
		LIMIT 1
	`

	return r.scanUser(r.pool.QueryRow(ctx, query, email))
}

// GetUserByExternalID retrieves a user by external ID
func (r *PostgreSQLRepository) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, username, display_name, active, name,
			emails, phone_numbers, photos, addresses, groups, roles, entitlements,
			enabled, email_verified, attributes, organization_id, directory_id, ldap_dn, source,
			password_hash, password_changed_at, password_must_change,
			failed_login_count, last_failed_login_at, locked_until,
			created_at, updated_at, deleted_at, last_login_at, meta
		FROM users
		WHERE external_id = $1 AND deleted_at IS NULL
	`

	return r.scanUser(r.pool.QueryRow(ctx, query, externalID))
}

// UpdateUser updates an existing user
func (r *PostgreSQLRepository) UpdateUser(ctx context.Context, user *User) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Marshal JSON fields
	emailsJSON, err := json.Marshal(user.Emails)
	if err != nil {
		return fmt.Errorf("marshal emails: %w", err)
	}
	phonesJSON, err := json.Marshal(user.PhoneNumbers)
	if err != nil {
		return fmt.Errorf("marshal phone numbers: %w", err)
	}
	photosJSON, err := json.Marshal(user.Photos)
	if err != nil {
		return fmt.Errorf("marshal photos: %w", err)
	}
	addressesJSON, err := json.Marshal(user.Addresses)
	if err != nil {
		return fmt.Errorf("marshal addresses: %w", err)
	}
	groupsJSON, err := json.Marshal(user.Groups)
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}
	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return fmt.Errorf("marshal roles: %w", err)
	}
	entitlementsJSON, err := json.Marshal(user.Entitlements)
	if err != nil {
		return fmt.Errorf("marshal entitlements: %w", err)
	}
	attributesJSON, err := json.Marshal(user.Attributes)
	if err != nil {
		return fmt.Errorf("marshal attributes: %w", err)
	}
	nameJSON, err := json.Marshal(user.Name)
	if err != nil {
		return fmt.Errorf("marshal name: %w", err)
	}
	metaJSON, err := json.Marshal(user.Meta)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}

	query := `
		UPDATE users SET
			external_id = $2, username = $3, display_name = $4, active = $5, name = $6,
			emails = $7, phone_numbers = $8, photos = $9, addresses = $10,
			groups = $11, roles = $12, entitlements = $13,
			enabled = $14, email_verified = $15, attributes = $16,
			organization_id = $17, directory_id = $18, ldap_dn = $19, source = $20,
			password_hash = $21, password_changed_at = $22, password_must_change = $23,
			failed_login_count = $24, last_failed_login_at = $25, locked_until = $26,
			updated_at = $27, last_login_at = $28, meta = $29
		WHERE id = $1 AND deleted_at IS NULL
	`

	user.UpdatedAt = time.Now()
	result, err := r.pool.Exec(ctx, query,
		user.ID, user.ExternalID, user.UserName, user.DisplayName, user.Active, nameJSON,
		emailsJSON, phonesJSON, photosJSON, addressesJSON,
		groupsJSON, rolesJSON, entitlementsJSON,
		user.Enabled, user.EmailVerified, attributesJSON,
		user.OrganizationID, user.DirectoryID, user.LdapDN, user.Source,
		user.PasswordHash, user.PasswordChangedAt, user.PasswordMustChange,
		user.FailedLoginCount, user.LastFailedLoginAt, user.LockedUntil,
		user.UpdatedAt, user.LastLoginAt, metaJSON,
	)

	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", user.ID)
	}

	return nil
}

// DeleteUser soft deletes a user by ID
func (r *PostgreSQLRepository) DeleteUser(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `UPDATE users SET deleted_at = $1 WHERE id = $2`
	now := time.Now()

	result, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", id)
	}

	return nil
}

// ListUsers lists users with filtering and pagination
func (r *PostgreSQLRepository) ListUsers(ctx context.Context, filter UserFilter) (*ListResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Set default pagination values
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	// Build WHERE clause
	whereConditions := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argIdx := 1

	if filter.Query != nil && *filter.Query != "" {
		whereConditions = append(whereConditions, fmt.Sprintf(
			"(username ILIKE $%d OR display_name ILIKE $%d OR emails::text ILIKE $%d)",
			argIdx, argIdx+1, argIdx+2,
		))
		queryPattern := "%" + *filter.Query + "%"
		args = append(args, queryPattern, queryPattern, queryPattern)
		argIdx += 3
	}

	if filter.Active != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("active = $%d", argIdx))
		args = append(args, *filter.Active)
		argIdx++
	}

	if filter.OrganizationID != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("organization_id = $%d", argIdx))
		args = append(args, *filter.OrganizationID)
		argIdx++
	}

	if filter.DirectoryID != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("directory_id = $%d", argIdx))
		args = append(args, *filter.DirectoryID)
		argIdx++
	}

	if filter.Source != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("source = $%d", argIdx))
		args = append(args, *filter.Source)
		argIdx++
	}

	if filter.Email != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("emails::jsonb ? $%d", argIdx))
		args = append(args, *filter.Email)
		argIdx++
	}

	if filter.UserName != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("username = $%d", argIdx))
		args = append(args, *filter.UserName)
		argIdx++
	}

	if filter.GroupID != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("groups::jsonb ? $%d", argIdx))
		args = append(args, *filter.GroupID)
		argIdx++
	}

	whereClause := strings.Join(whereConditions, " AND ")

	// Build ORDER BY clause
	orderBy := "created_at DESC"
	if filter.SortBy != "" {
		order := "DESC"
		if filter.SortOrder == "asc" {
			order = "ASC"
		}
		// Prevent SQL injection in sort
		validSortFields := map[string]bool{
			"username": true, "display_name": true, "created_at": true,
			"updated_at": true, "last_login_at": true, "email": true,
		}
		if validSortFields[filter.SortBy] {
			if filter.SortBy == "email" {
				orderBy = fmt.Sprintf("emails->0->>'value' %s", order)
			} else {
				orderBy = fmt.Sprintf("%s %s", filter.SortBy, order)
			}
		}
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users WHERE %s", whereClause)
	var totalResults int
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&totalResults)
	if err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}

	// Get paginated results
	query := fmt.Sprintf(`
		SELECT id, external_id, username, display_name, active, name,
			emails, phone_numbers, photos, addresses, groups, roles, entitlements,
			enabled, email_verified, attributes, organization_id, directory_id, ldap_dn, source,
			password_hash, password_changed_at, password_must_change,
			failed_login_count, last_failed_login_at, locked_until,
			created_at, updated_at, deleted_at, last_login_at, meta
		FROM users
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIdx, argIdx+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*User, error) {
		return r.scanUser(row)
	})
	if err != nil {
		return nil, fmt.Errorf("collect user rows: %w", err)
	}

	return &ListResponse{
		TotalResults: totalResults,
		ItemsPerPage: filter.Limit,
		StartIndex:   filter.Offset + 1,
		Resources:    users,
	}, nil
}

// ListUsersByGroup lists users who are members of a specific group
func (r *PostgreSQLRepository) ListUsersByGroup(ctx context.Context, groupID string, filter UserFilter) (*ListResponse, error) {
	filter.GroupID = &groupID
	return r.ListUsers(ctx, filter)
}

// scanUser scans a User from a database row
func (r *PostgreSQLRepository) scanUser(row pgx.Row) (*User, error) {
	var user User
	var nameJSON, emailsJSON, phonesJSON, photosJSON, addressesJSON []byte
	var groupsJSON, rolesJSON, entitlementsJSON, attributesJSON, metaJSON []byte

	err := row.Scan(
		&user.ID, &user.ExternalID, &user.UserName, &user.DisplayName, &user.Active, &nameJSON,
		&emailsJSON, &phonesJSON, &photosJSON, &addressesJSON, &groupsJSON, &rolesJSON, &entitlementsJSON,
		&user.Enabled, &user.EmailVerified, &attributesJSON, &user.OrganizationID, &user.DirectoryID,
		&user.LdapDN, &user.Source, &user.PasswordHash, &user.PasswordChangedAt, &user.PasswordMustChange,
		&user.FailedLoginCount, &user.LastFailedLoginAt, &user.LockedUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.LastLoginAt, &metaJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("scan user: %w", err)
	}

	// Unmarshal JSON fields
	if len(nameJSON) > 0 {
		if err := json.Unmarshal(nameJSON, &user.Name); err != nil {
			return nil, fmt.Errorf("unmarshal name: %w", err)
		}
	}
	if len(emailsJSON) > 0 {
		if err := json.Unmarshal(emailsJSON, &user.Emails); err != nil {
			return nil, fmt.Errorf("unmarshal emails: %w", err)
		}
	}
	if len(phonesJSON) > 0 {
		if err := json.Unmarshal(phonesJSON, &user.PhoneNumbers); err != nil {
			return nil, fmt.Errorf("unmarshal phone numbers: %w", err)
		}
	}
	if len(photosJSON) > 0 {
		if err := json.Unmarshal(photosJSON, &user.Photos); err != nil {
			return nil, fmt.Errorf("unmarshal photos: %w", err)
		}
	}
	if len(addressesJSON) > 0 {
		if err := json.Unmarshal(addressesJSON, &user.Addresses); err != nil {
			return nil, fmt.Errorf("unmarshal addresses: %w", err)
		}
	}
	if len(groupsJSON) > 0 && string(groupsJSON) != "null" {
		if err := json.Unmarshal(groupsJSON, &user.Groups); err != nil {
			return nil, fmt.Errorf("unmarshal groups: %w", err)
		}
	}
	if len(rolesJSON) > 0 && string(rolesJSON) != "null" {
		if err := json.Unmarshal(rolesJSON, &user.Roles); err != nil {
			return nil, fmt.Errorf("unmarshal roles: %w", err)
		}
	}
	if len(entitlementsJSON) > 0 && string(entitlementsJSON) != "null" {
		if err := json.Unmarshal(entitlementsJSON, &user.Entitlements); err != nil {
			return nil, fmt.Errorf("unmarshal entitlements: %w", err)
		}
	}
	if len(attributesJSON) > 0 && string(attributesJSON) != "null" {
		if err := json.Unmarshal(attributesJSON, &user.Attributes); err != nil {
			return nil, fmt.Errorf("unmarshal attributes: %w", err)
		}
	}
	if len(metaJSON) > 0 {
		if err := json.Unmarshal(metaJSON, &user.Meta); err != nil {
			return nil, fmt.Errorf("unmarshal meta: %w", err)
		}
	}

	return &user, nil
}

// CreateGroup creates a new group
func (r *PostgreSQLRepository) CreateGroup(ctx context.Context, group *Group) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	membersJSON, err := json.Marshal(group.Members)
	if err != nil {
		return fmt.Errorf("marshal members: %w", err)
	}
	attributesJSON, err := json.Marshal(group.Attributes)
	if err != nil {
		return fmt.Errorf("marshal attributes: %w", err)
	}
	metaJSON, err := json.Marshal(group.Meta)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}

	query := `
		INSERT INTO groups (
			id, external_id, display_name, members, organization_id, attributes,
			directory_id, source, created_at, updated_at, deleted_at, meta
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err = r.pool.Exec(ctx, query,
		group.ID, group.ExternalID, group.DisplayName, membersJSON, group.OrganizationID,
		attributesJSON, group.DirectoryID, group.Source,
		group.CreatedAt, group.UpdatedAt, group.DeletedAt, metaJSON,
	)

	if err != nil {
		return fmt.Errorf("insert group: %w", err)
	}

	return nil
}

// GetGroup retrieves a group by ID
func (r *PostgreSQLRepository) GetGroup(ctx context.Context, id string) (*Group, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, display_name, members, organization_id, attributes,
			directory_id, source, created_at, updated_at, deleted_at, meta
		FROM groups
		WHERE id = $1 AND deleted_at IS NULL
	`

	return r.scanGroup(r.pool.QueryRow(ctx, query, id))
}

// GetGroupByDisplayName retrieves a group by display name
func (r *PostgreSQLRepository) GetGroupByDisplayName(ctx context.Context, displayName string) (*Group, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, display_name, members, organization_id, attributes,
			directory_id, source, created_at, updated_at, deleted_at, meta
		FROM groups
		WHERE display_name = $1 AND deleted_at IS NULL
	`

	return r.scanGroup(r.pool.QueryRow(ctx, query, displayName))
}

// GetGroupByExternalID retrieves a group by external ID
func (r *PostgreSQLRepository) GetGroupByExternalID(ctx context.Context, externalID string) (*Group, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, display_name, members, organization_id, attributes,
			directory_id, source, created_at, updated_at, deleted_at, meta
		FROM groups
		WHERE external_id = $1 AND deleted_at IS NULL
	`

	return r.scanGroup(r.pool.QueryRow(ctx, query, externalID))
}

// UpdateGroup updates an existing group
func (r *PostgreSQLRepository) UpdateGroup(ctx context.Context, group *Group) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	membersJSON, err := json.Marshal(group.Members)
	if err != nil {
		return fmt.Errorf("marshal members: %w", err)
	}
	attributesJSON, err := json.Marshal(group.Attributes)
	if err != nil {
		return fmt.Errorf("marshal attributes: %w", err)
	}
	metaJSON, err := json.Marshal(group.Meta)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}

	query := `
		UPDATE groups SET
			external_id = $2, display_name = $3, members = $4, organization_id = $5,
			attributes = $6, directory_id = $7, source = $8, updated_at = $9, meta = $10
		WHERE id = $1 AND deleted_at IS NULL
	`

	group.UpdatedAt = time.Now()
	result, err := r.pool.Exec(ctx, query,
		group.ID, group.ExternalID, group.DisplayName, membersJSON, group.OrganizationID,
		attributesJSON, group.DirectoryID, group.Source, group.UpdatedAt, metaJSON,
	)

	if err != nil {
		return fmt.Errorf("update group: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("group not found: %s", group.ID)
	}

	return nil
}

// DeleteGroup soft deletes a group by ID
func (r *PostgreSQLRepository) DeleteGroup(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `UPDATE groups SET deleted_at = $1 WHERE id = $2`
	now := time.Now()

	result, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("group not found: %s", id)
	}

	return nil
}

// ListGroups lists groups with filtering and pagination
func (r *PostgreSQLRepository) ListGroups(ctx context.Context, filter GroupFilter) (*ListResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	whereConditions := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argIdx := 1

	if filter.Query != nil && *filter.Query != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("display_name ILIKE $%d", argIdx))
		args = append(args, "%"+*filter.Query+"%")
		argIdx++
	}

	if filter.OrganizationID != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("organization_id = $%d", argIdx))
		args = append(args, *filter.OrganizationID)
		argIdx++
	}

	if filter.DirectoryID != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("directory_id = $%d", argIdx))
		args = append(args, *filter.DirectoryID)
		argIdx++
	}

	if filter.Source != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("source = $%d", argIdx))
		args = append(args, *filter.Source)
		argIdx++
	}

	whereClause := strings.Join(whereConditions, " AND ")

	orderBy := "created_at DESC"
	if filter.SortBy != "" {
		order := "DESC"
		if filter.SortOrder == "asc" {
			order = "ASC"
		}
		validSortFields := map[string]bool{
			"display_name": true, "created_at": true, "updated_at": true,
		}
		if validSortFields[filter.SortBy] {
			orderBy = fmt.Sprintf("%s %s", filter.SortBy, order)
		}
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM groups WHERE %s", whereClause)
	var totalResults int
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&totalResults)
	if err != nil {
		return nil, fmt.Errorf("count groups: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT id, external_id, display_name, members, organization_id, attributes,
			directory_id, source, created_at, updated_at, deleted_at, meta
		FROM groups
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIdx, argIdx+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*Group, error) {
		return r.scanGroup(row)
	})
	if err != nil {
		return nil, fmt.Errorf("collect group rows: %w", err)
	}

	return &ListResponse{
		TotalResults: totalResults,
		ItemsPerPage: filter.Limit,
		StartIndex:   filter.Offset + 1,
		Resources:    groups,
	}, nil
}

// ListGroupsByUser lists groups that contain a specific user as a member
func (r *PostgreSQLRepository) ListGroupsByUser(ctx context.Context, userID string, filter GroupFilter) (*ListResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	whereConditions := []string{"deleted_at IS NULL", "members::jsonb ? $1"}
	args := []interface{}{userID}
	argIdx := 2

	if filter.Query != nil && *filter.Query != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("display_name ILIKE $%d", argIdx))
		args = append(args, "%"+*filter.Query+"%")
		argIdx++
	}

	if filter.OrganizationID != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("organization_id = $%d", argIdx))
		args = append(args, *filter.OrganizationID)
		argIdx++
	}

	whereClause := strings.Join(whereConditions, " AND ")

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM groups WHERE %s", whereClause)
	var totalResults int
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&totalResults)
	if err != nil {
		return nil, fmt.Errorf("count groups: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT id, external_id, display_name, members, organization_id, attributes,
			directory_id, source, created_at, updated_at, deleted_at, meta
		FROM groups
		WHERE %s
		ORDER BY display_name ASC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list groups by user: %w", err)
	}
	defer rows.Close()

	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*Group, error) {
		return r.scanGroup(row)
	})
	if err != nil {
		return nil, fmt.Errorf("collect group rows: %w", err)
	}

	return &ListResponse{
		TotalResults: totalResults,
		ItemsPerPage: filter.Limit,
		StartIndex:   filter.Offset + 1,
		Resources:    groups,
	}, nil
}

// AddGroupMember adds a user as a member of a group
func (r *PostgreSQLRepository) AddGroupMember(ctx context.Context, groupID, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Get the group first
	group, err := r.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}

	// Check if user is already a member
	for _, member := range group.Members {
		if member.Value == userID {
			return nil // Already a member
		}
	}

	// Add the new member
	group.Members = append(group.Members, Member{
		Value: userID,
		Type:  "User",
	})

	// Update the group
	return r.UpdateGroup(ctx, group)
}

// RemoveGroupMember removes a user from a group
func (r *PostgreSQLRepository) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Get the group first
	group, err := r.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}

	// Remove the member
	found := false
	newMembers := make([]Member, 0, len(group.Members))
	for _, member := range group.Members {
		if member.Value != userID {
			newMembers = append(newMembers, member)
		} else {
			found = true
		}
	}

	if !found {
		return nil // User was not a member
	}

	group.Members = newMembers
	return r.UpdateGroup(ctx, group)
}

// scanGroup scans a Group from a database row
func (r *PostgreSQLRepository) scanGroup(row pgx.Row) (*Group, error) {
	var group Group
	var membersJSON, attributesJSON, metaJSON []byte

	err := row.Scan(
		&group.ID, &group.ExternalID, &group.DisplayName, &membersJSON, &group.OrganizationID,
		&attributesJSON, &group.DirectoryID, &group.Source,
		&group.CreatedAt, &group.UpdatedAt, &group.DeletedAt, &metaJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("group not found")
		}
		return nil, fmt.Errorf("scan group: %w", err)
	}

	if len(membersJSON) > 0 && string(membersJSON) != "null" {
		if err := json.Unmarshal(membersJSON, &group.Members); err != nil {
			return nil, fmt.Errorf("unmarshal members: %w", err)
		}
	}
	if len(attributesJSON) > 0 && string(attributesJSON) != "null" {
		if err := json.Unmarshal(attributesJSON, &group.Attributes); err != nil {
			return nil, fmt.Errorf("unmarshal attributes: %w", err)
		}
	}
	if len(metaJSON) > 0 {
		if err := json.Unmarshal(metaJSON, &group.Meta); err != nil {
			return nil, fmt.Errorf("unmarshal meta: %w", err)
		}
	}

	return &group, nil
}

// CreateOrganization creates a new organization
func (r *PostgreSQLRepository) CreateOrganization(ctx context.Context, org *Organization) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	brandingJSON, err := json.Marshal(org.Branding)
	if err != nil {
		return fmt.Errorf("marshal branding: %w", err)
	}
	attributesJSON, err := json.Marshal(org.Attributes)
	if err != nil {
		return fmt.Errorf("marshal attributes: %w", err)
	}
	settingsJSON, err := json.Marshal(org.Settings)
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	metaJSON, err := json.Marshal(org.Meta)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}

	query := `
		INSERT INTO organizations (
			id, external_id, name, display_name, description, active, domain, branding,
			attributes, settings, created_at, updated_at, deleted_at, meta
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err = r.pool.Exec(ctx, query,
		org.ID, org.ExternalID, org.Name, org.DisplayName, org.Description, org.Active,
		org.Domain, brandingJSON, attributesJSON, settingsJSON,
		org.CreatedAt, org.UpdatedAt, org.DeletedAt, metaJSON,
	)

	if err != nil {
		return fmt.Errorf("insert organization: %w", err)
	}

	return nil
}

// GetOrganization retrieves an organization by ID
func (r *PostgreSQLRepository) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, name, display_name, description, active, domain, branding,
			attributes, settings, created_at, updated_at, deleted_at, meta
		FROM organizations
		WHERE id = $1 AND deleted_at IS NULL
	`

	return r.scanOrganization(r.pool.QueryRow(ctx, query, id))
}

// GetOrganizationByName retrieves an organization by name
func (r *PostgreSQLRepository) GetOrganizationByName(ctx context.Context, name string) (*Organization, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, name, display_name, description, active, domain, branding,
			attributes, settings, created_at, updated_at, deleted_at, meta
		FROM organizations
		WHERE name = $1 AND deleted_at IS NULL
	`

	return r.scanOrganization(r.pool.QueryRow(ctx, query, name))
}

// GetOrganizationByDomain retrieves an organization by domain
func (r *PostgreSQLRepository) GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, name, display_name, description, active, domain, branding,
			attributes, settings, created_at, updated_at, deleted_at, meta
		FROM organizations
		WHERE domain = $1 AND deleted_at IS NULL
	`

	return r.scanOrganization(r.pool.QueryRow(ctx, query, domain))
}

// GetOrganizationByExternalID retrieves an organization by external ID
func (r *PostgreSQLRepository) GetOrganizationByExternalID(ctx context.Context, externalID string) (*Organization, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, external_id, name, display_name, description, active, domain, branding,
			attributes, settings, created_at, updated_at, deleted_at, meta
		FROM organizations
		WHERE external_id = $1 AND deleted_at IS NULL
	`

	return r.scanOrganization(r.pool.QueryRow(ctx, query, externalID))
}

// UpdateOrganization updates an existing organization
func (r *PostgreSQLRepository) UpdateOrganization(ctx context.Context, org *Organization) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	brandingJSON, err := json.Marshal(org.Branding)
	if err != nil {
		return fmt.Errorf("marshal branding: %w", err)
	}
	attributesJSON, err := json.Marshal(org.Attributes)
	if err != nil {
		return fmt.Errorf("marshal attributes: %w", err)
	}
	settingsJSON, err := json.Marshal(org.Settings)
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	metaJSON, err := json.Marshal(org.Meta)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}

	query := `
		UPDATE organizations SET
			external_id = $2, name = $3, display_name = $4, description = $5, active = $6,
			domain = $7, branding = $8, attributes = $9, settings = $10,
			updated_at = $11, meta = $12
		WHERE id = $1 AND deleted_at IS NULL
	`

	org.UpdatedAt = time.Now()
	result, err := r.pool.Exec(ctx, query,
		org.ID, org.ExternalID, org.Name, org.DisplayName, org.Description, org.Active,
		org.Domain, brandingJSON, attributesJSON, settingsJSON, org.UpdatedAt, metaJSON,
	)

	if err != nil {
		return fmt.Errorf("update organization: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("organization not found: %s", org.ID)
	}

	return nil
}

// DeleteOrganization soft deletes an organization by ID
func (r *PostgreSQLRepository) DeleteOrganization(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `UPDATE organizations SET deleted_at = $1 WHERE id = $2`
	now := time.Now()

	result, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("organization not found: %s", id)
	}

	return nil
}

// ListOrganizations lists organizations with filtering and pagination
func (r *PostgreSQLRepository) ListOrganizations(ctx context.Context, filter OrganizationFilter) (*ListResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	whereConditions := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argIdx := 1

	if filter.Query != nil && *filter.Query != "" {
		whereConditions = append(whereConditions, fmt.Sprintf(
			"(name ILIKE $%d OR display_name ILIKE $%d)",
			argIdx, argIdx+1,
		))
		queryPattern := "%" + *filter.Query + "%"
		args = append(args, queryPattern, queryPattern)
		argIdx += 2
	}

	if filter.Active != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("active = $%d", argIdx))
		args = append(args, *filter.Active)
		argIdx++
	}

	if filter.Domain != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("domain = $%d", argIdx))
		args = append(args, *filter.Domain)
		argIdx++
	}

	whereClause := strings.Join(whereConditions, " AND ")

	orderBy := "created_at DESC"
	if filter.SortBy != "" {
		order := "DESC"
		if filter.SortOrder == "asc" {
			order = "ASC"
		}
		validSortFields := map[string]bool{
			"name": true, "display_name": true, "created_at": true, "updated_at": true,
		}
		if validSortFields[filter.SortBy] {
			orderBy = fmt.Sprintf("%s %s", filter.SortBy, order)
		}
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM organizations WHERE %s", whereClause)
	var totalResults int
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&totalResults)
	if err != nil {
		return nil, fmt.Errorf("count organizations: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT id, external_id, name, display_name, description, active, domain, branding,
			attributes, settings, created_at, updated_at, deleted_at, meta
		FROM organizations
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIdx, argIdx+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	defer rows.Close()

	orgs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*Organization, error) {
		return r.scanOrganization(row)
	})
	if err != nil {
		return nil, fmt.Errorf("collect organization rows: %w", err)
	}

	return &ListResponse{
		TotalResults: totalResults,
		ItemsPerPage: filter.Limit,
		StartIndex:   filter.Offset + 1,
		Resources:    orgs,
	}, nil
}

// scanOrganization scans an Organization from a database row
func (r *PostgreSQLRepository) scanOrganization(row pgx.Row) (*Organization, error) {
	var org Organization
	var brandingJSON, attributesJSON, settingsJSON, metaJSON []byte

	err := row.Scan(
		&org.ID, &org.ExternalID, &org.Name, &org.DisplayName, &org.Description, &org.Active,
		&org.Domain, &brandingJSON, &attributesJSON, &settingsJSON,
		&org.CreatedAt, &org.UpdatedAt, &org.DeletedAt, &metaJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, fmt.Errorf("scan organization: %w", err)
	}

	if len(brandingJSON) > 0 && string(brandingJSON) != "null" {
		if err := json.Unmarshal(brandingJSON, &org.Branding); err != nil {
			return nil, fmt.Errorf("unmarshal branding: %w", err)
		}
	}
	if len(attributesJSON) > 0 && string(attributesJSON) != "null" {
		if err := json.Unmarshal(attributesJSON, &org.Attributes); err != nil {
			return nil, fmt.Errorf("unmarshal attributes: %w", err)
		}
	}
	if len(settingsJSON) > 0 && string(settingsJSON) != "null" {
		if err := json.Unmarshal(settingsJSON, &org.Settings); err != nil {
			return nil, fmt.Errorf("unmarshal settings: %w", err)
		}
	}
	if len(metaJSON) > 0 {
		if err := json.Unmarshal(metaJSON, &org.Meta); err != nil {
			return nil, fmt.Errorf("unmarshal meta: %w", err)
		}
	}

	return &org, nil
}
