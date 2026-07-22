// Package identity — user data-access layer.
//
// This file is the REFERENCE IMPLEMENTATION of the Repository pattern for
// OpenIDX (see docs/architecture/design-patterns-review.md §1). It exists to
// show the target shape for splitting the god-object services into three
// collaborators:
//
//	handler  (gin)      -> parse/validate, call service, render via apierror
//	service  (domain)   -> business rules, depends on the UserRepository interface
//	repository (this)   -> the ONLY place user SQL lives; owns primary vs replica
//
// Why this matters:
//   - business logic becomes unit-testable with a fake repo (no live Postgres),
//   - all user SQL is in one type instead of scattered across ~145 call sites,
//   - read-mostly queries transparently use the read replica via db.Reader()
//     (Tier 1.6) without any handler/service change,
//   - the tenant boundary (org scoping) is enforced consistently in one place.
//
// Adoption is incremental (strangler-fig): new/changed user reads route through
// UserRepository; the legacy Service methods can delegate here and be deleted as
// they empty out. This file intentionally implements only the core reads as the
// template — extend method-by-method.
package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ErrUserNotFound is returned by the repository when no user matches within the
// caller's tenant scope. Callers map it to a 404 (see apierror). It is a
// sentinel so services can branch on it with errors.Is without string matching.
var ErrUserNotFound = errors.New("user not found")

// UserRepository is the data-access port for users. Depending on this interface
// (not the concrete pgx type) is what makes the domain layer unit-testable: a
// test supplies a fake, production supplies PostgresUserRepository.
//
// All methods are tenant-scoped: they derive the org from the context (set by
// the tenant resolver) and filter by it, so a caller can never read another
// tenant's user. A cross-tenant id reads as ErrUserNotFound, not a 403, so the
// existence of other tenants' users can't be probed.
type UserRepository interface {
	// GetByID returns the user with the given id within the caller's tenant, or
	// ErrUserNotFound. Read-only: served by the read replica when configured.
	GetByID(ctx context.Context, id string) (*User, error)

	// GetByUsername returns the user with the given username within the caller's
	// tenant, or ErrUserNotFound. Read-only.
	GetByUsername(ctx context.Context, username string) (*User, error)

	// GetByEmail returns the user with the given email within the caller's
	// tenant, or ErrUserNotFound. Read-only.
	GetByEmail(ctx context.Context, email string) (*User, error)

	// Exists reports whether a user with the given id exists in the caller's
	// tenant. Read-only.
	Exists(ctx context.Context, id string) (bool, error)

	// Create inserts a new user in the caller's tenant. WRITE: uses the primary
	// pool. On success the generated id and timestamps are written back onto the
	// passed *User. A duplicate username/email surfaces as ErrUserAlreadyExists.
	Create(ctx context.Context, user *User) error

	// Update mutates an existing user's core fields in the caller's tenant.
	// WRITE: primary pool. Returns ErrUserNotFound when no row matches (so a
	// cross-tenant id can't be probed or written).
	Update(ctx context.Context, user *User) error

	// Delete removes a user row in the caller's tenant. WRITE: primary pool.
	// Returns ErrUserNotFound when no row matches. NOTE: this only removes the
	// row — the service is responsible for ordering audit + deprovisioning
	// (session/API-key/PAM revocation) around it.
	Delete(ctx context.Context, id string) error
}

// ErrUserAlreadyExists is returned by Create on a unique-constraint violation
// (duplicate username or email within the tenant). Callers map it to 409.
var ErrUserAlreadyExists = errors.New("user already exists")

// PostgresUserRepository is the pgx implementation of UserRepository. It holds
// the *database.PostgresDB so it can pick the primary pool (writes / read-your-
// write) or the replica pool (Reader(), read-mostly) per query — the seam that
// makes the Tier 1.6 read replica usable without touching callers.
type PostgresUserRepository struct {
	db *database.PostgresDB
}

// NewPostgresUserRepository constructs the pgx-backed user repository.
func NewPostgresUserRepository(db *database.PostgresDB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

// userSelectColumns is the canonical column list + NULL-coalescing for scanning
// a UserDB. Centralized so every user read stays consistent (first_name/last_name
// are nullable for SCIM users with no name; a raw NULL would error the scan).
const userSelectColumns = `
	id, username, email,
	COALESCE(first_name, '') AS first_name,
	COALESCE(last_name, '')  AS last_name,
	enabled, email_verified,
	created_at, updated_at, last_login_at, password_changed_at,
	password_must_change, failed_login_count, last_failed_login_at, locked_until`

// scanUser scans one row (in userSelectColumns order) into a UserDB.
func scanUser(row pgx.Row) (*UserDB, error) {
	var u UserDB
	err := row.Scan(
		&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName,
		&u.Enabled, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
		&u.PasswordChangedAt, &u.PasswordMustChange, &u.FailedLoginCount,
		&u.LastFailedLoginAt, &u.LockedUntil,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetByID implements UserRepository.
func (r *PostgresUserRepository) GetByID(ctx context.Context, id string) (*User, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Read-mostly: use the replica pool when one is configured (Tier 1.6). The
	// RLS checkout hook still stamps app.org_id, and we filter by org explicitly
	// as defense in depth.
	query := `SELECT ` + userSelectColumns + ` FROM users WHERE id = $1 AND org_id = $2`
	dbUser, err := scanUser(r.db.Reader().QueryRow(ctx, query, id, org.ID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	user := dbUser.ToUser()
	return &user, nil
}

// GetByUsername implements UserRepository.
func (r *PostgresUserRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	query := `SELECT ` + userSelectColumns + ` FROM users WHERE username = $1 AND org_id = $2`
	dbUser, err := scanUser(r.db.Reader().QueryRow(ctx, query, username, org.ID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user by username: %w", err)
	}
	user := dbUser.ToUser()
	return &user, nil
}

// GetByEmail implements UserRepository.
func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	query := `SELECT ` + userSelectColumns + ` FROM users WHERE email = $1 AND org_id = $2`
	dbUser, err := scanUser(r.db.Reader().QueryRow(ctx, query, email, org.ID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	user := dbUser.ToUser()
	return &user, nil
}

// Exists implements UserRepository.
func (r *PostgresUserRepository) Exists(ctx context.Context, id string) (bool, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}
	var exists bool
	err = r.db.Reader().QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND org_id = $2)`,
		id, org.ID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("user exists check: %w", err)
	}
	return exists, nil
}

// isUniqueViolation reports whether err is a Postgres 23505 unique_violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Create implements UserRepository. WRITE — uses the primary pool. Reads-your-
// write callers therefore see the row immediately (a replica could lag).
func (r *PostgresUserRepository) Create(ctx context.Context, user *User) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	dbUser := FromUser(*user)
	if dbUser.ID == "" {
		dbUser.ID = uuid.New().String()
	}
	now := time.Now()
	dbUser.CreatedAt = now
	dbUser.UpdatedAt = now

	_, err = r.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, first_name, last_name, enabled,
		                   email_verified, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, dbUser.ID, dbUser.Username, dbUser.Email, dbUser.FirstName, dbUser.LastName,
		dbUser.Enabled, dbUser.EmailVerified, dbUser.CreatedAt, dbUser.UpdatedAt, org.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrUserAlreadyExists
		}
		return fmt.Errorf("create user: %w", err)
	}

	// Write the generated id + timestamps back so the caller (and its audit /
	// webhook hooks) see the real values.
	user.ID = dbUser.ID
	user.CreatedAt = dbUser.CreatedAt
	user.UpdatedAt = dbUser.UpdatedAt
	return nil
}

// Update implements UserRepository. WRITE — primary pool. Returns
// ErrUserNotFound when no row in the tenant matches.
func (r *PostgresUserRepository) Update(ctx context.Context, user *User) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	dbUser := FromUser(*user)
	dbUser.UpdatedAt = time.Now()

	result, err := r.db.Pool.Exec(ctx, `
		UPDATE users
		SET username = $2, email = $3, first_name = $4, last_name = $5,
		    enabled = $6, email_verified = $7, updated_at = $8
		WHERE id = $1 AND org_id = $9
	`, dbUser.ID, dbUser.Username, dbUser.Email, dbUser.FirstName, dbUser.LastName,
		dbUser.Enabled, dbUser.EmailVerified, dbUser.UpdatedAt, org.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrUserAlreadyExists
		}
		return fmt.Errorf("update user: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	user.UpdatedAt = dbUser.UpdatedAt
	return nil
}

// Delete implements UserRepository. WRITE — primary pool. Only removes the row;
// the service orders audit + deprovisioning around this call.
func (r *PostgresUserRepository) Delete(ctx context.Context, id string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	result, err := r.db.Pool.Exec(ctx,
		`DELETE FROM users WHERE id = $1 AND org_id = $2`, id, org.ID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// Ensure the concrete type satisfies the interface at compile time.
var _ UserRepository = (*PostgresUserRepository)(nil)
