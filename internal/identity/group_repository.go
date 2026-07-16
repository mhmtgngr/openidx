// Package identity — group data-access layer.
//
// GroupRepository is the second aggregate extracted with the Repository pattern
// (after UserRepository — see user_repository.go and
// docs/architecture/design-patterns-review.md). It exists to show the template
// repeats cleanly: reads on db.Reader() (replica), writes on db.Pool (primary),
// tenant-scoped, with typed sentinels. Group SQL lives here instead of inline in
// the god-object service.
package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ErrGroupNotFound is the sentinel for a group miss within the tenant (→404).
var ErrGroupNotFound = errors.New("group not found")

// GroupRepository is the data-access port for groups. Depending on the
// interface keeps group business logic unit-testable with a fake.
type GroupRepository interface {
	// GetByID returns the group (with member_count) in the caller's tenant, or
	// ErrGroupNotFound. Read-only (replica).
	GetByID(ctx context.Context, id string) (*Group, error)

	// GetByName returns the group by display name in the caller's tenant, or
	// ErrGroupNotFound. Read-only (replica).
	GetByName(ctx context.Context, name string) (*Group, error)

	// Create inserts a group in the caller's tenant. WRITE (primary). Writes the
	// generated id + timestamps back onto the passed *Group.
	Create(ctx context.Context, group *Group) error

	// Update mutates a group's fields in the caller's tenant. WRITE (primary).
	Update(ctx context.Context, group *Group) error

	// Delete removes a group and its memberships in the caller's tenant. WRITE
	// (primary). Idempotent on memberships; returns nil even if the group row was
	// already absent (matches the legacy DeleteGroup contract).
	Delete(ctx context.Context, id string) error
}

// PostgresGroupRepository is the pgx implementation of GroupRepository.
type PostgresGroupRepository struct {
	db *database.PostgresDB
}

// NewPostgresGroupRepository constructs the pgx-backed group repository.
func NewPostgresGroupRepository(db *database.PostgresDB) *PostgresGroupRepository {
	return &PostgresGroupRepository{db: db}
}

// groupSelectSQL is the canonical group read (with a correlated member_count).
// $1 is the filter value (id or name), $2 is org_id.
const groupSelectColumns = `
	g.id, g.name, g.description, g.parent_id, g.allow_self_join, g.require_approval,
	g.max_members, g.created_at, g.updated_at,
	COALESCE((SELECT COUNT(*) FROM group_memberships gm WHERE gm.group_id = g.id AND gm.org_id = $2), 0) AS member_count`

func scanGroup(row pgx.Row) (*GroupDB, error) {
	var g GroupDB
	err := row.Scan(
		&g.ID, &g.DisplayName, &g.Description, &g.ParentID, &g.AllowSelfJoin,
		&g.RequireApproval, &g.MaxMembers, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount,
	)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// GetByID implements GroupRepository.
func (r *PostgresGroupRepository) GetByID(ctx context.Context, id string) (*Group, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	query := `SELECT ` + groupSelectColumns + ` FROM groups g WHERE g.id = $1 AND g.org_id = $2`
	dbGroup, err := scanGroup(r.db.Reader().QueryRow(ctx, query, id, org.ID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		return nil, fmt.Errorf("get group by id: %w", err)
	}
	group := dbGroup.ToGroup()
	return &group, nil
}

// GetByName implements GroupRepository.
func (r *PostgresGroupRepository) GetByName(ctx context.Context, name string) (*Group, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	query := `SELECT ` + groupSelectColumns + ` FROM groups g WHERE g.name = $1 AND g.org_id = $2`
	dbGroup, err := scanGroup(r.db.Reader().QueryRow(ctx, query, name, org.ID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		return nil, fmt.Errorf("get group by name: %w", err)
	}
	group := dbGroup.ToGroup()
	return &group, nil
}

// Create implements GroupRepository. WRITE — primary pool.
func (r *PostgresGroupRepository) Create(ctx context.Context, group *Group) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	if group.ID == "" {
		group.ID = uuid.New().String()
	}
	now := time.Now()
	group.CreatedAt = now
	group.UpdatedAt = now
	dbGroup := FromGroup(*group)

	_, err = r.db.Pool.Exec(ctx, `
		INSERT INTO groups (id, name, description, parent_id, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, dbGroup.ID, dbGroup.DisplayName, dbGroup.Description, dbGroup.ParentID,
		dbGroup.CreatedAt, dbGroup.UpdatedAt, org.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrGroupAlreadyExists
		}
		return fmt.Errorf("create group: %w", err)
	}
	return nil
}

// ErrGroupAlreadyExists is returned by Create on a duplicate group name in the
// tenant (→409).
var ErrGroupAlreadyExists = errors.New("group already exists")

// Update implements GroupRepository. WRITE — primary pool. Returns
// ErrGroupNotFound when no row matches.
func (r *PostgresGroupRepository) Update(ctx context.Context, group *Group) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	group.UpdatedAt = time.Now()
	dbGroup := FromGroup(*group)

	result, err := r.db.Pool.Exec(ctx, `
		UPDATE groups
		SET name = $2, description = $3, parent_id = $4, allow_self_join = $5,
		    require_approval = $6, max_members = $7, updated_at = $8
		WHERE id = $1 AND org_id = $9
	`, dbGroup.ID, dbGroup.DisplayName, dbGroup.Description, dbGroup.ParentID,
		dbGroup.AllowSelfJoin, dbGroup.RequireApproval, dbGroup.MaxMembers, dbGroup.UpdatedAt, org.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrGroupAlreadyExists
		}
		return fmt.Errorf("update group: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	group.UpdatedAt = dbGroup.UpdatedAt
	return nil
}

// Delete implements GroupRepository. WRITE — primary pool. Removes memberships
// first, then the group, so no orphaned membership rows remain. Idempotent.
func (r *PostgresGroupRepository) Delete(ctx context.Context, id string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	if _, err := r.db.Pool.Exec(ctx,
		`DELETE FROM group_memberships WHERE group_id = $1 AND org_id = $2`, id, org.ID); err != nil {
		return fmt.Errorf("remove group memberships: %w", err)
	}
	if _, err := r.db.Pool.Exec(ctx,
		`DELETE FROM groups WHERE id = $1 AND org_id = $2`, id, org.ID); err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	return nil
}

// Ensure the concrete type satisfies the interface at compile time.
var _ GroupRepository = (*PostgresGroupRepository)(nil)
