// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV214HoldsTheExternalIdentityInvariant applies v214 and checks the
// database half of invariant I1: an external user exists only with a vendor,
// an expiry and, while the account is live, a sponsor, and nobody else carries
// those fields. It then checks that a sponsor's delete refuses to leave a live
// external user unsponsored, that the same delete goes through once the
// account is suspended, and that rolling back removes the columns and table.
func TestV214HoldsTheExternalIdentityInvariant(t *testing.T) {
	db, _, cleanup := adminPoolOrSkip(t)
	defer cleanup()
	ctx := context.Background()
	pool := db.Pool

	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	m := migrations.NewMigrator(pool.Raw(), zap.NewNop())
	if err := m.MigrateTo(ctx, 214); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var org string
	if err := pool.QueryRow(ctx,
		"SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&org); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	user := func(name string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email) VALUES ($1::uuid, $2::text, $2::text || '@example.test')
			RETURNING id::text`, org, name).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		return id
	}
	sponsor := user("v214-sponsor")
	var vendor string
	if err := pool.QueryRow(ctx, `
		INSERT INTO vendor_organizations (org_id, name, allowed_email_domains)
		VALUES ($1::uuid, 'Acme Support', '{supplier.example.test}') RETURNING id::text`, org).Scan(&vendor); err != nil {
		t.Fatalf("seed vendor: %v", err)
	}

	var internalType, internalStatus string
	if err := pool.QueryRow(ctx, `SELECT user_type, account_status FROM users WHERE id = $1::uuid`, sponsor).
		Scan(&internalType, &internalStatus); err != nil || internalType != "internal" || internalStatus != "active" {
		t.Fatalf("an existing user reads %q/%q (err %v), want internal/active", internalType, internalStatus, err)
	}

	insertExternal := func(name, vendorID, sponsorID, expires, status string) error {
		_, err := pool.Exec(ctx, `
			INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at, account_status)
			VALUES ($1::uuid, $2::text, $2::text || '@supplier.example.test', 'external',
			        NULLIF($3,'')::uuid, NULLIF($4,'')::uuid, NULLIF($5,'')::timestamptz, $6)`,
			org, name, vendorID, sponsorID, expires, status)
		return err
	}
	const later = "2099-01-01T00:00:00Z"
	if err := insertExternal("v214-vendor-ok", vendor, sponsor, later, "active"); err != nil {
		t.Fatalf("a sponsored external user with a vendor and an expiry was refused: %v", err)
	}
	for _, tc := range []struct{ name, vendor, sponsor, expires, status string }{
		{"no-sponsor", vendor, "", later, "active"},
		{"no-sponsor-pending", vendor, "", later, "pending_mfa"},
		{"no-expiry", vendor, sponsor, "", "active"},
		{"no-vendor", "", sponsor, later, "active"},
		{"bad-status", vendor, sponsor, later, "dormant"},
	} {
		if err := insertExternal("v214-"+tc.name, tc.vendor, tc.sponsor, tc.expires, tc.status); err == nil {
			t.Errorf("%s: an external user without it was accepted", tc.name)
		}
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (org_id, username, email, sponsor_user_id) VALUES ($1::uuid, 'v214-internal-sponsored', 'x@example.test', $2::uuid)`,
		org, sponsor); err == nil {
		t.Error("an internal user carrying a sponsor was accepted")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_invitations (org_id, email, invited_by, token, expires_at, user_type, vendor_org_id)
		VALUES ($1::uuid, 'inv@supplier.example.test', $2::uuid, 'v214-token', NOW() + interval '7 days', 'external', $3::uuid)`,
		org, sponsor, vendor); err == nil {
		t.Error("an external invitation without a sponsor and an expiry was accepted")
	}

	// The guard triggers: what an external user may be given, at every writer.
	var external string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM users WHERE username = 'v214-vendor-ok'`).Scan(&external); err != nil {
		t.Fatalf("read the external user: %v", err)
	}
	refusedBy := func(what, constraint string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s went through", what)
			return
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != constraint {
			t.Errorf("%s failed for another reason (want %s): %v", what, constraint, err)
		}
	}
	roleID := func(name string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `SELECT id::text FROM roles WHERE name = $1 AND org_id = $2::uuid`, name, org).Scan(&id); err != nil {
			t.Fatalf("role %s: %v", name, err)
		}
		return id
	}
	grantRole := func(userID, role string) error {
		_, err := pool.Exec(ctx, `INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
			userID, roleID(role), org)
		return err
	}
	if err := grantRole(external, "user"); err != nil {
		t.Errorf("the user role was refused to an external user: %v", err)
	}
	for _, role := range []string{"admin", "auditor", "manager", "developer"} {
		refusedBy("the "+role+" role for an external user", "external_role_cap", grantRole(external, role))
	}
	if err := grantRole(sponsor, "admin"); err != nil {
		t.Errorf("the admin role was refused to an internal user: %v", err)
	}

	group := func(name string, allowed bool) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO groups (org_id, name, external_allowed) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
			org, name, allowed).Scan(&id); err != nil {
			t.Fatalf("group %s: %v", name, err)
		}
		return id
	}
	join := func(userID, groupID string) error {
		_, err := pool.Exec(ctx, `INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
			userID, groupID, org)
		return err
	}
	openGroup, closedGroup := group("v214-vendors", true), group("v214-finance", false)
	if err := join(external, openGroup); err != nil {
		t.Errorf("an external_allowed group was refused to an external user: %v", err)
	}
	refusedBy("a closed group for an external user", "external_group_not_allowed", join(external, closedGroup))
	if err := join(sponsor, closedGroup); err != nil {
		t.Errorf("a closed group was refused to an internal user: %v", err)
	}
	_, err := pool.Exec(ctx, `UPDATE groups SET external_allowed = false WHERE id = $1::uuid`, openGroup)
	refusedBy("closing a group with an external member", "external_group_has_members", err)

	_, err = pool.Exec(ctx, `INSERT INTO admin_delegations (delegate_id, delegated_by, scope_type, org_id)
		VALUES ($1::uuid, $2::uuid, 'organization', $3::uuid)`, external, sponsor, org)
	refusedBy("a delegation to an external user", "external_cannot_approve", err)

	_, err = pool.Exec(ctx, `UPDATE users SET user_type = 'internal', vendor_org_id = NULL, sponsor_user_id = NULL,
		account_expires_at = NULL WHERE id = $1::uuid`, external)
	refusedBy("turning an external user internal", "user_type_immutable", err)

	// A sponsor's delete would leave a live external user unsponsored.
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, sponsor); err == nil {
		t.Fatal("deleting the sponsor of a live external user went through")
	} else if !strings.Contains(err.Error(), "users_external_identity_check") {
		t.Fatalf("the delete failed for another reason: %v", err)
	}
	_, err = pool.Exec(ctx, `UPDATE users SET account_status = 'suspended' WHERE sponsor_user_id = $1::uuid`, sponsor)
	refusedBy("suspending an external user while leaving it enabled", "users_external_enabled_check", err)
	if _, err := pool.Exec(ctx, `UPDATE users SET account_status = 'suspended', enabled = false WHERE sponsor_user_id = $1::uuid`, sponsor); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	_, err = pool.Exec(ctx, `UPDATE users SET enabled = true WHERE sponsor_user_id = $1::uuid`, sponsor)
	refusedBy("re-enabling a suspended external user", "users_external_enabled_check", err)
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, sponsor); err != nil {
		t.Fatalf("deleting the sponsor of a suspended external user: %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE groups SET name = name WHERE external_allowed`); err != nil {
		t.Fatalf("groups.external_allowed missing: %v", err)
	}

	if err := m.RollbackTo(ctx, 213); err != nil {
		t.Fatalf("roll back: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		 WHERE table_name = 'users' AND column_name IN ('user_type','account_status','sponsor_user_id')`).Scan(&n); err != nil || n != 0 {
		t.Errorf("after rollback users still has %d of the columns (err %v)", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relname = 'vendor_organizations'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("after rollback vendor_organizations still exists (err %v)", err)
	}
}
