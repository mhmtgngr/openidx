// package migrations_test so this can reach adminPoolOrSkip, like v172_test.go.
package migrations_test

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV173TenantScopedNames applies v173 and checks the one thing it is for:
// before it, the second organization to want an ordinary name is refused; after
// it, both organizations hold their own.
//
// The refusal is asserted first, at v172, because a migration that widens a key
// proves nothing unless the narrow key was actually in the way. That is the
// difference between this test and one that only checks the new index exists.
//
// "developer" is not a corner case. The seed creates admin, manager, user,
// auditor and developer for the default organization on every install, so the
// five most ordinary role names on a multi-tenant install are taken before the
// second tenant arrives.
func TestV173TenantScopedNames(t *testing.T) {
	db, _, cleanup := adminPoolOrSkip(t)
	defer cleanup()
	ctx := context.Background()
	pool := db.Pool

	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	m := migrations.NewMigrator(pool, zap.NewNop())

	if err := m.MigrateTo(ctx, 172); err != nil {
		t.Fatalf("migrate to 172: %v", err)
	}

	var orgA, orgB string
	if err := pool.QueryRow(ctx,
		"SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&orgA); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	if err := pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('names-b','names-b') RETURNING id::text").Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}

	// Each case: the table, the name column, and a name org A holds already (or
	// is given here) that org B must be able to hold too.
	cases := []struct {
		table  string
		column string
		name   string
		insert string // $1 name, $2 org
	}{
		{
			table: "roles", column: "name", name: "developer",
			insert: "INSERT INTO roles (name, description, org_id) VALUES ($1,'',$2)",
		},
		{
			table: "service_accounts", column: "name", name: "ci",
			insert: "INSERT INTO service_accounts (name, description, status, org_id) VALUES ($1,'','active',$2)",
		},
		{
			table: "scim_groups", column: "display_name", name: "Engineering",
			insert: "INSERT INTO scim_groups (display_name, data, org_id) VALUES ($1,'{}'::jsonb,$2)",
		},
	}

	// --- at v172: org A takes the name, org B is refused ---------------------
	for _, c := range cases {
		// Org A may already hold it (roles are seeded); make sure it does.
		var held bool
		if err := pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM "+c.table+" WHERE "+c.column+" = $1)", c.name).Scan(&held); err != nil {
			t.Fatalf("%s: check existing %q: %v", c.table, c.name, err)
		}
		if !held {
			if _, err := pool.Exec(ctx, c.insert, c.name, orgA); err != nil {
				t.Fatalf("%s: org A could not take %q: %v", c.table, c.name, err)
			}
		}

		_, err := pool.Exec(ctx, c.insert, c.name, orgB)
		if err == nil {
			t.Fatalf("%s: org B took %q at v172 — the install-wide key is already gone, so this test proves nothing",
				c.table, c.name)
		}
		if !strings.Contains(err.Error(), "duplicate key value") {
			t.Fatalf("%s: org B was refused %q for the wrong reason: %v", c.table, c.name, err)
		}
	}

	// --- v173: the same insert succeeds, and each org sees only its own ------
	if err := m.MigrateTo(ctx, 173); err != nil {
		t.Fatalf("migrate to 173: %v", err)
	}
	for _, c := range cases {
		if _, err := pool.Exec(ctx, c.insert, c.name, orgB); err != nil {
			t.Fatalf("%s: org B still cannot take %q after v173: %v", c.table, c.name, err)
		}

		var n int
		if err := pool.QueryRow(ctx,
			"SELECT COUNT(*) FROM "+c.table+" WHERE "+c.column+" = $1", c.name).Scan(&n); err != nil {
			t.Fatalf("%s: count %q: %v", c.table, c.name, err)
		}
		if n != 2 {
			t.Fatalf("%s: %d rows named %q, want 2 (one per org)", c.table, n, c.name)
		}

		// The new key must still be a key: one org cannot hold the name twice.
		if _, err := pool.Exec(ctx, c.insert, c.name, orgB); err == nil {
			t.Fatalf("%s: org B took %q twice — (org_id, %s) is not unique", c.table, c.name, c.column)
		}
	}

	// --- down: the install-wide key returns, duplicates removed -------------
	//
	// RollbackTo, not MigrateTo: MigrateTo only rolls FORWARD (it applies the
	// pending set at or below the target), so MigrateTo(172) from 173 is a
	// no-op that logs "No pending migrations" and leaves every assertion below
	// reading v173 state. This test found that by failing; a rollback check
	// written the wrong way is one more thing that looks like coverage.
	if err := m.RollbackTo(ctx, 172); err != nil {
		t.Fatalf("roll back to 172: %v", err)
	}
	for _, c := range cases {
		var n int
		if err := pool.QueryRow(ctx,
			"SELECT COUNT(*) FROM "+c.table+" WHERE "+c.column+" = $1", c.name).Scan(&n); err != nil {
			t.Fatalf("%s: count %q after rollback: %v", c.table, c.name, err)
		}
		if n != 1 {
			t.Fatalf("%s: %d rows named %q after rollback, want 1 — the down migration must leave a rebuildable key",
				c.table, n, c.name)
		}
		if _, err := pool.Exec(ctx, c.insert, c.name, orgB); err == nil {
			t.Fatalf("%s: %q is takeable again after rollback — the install-wide key was not restored", c.table, c.name)
		}
	}

	// And forward once more: a rollback must not make the migration unrunnable.
	if err := m.MigrateTo(ctx, 173); err != nil {
		t.Fatalf("re-apply 173 after rollback: %v", err)
	}
}
