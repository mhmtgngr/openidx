// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV213GivesEveryBrokeredRouteAnEntryAndNobodyAGrant applies v213 over an
// install with a brokered route and checks that the route gets exactly one
// entry carrying the connection record's target, secret and flags, that a
// second run adds nothing, that nobody holds a grant on it, and that rolling
// back keeps the entry and drops the link.
func TestV213GivesEveryBrokeredRouteAnEntryAndNobodyAGrant(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 212); err != nil {
		t.Fatalf("migrate to the version before it: %v", err)
	}

	var org string
	if err := pool.QueryRow(ctx,
		"SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&org); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	var route, secret string
	if err := pool.QueryRow(ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled)
		VALUES ($1::uuid, 'v213-bastion', 'https://bastion.example.test', 'ssh://198.51.100.7:22', true)
		RETURNING id::text`, org).Scan(&route); err != nil {
		t.Fatalf("seed a route: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO vault_secrets (org_id, name, type)
		VALUES ($1::uuid, 'v213-secret', 'password')
		RETURNING id::text`, org).Scan(&secret); err != nil {
		t.Fatalf("seed a vault secret: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO guacamole_connections
		    (route_id, org_id, guacamole_connection_id, protocol, hostname, port,
		     vault_secret_id, inject_username, require_approval, record_session)
		VALUES ($1::uuid, $2::uuid, 'guac-v213', 'ssh', '198.51.100.7', 22, $3::uuid, 'ops', true, true)`,
		route, org, secret); err != nil {
		t.Fatalf("seed the brokered connection: %v", err)
	}

	if err := m.MigrateTo(ctx, 213); err != nil {
		t.Fatalf("migrate to 213: %v", err)
	}

	var count int
	var entryOrg, name, entryType, host, user, entrySecret, guacID, reach string
	var port int
	var approval, record bool
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) OVER (), org_id::text, name, entry_type, hostname, port, COALESCE(username,''),
		       COALESCE(vault_secret_id::text,''), COALESCE(guacamole_connection_id,''),
		       require_approval, record_session, reach_mode
		  FROM pam_entries WHERE proxy_route_id = $1::uuid`, route).Scan(
		&count, &entryOrg, &name, &entryType, &host, &port, &user, &entrySecret, &guacID, &approval, &record, &reach); err != nil {
		t.Fatalf("the route has no entry after v213: %v", err)
	}
	switch {
	case count != 1:
		t.Fatalf("the route has %d entries, want 1", count)
	case entryOrg != org:
		t.Fatalf("the entry is in org %s, want the route's %s", entryOrg, org)
	case name != "v213-bastion" || entryType != "ssh" || host != "198.51.100.7" || port != 22:
		t.Fatalf("the entry does not describe the route's target: %s %s %s:%d", name, entryType, host, port)
	case user != "ops" || entrySecret != secret || guacID != "guac-v213":
		t.Fatalf("the entry does not carry the connection record's identity and secret: user %q secret %q guac %q",
			user, entrySecret, guacID)
	case !approval || !record:
		t.Fatalf("require_approval %v record_session %v, want both carried over", approval, record)
	case reach != "direct":
		t.Fatalf("reach_mode %q, want direct", reach)
	}

	var grants int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM pam_entry_grants g JOIN pam_entries e ON e.id = g.entry_id
		 WHERE e.proxy_route_id = $1::uuid`, route).Scan(&grants); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if grants != 0 {
		t.Fatalf("the backfill gave out %d grants; nobody held one before and nobody must get one now", grants)
	}

	// Idempotent: running the backfill statement again adds nothing.
	if _, err := pool.Exec(ctx, backfillOf(t)); err != nil {
		t.Fatalf("re-run the backfill: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM pam_entries WHERE proxy_route_id = $1::uuid`, route).Scan(&count); err != nil {
		t.Fatalf("recount: %v", err)
	}
	if count != 1 {
		t.Fatalf("a second backfill made it %d entries, want still 1", count)
	}

	if err := m.RollbackTo(ctx, 212); err != nil {
		t.Fatalf("roll back to 212: %v", err)
	}
	var hasColumn bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
		                WHERE table_name = 'pam_entries' AND column_name = 'proxy_route_id')`).Scan(&hasColumn); err != nil {
		t.Fatalf("read columns: %v", err)
	}
	if hasColumn {
		t.Fatal("proxy_route_id survived the rollback")
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM pam_entries WHERE name = 'v213-bastion'`).Scan(&count); err != nil {
		t.Fatalf("count entries after rollback: %v", err)
	}
	if count != 1 {
		t.Fatalf("the rollback left %d entries named after the route, want the 1 it made kept", count)
	}
}

// backfillOf returns v213's INSERT statement, so the test re-runs exactly what
// the migration ran rather than a copy that could drift from it.
func backfillOf(t *testing.T) string {
	t.Helper()
	for _, mig := range migrations.All() {
		if mig.Version != 213 {
			continue
		}
		up := mig.UpSQL
		from := strings.Index(up, "INSERT INTO pam_entries")
		if from < 0 {
			break
		}
		to := strings.Index(up[from:], ";")
		if to < 0 {
			break
		}
		return up[from : from+to]
	}
	t.Fatal("v213 has no INSERT statement")
	return ""
}
