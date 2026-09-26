// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV205ExistingClientsKeepAPIAccessAndNewOnesDoNot applies v205 over an
// install that already has clients -- the seeded console, one an operator
// registered, and one of a second organization -- and checks that every one of
// them may still call OpenIDX's own APIs afterwards, that a client registered
// after the upgrade may not unless it says so, and that rolling back removes
// the column.
func TestV205ExistingClientsKeepAPIAccessAndNewOnesDoNot(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 204); err != nil {
		t.Fatalf("migrate to 204: %v", err)
	}

	var org string
	if err := pool.QueryRow(ctx,
		"SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&org); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	var otherOrg string
	if err := pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug, status) VALUES ('v205 tenant', 'v205-tenant', 'active')
		RETURNING id::text`).Scan(&otherOrg); err != nil {
		t.Fatalf("create a second organization: %v", err)
	}
	insertIn := func(orgID, clientID string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO oauth_clients (id, client_id, name, type, redirect_uris, grant_types, response_types, scopes, org_id)
			VALUES (gen_random_uuid(), $1, $1, 'confidential', '[]', '["client_credentials"]', '[]', '[]', $2::uuid)`,
			clientID, orgID); err != nil {
			t.Fatalf("insert client %s: %v", clientID, err)
		}
	}
	insertIn(org, "v205-registered-before")
	insertIn(otherOrg, "v205-other-tenant-before")

	if err := m.MigrateTo(ctx, 205); err != nil {
		t.Fatalf("migrate to 205: %v", err)
	}

	apiAccess := func(clientID string) bool {
		t.Helper()
		var allowed bool
		if err := pool.QueryRow(ctx,
			`SELECT api_access FROM oauth_clients WHERE client_id = $1 AND org_id = $2::uuid`, clientID, org).Scan(&allowed); err != nil {
			t.Fatalf("read api_access of %s: %v", clientID, err)
		}
		return allowed
	}
	for _, existing := range []string{"admin-console", "v205-registered-before"} {
		if !apiAccess(existing) {
			t.Errorf("%s existed before v205 and lost API access on the upgrade", existing)
		}
	}
	var without int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients WHERE NOT api_access`).Scan(&without); err != nil {
		t.Fatalf("count clients without API access: %v", err)
	}
	if without != 0 {
		t.Errorf("%d clients that existed before v205 have no API access after it", without)
	}

	insertIn(org, "v205-registered-after")
	if apiAccess("v205-registered-after") {
		t.Error("a client registered after v205 may call OpenIDX's APIs without being allowed to")
	}

	if err := m.RollbackTo(ctx, 204); err != nil {
		t.Fatalf("roll back to 204: %v", err)
	}
	var columns int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_name = 'oauth_clients' AND column_name = 'api_access'`).Scan(&columns); err != nil {
		t.Fatalf("look for the column: %v", err)
	}
	if columns != 0 {
		t.Error("rolling back v205 left oauth_clients.api_access behind")
	}
}
