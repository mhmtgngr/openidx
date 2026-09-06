package identity

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// setupMigratedDB gives a test the schema the product creates, rather than one
// the test builds for itself.
//
// The rest of this package's DB tests CREATE the tables they need, which is why
// a lifecycle action naming a column user_roles does not have survived: a test
// that defines the column cannot notice that the product's schema lacks it.
func setupMigratedDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	url := os.Getenv("OPENIDX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("OPENIDX_TEST_DATABASE_URL not set; this test needs the real migration chain")
		return nil, func() {}
	}
	ctx := context.Background()
	db, err := database.NewPostgres(url)
	if err != nil {
		t.Skipf("OPENIDX_TEST_DATABASE_URL set but unreachable: %v", err)
		return nil, func() {}
	}
	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			db.Close()
			t.Fatalf("reset test schema (%s): %v", stmt, err)
		}
	}
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		db.Close()
		t.Fatalf("migrate to latest: %v", err)
	}
	return db, func() { db.Close() }
}

// TestLifecycleAssignRoleActuallyAssigns drives the joiner action that granted
// nothing.
//
// executeLifecycleAction's assign_role branch inserted into user_roles with a
// created_at column. The table records the grant time as assigned_at and has
// never had a created_at, so the statement could not plan: every lifecycle rule
// that assigns a role has failed, on every install, since it was written. The
// error was returned and logged by the caller, so from the console a joiner
// rule ran and granted no access -- the exact failure an automated-provisioning
// feature exists to prevent.
func TestLifecycleAssignRoleActuallyAssigns(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	seedCtx := orgctx.WithBypassRLS(context.Background())
	const (
		org    = "00000000-0000-0000-0000-000000000010"
		user   = "77777777-0000-0000-0000-0000000000a1"
		roleID = "77777777-0000-0000-0000-0000000000b1"
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'jml-u', 'jml-u@test.local', $2)`, user, org)
	exec(`INSERT INTO roles (id, name, description, org_id) VALUES ($1, 'jml-engineer', 'seeded by the test', $2)`, roleID, org)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	svc := &Service{db: db, logger: zap.NewNop()}

	if err := svc.executeLifecycleAction(ctx, user, map[string]interface{}{
		"type":    "assign_role",
		"role_id": roleID,
	}); err != nil {
		t.Fatalf("assign_role: %v", err)
	}

	var n int
	if err := db.Pool.QueryRow(seedCtx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id = $1 AND role_id = $2 AND org_id = $3`,
		user, roleID, org).Scan(&n); err != nil {
		t.Fatalf("read back the assignment: %v", err)
	}
	if n != 1 {
		t.Fatalf("the rule reported success and granted %d roles, want 1", n)
	}

	// The action is idempotent: a rule that fires twice must not error.
	if err := svc.executeLifecycleAction(ctx, user, map[string]interface{}{
		"type":    "assign_role",
		"role_id": roleID,
	}); err != nil {
		t.Fatalf("assign_role, second run: %v", err)
	}

	// And remove_role takes it away again, so the pair is exercised on the
	// schema rather than on one half of it.
	if err := svc.executeLifecycleAction(ctx, user, map[string]interface{}{
		"type":    "remove_role",
		"role_id": roleID,
	}); err != nil {
		t.Fatalf("remove_role: %v", err)
	}
	if err := db.Pool.QueryRow(seedCtx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id = $1 AND role_id = $2`,
		user, roleID).Scan(&n); err != nil {
		t.Fatalf("read back after removal: %v", err)
	}
	if n != 0 {
		t.Errorf("remove_role left %d assignment(s)", n)
	}
}
