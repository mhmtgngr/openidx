package access

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/testsupport"
)

// TestAssignmentAllowed_BypassesRLS is the regression test for the review's
// Critical finding on this task: appForRoute correctly bypassed RLS for the
// route→application lookup, but the assignment check right after it used the
// request's own (unbypassed) context. Because applications,
// user_application_assignments, group_memberships and
// group_application_assignments are all FORCE ROW LEVEL SECURITY (see
// internal/migrations/sql_v37.go and sql_v136.go), an unbypassed context with
// no ambient org — exactly what the proxy data plane has, since it resolves
// its tenant from the Host header rather than from orgctx — makes Postgres
// additionally filter every row by app.org_id = NULL. appaccess.Allowed's
// own explicit `a.org_id = $2` predicate then matches zero rows regardless of
// the real assignment, and the caller silently sees "not assigned".
//
// This has to run against REAL row security to mean anything: a superuser
// connection bypasses RLS regardless of policy, which is exactly how the
// existing test suites for this package and for internal/appaccess (whose
// setupTestDB connects as the container's own superuser and creates no
// policies at all) could not have caught this — nothing in either exercises
// FORCE ROW LEVEL SECURITY. internal/common/database/rls_enforcement_test.go
// established the pattern this test follows: create the real policy, connect
// as an ordinary role the way the production pool does, and prove Postgres
// itself filters (or doesn't).
func TestAssignmentAllowed_BypassesRLS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed RLS test in -short mode")
	}
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}
	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	})
	defer func() { _ = container.Terminate(ctx) }()

	host, err := container.Host(ctx)
	if err != nil {
		t.Skipf("could not resolve container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Skipf("could not resolve container port: %v", err)
	}

	const (
		org      = "aaaaaaaa-0000-0000-0000-000000000001"
		otherOrg = "bbbbbbbb-0000-0000-0000-000000000002"
		userID   = "cccccccc-0000-0000-0000-000000000003"
		appID    = "dddddddd-0000-0000-0000-000000000004"
		routeID  = "eeeeeeee-0000-0000-0000-000000000005"
	)

	adminDSN := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer admin.Close()

	// The org-scope belt exactly as production runs it (sql_v37.go /
	// sql_v136.go): bypass marker OR matching org, forced even for the table
	// owner, on every table the assignment predicate touches.
	orgScopePolicy := func(table string) []string {
		policy := fmt.Sprintf("pol_%s_org_scope", table)
		return []string{
			fmt.Sprintf(`CREATE POLICY %s ON %s
				USING (current_setting('app.bypass_rls', true) = 'on'
				       OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)`, policy, table),
			fmt.Sprintf(`ALTER TABLE %s ENABLE ROW LEVEL SECURITY`, table),
			fmt.Sprintf(`ALTER TABLE %s FORCE ROW LEVEL SECURITY`, table),
		}
	}

	setup := []string{
		`CREATE TABLE applications (
			id UUID PRIMARY KEY, route_id UUID, org_id UUID NOT NULL, enabled BOOLEAN NOT NULL DEFAULT true)`,
		`CREATE TABLE user_application_assignments (
			user_id UUID NOT NULL, application_id UUID NOT NULL, org_id UUID NOT NULL)`,
		`CREATE TABLE group_application_assignments (
			group_id UUID NOT NULL, application_id UUID NOT NULL, org_id UUID NOT NULL)`,
		`CREATE TABLE group_memberships (user_id UUID NOT NULL, group_id UUID NOT NULL, org_id UUID NOT NULL)`,
	}
	setup = append(setup, orgScopePolicy("applications")...)
	setup = append(setup, orgScopePolicy("user_application_assignments")...)
	setup = append(setup, orgScopePolicy("group_application_assignments")...)
	setup = append(setup, orgScopePolicy("group_memberships")...)
	setup = append(setup,
		fmt.Sprintf(`INSERT INTO applications (id, route_id, org_id, enabled) VALUES ('%s','%s','%s', true)`, appID, routeID, org),
		fmt.Sprintf(`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ('%s','%s','%s')`, userID, appID, org),
		// RLS does not apply to superusers, so the pool under test must log in
		// as an ordinary role for this test to prove anything.
		`CREATE ROLE openidx_app LOGIN PASSWORD 'app_secret'`,
		`GRANT SELECT ON applications, user_application_assignments, group_application_assignments, group_memberships TO openidx_app`,
	)
	for _, stmt := range setup {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup failed (%s): %v", stmt, err)
		}
	}

	// The pool under test: an ordinary role, exactly like the production
	// access-service connection — database.NewPostgres wires the RLS-checkout
	// hook for every pool it creates (database.buildPoolConfig calls
	// configureRLS unconditionally), so this reproduces the real client, not a
	// hand-rolled approximation of it.
	appDSN := fmt.Sprintf("postgres://openidx_app:app_secret@%s:%s/testdb?sslmode=disable", host, port.Port())
	db, err := database.NewPostgres(appDSN)
	if err != nil {
		t.Fatalf("app pool: %v", err)
	}
	defer db.Close()

	s := &Service{db: db, logger: zap.NewNop()}

	// reqCtx carries no ambient org context at all — exactly what handleProxy
	// has. The proxy resolves its tenant from the Host header, not from
	// orgctx, so there is no orgctx.With call anywhere upstream of the
	// assignment overlay on that request path.
	reqCtx := context.Background()

	t.Run("assignmentAllowed finds the real assignment with no ambient org", func(t *testing.T) {
		assigned, fresh := s.assignmentAllowed(reqCtx, userID, org, appID)
		if !fresh {
			t.Fatalf("expected a fresh (uncached) lookup on first call")
		}
		if !assigned {
			t.Fatal("assignmentAllowed must find the real assignment: it applies orgctx.WithBypassRLS " +
				"itself so appaccess.Allowed's explicit a.org_id predicate is the sole scope. A false " +
				"result here means RLS silently filtered the query on the request's (nonexistent) " +
				"app.org_id GUC — exactly the bug this test guards against.")
		}
	})

	t.Run("assignmentAllowed is unaffected by a mismatched ambient org", func(t *testing.T) {
		// Simulates the proxy having resolved *some* org context that isn't
		// the application's own — the bypass must make that irrelevant too.
		mismatched := orgctx.With(reqCtx, orgctx.Org{ID: otherOrg})
		assigned, _ := s.assignmentAllowed(mismatched, userID+"-2", org, appID)
		// This user has no assignment row at all, so the correct answer is
		// still false — but it must come from appaccess.Allowed's own
		// predicate (a.org_id = $2, no match on assignment), not from RLS
		// filtering out the application row entirely regardless of user.
		if assigned {
			t.Fatal("unassigned user must not be reported as assigned")
		}
	})

	t.Run("appForRoute resolves the application despite a mismatched ambient org", func(t *testing.T) {
		gotAppID, gotOrgID := s.appForRoute(orgctx.With(context.Background(), orgctx.Org{ID: otherOrg}), routeID)
		if gotAppID != appID || gotOrgID != org {
			t.Fatalf("appForRoute under a mismatched ambient org: got (%q,%q), want (%q,%q)",
				gotAppID, gotOrgID, appID, org)
		}
	})
}
