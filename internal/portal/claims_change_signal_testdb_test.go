package portal

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/migrations"
)

// portalMigratedDB is a database with the product's schema: the one
// OPENIDX_TEST_DATABASE_URL names, reset, or the package's container.
func portalMigratedDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	var db *database.PostgresDB
	cleanup := func() {}
	if url := os.Getenv("OPENIDX_TEST_DATABASE_URL"); url != "" {
		var err error
		if db, err = database.NewPostgres(url); err != nil {
			t.Skipf("OPENIDX_TEST_DATABASE_URL set but unreachable: %v", err)
			return nil, cleanup
		}
		for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
			if _, err := db.Pool.Exec(context.Background(), stmt); err != nil {
				db.Close()
				t.Fatalf("reset test schema (%s): %v", stmt, err)
			}
		}
		cleanup = func() { db.Close() }
	} else if db, cleanup = setupPortalTestDB(t); db == nil {
		return nil, cleanup
	}
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(context.Background(), -1); err != nil {
		cleanup()
		t.Fatalf("migrate to latest: %v", err)
	}
	return db, cleanup
}

// A group joined through the portal tells the tenant's SSF receivers (CAEP
// token-claims-change): a self-join that needs no approval when it is made,
// and one that does when it is approved; a denied request and a join of a
// group the user already belongs to say nothing.
func TestAPortalGroupJoinTellsTheReceivers(t *testing.T) {
	db, cleanup := portalMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
			org, name+"-"+suffix)
	}
	group := func(name string, approval bool) string {
		return scalar(`INSERT INTO groups (org_id, name, allow_self_join, require_approval) VALUES ($1, $2, true, $3) RETURNING id::text`,
			org, name+"-"+suffix, approval)
	}
	reasons := func(userID string) string {
		return scalar(`SELECT COALESCE(string_agg(claims->>'reason', ',' ORDER BY id), '') FROM ssf_pending_events
			WHERE subject_id = $1 AND event_type = $2 AND org_id = $3`, userID, ssfsignal.TokenClaimsChange, org)
	}
	svc := NewService(db, zap.NewNop())
	open, guarded := group("pj-open", false), group("pj-guarded", true)
	reviewer := user("pj-reviewer")
	joiner, approved, denied := user("pj-joiner"), user("pj-approved"), user("pj-denied")

	for i := 0; i < 2; i++ {
		if err := svc.RequestGroupJoin(ctx, joiner, open, "release"); err != nil {
			t.Fatalf("join an open group (run %d): %v", i+1, err)
		}
	}
	for _, c := range []struct {
		userID, decision string
	}{{approved, "approved"}, {denied, "denied"}} {
		if err := svc.RequestGroupJoin(ctx, c.userID, guarded, "release"); err != nil {
			t.Fatalf("request a guarded group: %v", err)
		}
		req := scalar(`SELECT id::text FROM group_join_requests WHERE user_id = $1 AND group_id = $2`, c.userID, guarded)
		if err := svc.ReviewGroupRequest(ctx, req, reviewer, c.decision, "ok"); err != nil {
			t.Fatalf("review the request (%s): %v", c.decision, err)
		}
	}

	for _, c := range []struct{ who, userID, want string }{
		{"a self-join that needs no approval, made twice", joiner, "portal.group_join"},
		{"an approved join request", approved, "portal.group_join_approved"},
		{"a denied join request", denied, ""},
	} {
		if got := reasons(c.userID); got != c.want {
			t.Errorf("%s: token-claims-change reasons %q, want %q", c.who, got, c.want)
		}
	}
}
