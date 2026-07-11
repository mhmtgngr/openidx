package admin

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestResolveItemReviewer guards the reviewer_strategy fix: "manager" resolves
// the subject user's manager (users.manager_id, v70) org-scoped, with the org
// admin as fallback — previously the strategy was stored/echoed but ignored
// and every attestation item went to the org admin.
//
// Runs against the fully-migrated schema from setupPAMTestDB (which applies
// all migrations): org A is the seeded default org, whose 'admin' user is the
// fallback target. usernames/emails are globally unique in this schema, so
// the test seeds its own distinct users rather than creating tables.
func TestResolveItemReviewer(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	// users is FORCE RLS (v37); the pool sets the app.org_id / app.bypass_rls
	// GUCs from orgctx at connection acquire. Seed across orgs under bypass;
	// exercise the resolver under org A's context like production does.
	ctx := orgctx.WithBypassRLS(context.Background())
	const (
		orgA     = "00000000-0000-0000-0000-000000000010" // seeded default org
		orgB     = "00000000-0000-0000-0000-00000000000b"
		orgEmpty = "00000000-0000-0000-0000-00000000000c" // never created
		managerA = "aaaaaaaa-0000-0000-0000-000000000002"
		reportA  = "aaaaaaaa-0000-0000-0000-000000000003"
		orphanA  = "aaaaaaaa-0000-0000-0000-000000000004"
		mgrB     = "bbbbbbbb-0000-0000-0000-000000000002"
		reportB  = "bbbbbbbb-0000-0000-0000-000000000001"
	)
	exec := func(q string, a ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, a...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	// Org B exists only for the cross-org isolation check.
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org B (attn test)', 'org-b-attn-test')`, orgB)
	exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'attn-mgr-a', 'attn-mgr-a@test.local', $2)`, managerA, orgA)
	exec(`INSERT INTO users (id, username, email, org_id, manager_id) VALUES ($1, 'attn-report-a', 'attn-report-a@test.local', $2, $3)`, reportA, orgA, managerA)
	exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'attn-orphan-a', 'attn-orphan-a@test.local', $2)`, orphanA, orgA)
	exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'attn-mgr-b', 'attn-mgr-b@test.local', $2)`, mgrB, orgB)
	exec(`INSERT INTO users (id, username, email, org_id, manager_id) VALUES ($1, 'attn-report-b', 'attn-report-b@test.local', $2, $3)`, reportB, orgB, mgrB)

	// The fallback target: the default org's seeded 'admin' user.
	var adminA string
	if err := db.Pool.QueryRow(ctx,
		`SELECT id::text FROM users WHERE username = 'admin' AND org_id = $1`, orgA,
	).Scan(&adminA); err != nil {
		t.Fatalf("seeded default-org admin not found: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})

	deref := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}

	// manager strategy resolves the subject's manager.
	if got := s.resolveItemReviewer(ctxA, orgA, "manager", reportA); deref(got) != managerA {
		t.Fatalf("manager strategy: want %s, got %s", managerA, deref(got))
	}
	// A user without a manager falls back to the org admin.
	if got := s.resolveItemReviewer(ctxA, orgA, "manager", orphanA); deref(got) != adminA {
		t.Fatalf("orphan fallback: want admin %s, got %s", adminA, deref(got))
	}
	// Items without a subject user go to the org admin.
	if got := s.resolveItemReviewer(ctxA, orgA, "manager", ""); deref(got) != adminA {
		t.Fatalf("no subject: want admin %s, got %s", adminA, deref(got))
	}
	// Non-manager strategies keep the org-admin default even when a manager exists.
	if got := s.resolveItemReviewer(ctxA, orgA, "admin_only", reportA); deref(got) != adminA {
		t.Fatalf("admin_only strategy: want admin %s, got %s", adminA, deref(got))
	}
	// Cross-org: resolving an org-B user under org A must not return org B's
	// manager — the lookup is org-scoped (and org B's rows are invisible under
	// org A's RLS context), so it falls back to org A's admin.
	if got := s.resolveItemReviewer(ctxA, orgA, "manager", reportB); deref(got) != adminA {
		t.Fatalf("cross-org: want org A admin %s, got %s", adminA, deref(got))
	}
	// An org with neither manager nor admin yields a NULL reviewer, not a drop.
	ctxEmpty := orgctx.With(context.Background(), orgctx.Org{ID: orgEmpty})
	if got := s.resolveItemReviewer(ctxEmpty, orgEmpty, "manager", ""); got != nil {
		t.Fatalf("empty org: want nil reviewer, got %s", *got)
	}
}
