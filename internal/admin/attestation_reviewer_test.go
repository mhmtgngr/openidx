package admin

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestResolveItemReviewer guards the reviewer_strategy fix: "manager" resolves
// the subject user's manager (users.manager_id, v70) org-scoped, with the org
// admin as fallback — previously the strategy was stored/echoed but ignored
// and every attestation item went to the org admin.
func TestResolveItemReviewer(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE users (
			id UUID PRIMARY KEY,
			org_id UUID NOT NULL,
			username VARCHAR(255),
			manager_id UUID REFERENCES users(id) ON DELETE SET NULL);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		orgA     = "00000000-0000-0000-0000-00000000000a"
		orgB     = "00000000-0000-0000-0000-00000000000b"
		adminA   = "aaaaaaaa-0000-0000-0000-000000000001"
		managerA = "aaaaaaaa-0000-0000-0000-000000000002"
		reportA  = "aaaaaaaa-0000-0000-0000-000000000003"
		orphanA  = "aaaaaaaa-0000-0000-0000-000000000004"
		reportB  = "bbbbbbbb-0000-0000-0000-000000000001"
		mgrB     = "bbbbbbbb-0000-0000-0000-000000000002"
	)
	exec := func(q string, a ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, a...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO users (id, org_id, username) VALUES ($1,$2,'admin')`, adminA, orgA)
	exec(`INSERT INTO users (id, org_id, username) VALUES ($1,$2,'manager')`, managerA, orgA)
	exec(`INSERT INTO users (id, org_id, username, manager_id) VALUES ($1,$2,'report',$3)`, reportA, orgA, managerA)
	exec(`INSERT INTO users (id, org_id, username) VALUES ($1,$2,'orphan')`, orphanA, orgA)
	// Org B user with a manager: must never leak into org A resolution.
	exec(`INSERT INTO users (id, org_id, username) VALUES ($1,$2,'mgrB')`, mgrB, orgB)
	exec(`INSERT INTO users (id, org_id, username, manager_id) VALUES ($1,$2,'reportB',$3)`, reportB, orgB, mgrB)

	s := &Service{db: db, logger: zap.NewNop()}

	deref := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}

	// manager strategy resolves the subject's manager.
	if got := s.resolveItemReviewer(ctx, orgA, "manager", reportA); deref(got) != managerA {
		t.Fatalf("manager strategy: want %s, got %s", managerA, deref(got))
	}
	// A user without a manager falls back to the org admin.
	if got := s.resolveItemReviewer(ctx, orgA, "manager", orphanA); deref(got) != adminA {
		t.Fatalf("orphan fallback: want admin %s, got %s", adminA, deref(got))
	}
	// Items without a subject user go to the org admin.
	if got := s.resolveItemReviewer(ctx, orgA, "manager", ""); deref(got) != adminA {
		t.Fatalf("no subject: want admin %s, got %s", adminA, deref(got))
	}
	// Non-manager strategies keep the org-admin default even when a manager exists.
	if got := s.resolveItemReviewer(ctx, orgA, "admin_only", reportA); deref(got) != adminA {
		t.Fatalf("admin_only strategy: want admin %s, got %s", adminA, deref(got))
	}
	// Cross-org: resolving an org-B user under org A must not return org B's
	// manager — the lookup is org-scoped, so it falls back to org A's admin.
	if got := s.resolveItemReviewer(ctx, orgA, "manager", reportB); deref(got) != adminA {
		t.Fatalf("cross-org: want org A admin %s, got %s", adminA, deref(got))
	}
	// An org with neither manager nor admin yields a NULL reviewer, not a drop.
	if got := s.resolveItemReviewer(ctx, "00000000-0000-0000-0000-00000000000c", "manager", ""); got != nil {
		t.Fatalf("empty org: want nil reviewer, got %s", *got)
	}
}
