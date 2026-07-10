package governance

import (
	"context"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestResolveReviewer_Manager guards the manager reviewer strategy. A
// certification campaign configured to route items to each owner's manager
// depends on users.manager_id (added by migration v70 and populated from the
// SCIM enterprise-extension manager.value). Before v70 that column did not
// exist, the query errored, and every "manager" campaign silently fell back to
// the system admin — the control looked configured but no manager ever
// reviewed anything. This asserts the resolver returns the real manager when
// one is set and only falls back to the admin default when there is none.
// DB-backed because resolveReviewer runs a real query against users.
func TestResolveReviewer_Manager(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE users (
			id UUID PRIMARY KEY,
			org_id UUID NOT NULL,
			manager_id UUID REFERENCES users(id) ON DELETE SET NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	const (
		manager = "dddddddd-0000-0000-0000-000000000001"
		report  = "dddddddd-0000-0000-0000-000000000002"
		orphan  = "dddddddd-0000-0000-0000-000000000003"
		// The resolver's hard-coded fallback when no reviewer resolves.
		adminDefault = "00000000-0000-0000-0000-000000000001"
	)

	exec := func(q string, args ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	// Manager first: report's manager_id FK-references it.
	exec(`INSERT INTO users (id, org_id) VALUES ($1, $2)`, manager, orgID)
	exec(`INSERT INTO users (id, org_id, manager_id) VALUES ($1, $2, $3)`, report, orgID, manager)
	exec(`INSERT INTO users (id, org_id) VALUES ($1, $2)`, orphan, orgID) // manager_id NULL

	s := &CertificationService{db: db, logger: zaptest.NewLogger(t)}
	campaign := &CertificationCampaign{
		Reviewers: []CampaignReviewer{{Type: "manager"}},
	}

	t.Run("manager set resolves to the manager", func(t *testing.T) {
		got, err := s.resolveReviewer(ctx, campaign, report, "role-xyz")
		if err != nil {
			t.Fatalf("resolveReviewer: %v", err)
		}
		if got != manager {
			t.Fatalf("expected the manager %s to review, got %s (manager strategy fell through)", manager, got)
		}
	})

	t.Run("no manager falls back to admin default", func(t *testing.T) {
		got, err := s.resolveReviewer(ctx, campaign, orphan, "role-xyz")
		if err != nil {
			t.Fatalf("resolveReviewer: %v", err)
		}
		if got != adminDefault {
			t.Fatalf("expected admin default %s when the owner has no manager, got %s", adminDefault, got)
		}
	})
}
