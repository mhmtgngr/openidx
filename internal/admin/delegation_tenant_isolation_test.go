package admin

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the delegated-administration CRUD, migration v152.
//
// The read side of this feature is the policy enforcement point, and it is
// proven in internal/common/middleware. This file covers the admin API that
// writes the rows the enforcement point reads. Before v152 the table carried no
// org_id and:
//
//	CreateDelegation  inserted whatever delegate_id arrived in the body
//	UpdateDelegation  UPDATE admin_delegations SET ... WHERE id = $N
//	DeleteDelegation  DELETE FROM admin_delegations WHERE id = $1
//	ListDelegations   its count ran over the whole table, and said so
//
// `permissions` is one of the fields UpdateDelegation will SET, so the second
// line is the sharp one: an administrator of one tenant could rewrite the
// permission list on another tenant's delegation, and the unscoped read in the
// enforcement point would honour it on that user's next request.
//
// The harness connects as the container superuser, which bypasses RLS, so what
// these prove is the explicit org predicate in every query. The FORCE RLS belt
// is proven separately in test/integration/cross_org_test.go under a
// NOSUPERUSER NOBYPASSRLS role.
func TestAdminDelegations_TenantIsolation(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('dlg-b','dlg-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	seedUser := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	userA := seedUser(orgA, "dlg-a-user")
	adminA := seedUser(orgA, "dlg-a-admin")
	userB := seedUser(orgB, "dlg-b-user")
	adminB := seedUser(orgB, "dlg-b-admin")

	ctxA := orgctx.With(ctx, orgctx.Org{ID: orgA})
	ctxB := orgctx.With(ctx, orgctx.Org{ID: orgB})
	s := &Service{db: db, logger: zap.NewNop()}

	// Org A delegates the vault reveal permission to its own user.
	delegation := &AdminDelegation{
		DelegateID:  userA,
		DelegatedBy: adminA,
		ScopeType:   "organization",
		ScopeID:     orgA,
		Permissions: []string{"vault:reveal"},
		Enabled:     true,
	}
	if err := s.CreateDelegation(ctxA, delegation); err != nil {
		t.Fatalf("org A delegating within its own organization: %v", err)
	}
	delegationID := delegation.ID

	// THE GRANT ACROSS THE BOUNDARY.
	t.Run("a delegation cannot name another tenant's user", func(t *testing.T) {
		err := s.CreateDelegation(ctxB, &AdminDelegation{
			DelegateID:  userA, // org A's user
			DelegatedBy: adminB,
			ScopeType:   "organization",
			ScopeID:     orgB,
			Permissions: []string{"vault:reveal"},
			Enabled:     true,
		})
		if err == nil {
			t.Fatal("org B granted administrative permissions to org A's user. The enforcement " +
				"point merges a delegation straight into the permission set RequirePermission " +
				"decides on, so this is not a record, it is a grant")
		}

		// And nothing was written.
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM admin_delegations WHERE delegate_id = $1::uuid`, userA).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 1 {
			t.Fatalf("org A's user has %d delegations, want only the one org A created", n)
		}
	})

	t.Run("a delegation cannot be scoped to another tenant's organization", func(t *testing.T) {
		err := s.CreateDelegation(ctxB, &AdminDelegation{
			DelegateID:  userB,
			DelegatedBy: adminB,
			ScopeType:   "organization",
			ScopeID:     orgA, // scoped at org A
			Permissions: []string{"users:write"},
			Enabled:     true,
		})
		if err == nil {
			t.Fatal("org B created a delegation scoped to org A's organization")
		}
	})

	// THE REWRITE.
	t.Run("another tenant cannot rewrite the permission list", func(t *testing.T) {
		err := s.UpdateDelegation(ctxB, delegationID, map[string]interface{}{
			"permissions": []string{"vault:reveal", "users:delete", "roles:write"},
			"enabled":     true,
		})
		if err == nil {
			t.Fatal("org B rewrote the permissions on org A's delegation. UpdateDelegation builds " +
				"its SET list from the request body and `permissions` is one of the fields, so an " +
				"unscoped WHERE here is a self-service privilege grant into another tenant")
		}

		var perms []byte
		if err := db.Pool.QueryRow(ctx,
			`SELECT permissions FROM admin_delegations WHERE id = $1::uuid`, delegationID).Scan(&perms); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if got := string(perms); got != `["vault:reveal"]` {
			t.Fatalf("org A's delegation now grants %s", got)
		}
	})

	t.Run("another tenant cannot delete the delegation", func(t *testing.T) {
		if err := s.DeleteDelegation(ctxB, delegationID); err == nil {
			t.Fatal("org B deleted org A's delegation")
		}
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM admin_delegations WHERE id = $1::uuid`, delegationID).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 1 {
			t.Fatal("org A's delegation was deleted by another tenant")
		}
	})

	// THE DISCLOSURE, and the paging total that gave the game away.
	t.Run("the list and its count are both per org", func(t *testing.T) {
		got, total, err := s.ListDelegations(ctxB, 0, 50, "")
		if err != nil {
			t.Fatalf("org B list: %v", err)
		}
		for _, d := range got {
			if d.ID == delegationID {
				t.Fatalf("org B's console lists org A's delegation (%s -> %v)", d.DelegateID, d.Permissions)
			}
		}
		if total != 0 {
			t.Fatalf("org B has no delegations but the paging total says %d. The count query ran "+
				"over the whole table — its own comment said so — so the console showed one "+
				"tenant's rows under every tenant's total", total)
		}

		got, total, err = s.ListDelegations(ctxA, 0, 50, "")
		if err != nil {
			t.Fatalf("org A list: %v", err)
		}
		if total != 1 || len(got) != 1 || got[0].ID != delegationID {
			t.Fatalf("org A should see exactly its own delegation, got %d rows / total %d", len(got), total)
		}
	})

	t.Run("get is per org", func(t *testing.T) {
		if _, err := s.GetDelegation(ctxB, delegationID); err == nil {
			t.Fatal("org B fetched org A's delegation, which names a user, a grantor and a " +
				"permission list")
		}
		if _, err := s.GetDelegation(ctxA, delegationID); err != nil {
			t.Fatalf("org A cannot fetch its OWN delegation: %v; the predicate must scope, not "+
				"empty", err)
		}
	})
}
