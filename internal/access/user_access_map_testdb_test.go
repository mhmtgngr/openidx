package access

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// User Access 360 on the schema the product migrates to. The access map's other
// tests run on tables they create by hand, and those declared
// access_requests.resource_id as VARCHAR where the product has UUID. The JIT
// query paired that column with resource_name in one COALESCE, which Postgres
// refuses for a UUID and a VARCHAR when it plans the query. So the map
// answered 500 for every user, elevated or not, from v1.35.0 until this test,
// and the hand-written schema kept it green.
func TestUserAccessMapBuildsOnTheMigratedSchema(t *testing.T) {
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUser := func(name string) string {
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
	var roleID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO roles (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`,
		org, "on-call-"+suffix).Scan(&roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	elevate := func(userID string, resourceName *string) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO access_requests (requester_id, org_id, resource_type, resource_id, resource_name, status, expires_at)
			VALUES ($1::uuid, $2::uuid, 'role', $3::uuid, $4, 'fulfilled', NOW() + INTERVAL '1 hour')`,
			userID, org, roleID, resourceName); err != nil {
			t.Fatalf("seed elevation: %v", err)
		}
	}
	svc := &Service{db: db, logger: zap.NewNop()}
	elevations := func(userID string) []AccessMapJITGrant {
		t.Helper()
		m, err := svc.buildUserAccessMap(orgCtx, org, userID)
		if err != nil {
			t.Fatalf("User Access 360 for %s: %v", userID, err)
		}
		return m.PAM.ActiveJITGrants
	}

	t.Run("a user with no elevation", func(t *testing.T) {
		if got := elevations(seedUser("plain")); len(got) != 0 {
			t.Errorf("want no elevations, got %+v", got)
		}
	})
	t.Run("an elevation is listed by the name the request recorded", func(t *testing.T) {
		user := seedUser("named")
		name := "on-call"
		elevate(user, &name)
		if got := elevations(user); len(got) != 1 || got[0].RoleName != name {
			t.Errorf("want one elevation named %q, got %+v", name, got)
		}
	})
	t.Run("an elevation with no recorded name is listed by its resource id", func(t *testing.T) {
		user := seedUser("unnamed")
		elevate(user, nil)
		if got := elevations(user); len(got) != 1 || got[0].RoleName != roleID {
			t.Errorf("want one elevation listed as %s, got %+v", roleID, got)
		}
	})
}
