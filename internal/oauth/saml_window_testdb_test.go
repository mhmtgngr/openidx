package oauth

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// A SAML assertion names the user's roles and groups, as an OAuth token does.
// The token reads only those whose window is open (v223, v224); the assertion
// read the roles without the window, so a role whose window had ended was
// still asserted until the expiry sweep deleted it. On the migrated schema, a
// user holding one live and one ended role, and one live and one ended group,
// is asserted with the live ones only.
func TestASAMLAssertionCarriesOnlyLiveRolesAndGroups(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
		return v
	}
	user := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "asserted-"+suffix)
	for _, w := range []struct{ name, ends string }{{"live-" + suffix, "1 hour"}, {"ended-" + suffix, "-5 minutes"}} {
		role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, w.name)
		scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at)
			VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`, user, role, org, w.ends)
		group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, w.name)
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at)
			VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`, user, group, org, w.ends)
	}

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	if got := s.getUserRoles(ctx, user); !slices.Equal(got, []string{"live-" + suffix}) {
		t.Errorf("the assertion's roles = %v; want only the live role", got)
	}
	if got := s.getUserGroups(ctx, user); !slices.Equal(got, []string{"live-" + suffix}) {
		t.Errorf("the assertion's groups = %v; want only the live group", got)
	}
}
