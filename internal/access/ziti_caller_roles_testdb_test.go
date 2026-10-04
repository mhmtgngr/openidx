package access

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The Ziti HTTP forwarder tells the upstream who the caller is, roles
// included, and an upstream may authorize on them. It read every user_roles
// row, so a role whose window had ended (v223) was still forwarded until the
// expiry sweep deleted it. On the migrated schema, a caller holding one live
// and one ended role is forwarded with the live one only.
func TestTheZitiCallerIsForwardedWithLiveRolesOnly(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	octx := orgctx.WithBypassRLS(ctx)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...any) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(octx, q, args...).Scan(&v); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
		return v
	}
	user := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "caller-"+suffix)
	for _, r := range []struct{ name, ends string }{{"live-" + suffix, "1 hour"}, {"ended-" + suffix, "-5 minutes"}} {
		role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, r.name)
		scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at)
			VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`, user, role, org, r.ends)
	}

	zm := &ZitiManager{cfg: &config.Config{}, logger: zap.NewNop(), db: db}
	email, _, roles, err := zm.callerIdentity(octx, user)
	if err != nil || email != "caller-"+suffix+"@example.test" || roles != "live-"+suffix {
		t.Errorf("callerIdentity = %q, roles %q, %v; want the caller's email and only the live role", email, roles, err)
	}
}
