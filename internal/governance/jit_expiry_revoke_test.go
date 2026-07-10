package governance

import (
	"context"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestRevokeExpiredJITAccess_RevokesApplication guards the JIT-expiry sweep. A
// time-bound "application" grant that has passed expires_at must have its
// underlying user_application_assignments row removed, not merely be marked
// expired: the old switch had no application case, hit the log-only default,
// yet still flipped the request to expired and wrote an outcome='success'
// audit — so app access persisted forever while the trail claimed revocation.
// An unmapped resource type must now fail loud (request stays fulfilled) rather
// than record a false success. DB-backed because the sweep runs real deletes.
func TestRevokeExpiredJITAccess_RevokesApplication(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	// Mirror the production checker, which runs the sweep under bypass-RLS.
	ctx := orgctx.WithBypassRLS(context.Background())
	const org = "00000000-0000-0000-0000-000000000010"

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE access_requests (
			id UUID PRIMARY KEY, requester_id UUID, resource_type VARCHAR(50),
			resource_id UUID, resource_name VARCHAR(255), org_id UUID,
			status VARCHAR(30), expires_at TIMESTAMPTZ, updated_at TIMESTAMPTZ DEFAULT now());
		CREATE TABLE user_application_assignments (user_id UUID, application_id UUID, org_id UUID);
		CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID);
		CREATE TABLE audit_events (
			id UUID PRIMARY KEY, event_type VARCHAR(50), category VARCHAR(50), action VARCHAR(100),
			outcome VARCHAR(20), actor_id UUID, actor_ip VARCHAR(45), target_id UUID,
			target_type VARCHAR(50), details JSONB, created_at TIMESTAMPTZ, org_id UUID);
		CREATE TABLE temp_access_links (status VARCHAR(20), expires_at TIMESTAMPTZ);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	const (
		appReq   = "a0000000-0000-0000-0000-000000000001"
		roleReq  = "a0000000-0000-0000-0000-000000000002"
		bogusReq = "a0000000-0000-0000-0000-000000000003"
		user     = "b0000000-0000-0000-0000-000000000001"
		appID    = "c0000000-0000-0000-0000-000000000001"
		roleID   = "c0000000-0000-0000-0000-000000000002"
		bogusRes = "c0000000-0000-0000-0000-000000000003"
	)
	exec := func(q string, args ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	req := func(id, rtype, rid string) {
		exec(`INSERT INTO access_requests (id, requester_id, resource_type, resource_id, resource_name, org_id, status, expires_at)
		      VALUES ($1, $2, $3, $4, 'r', $5, 'fulfilled', NOW() - INTERVAL '1 hour')`, id, user, rtype, rid, org)
	}
	// Expired application grant + its assignment (the gap).
	req(appReq, "application", appID)
	exec(`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1,$2,$3)`, user, appID, org)
	// Expired role grant + its assignment (regression: still revoked).
	req(roleReq, "role", roleID)
	exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, user, roleID, org)
	// Expired grant of an unmapped type (must fail loud, stay fulfilled).
	req(bogusReq, "widget", bogusRes)

	s := &Service{db: db, logger: zaptest.NewLogger(t)}
	s.revokeExpiredJITAccess(ctx)

	count := func(q string, args ...interface{}) int {
		var n int
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("count (%s): %v", q, err)
		}
		return n
	}
	status := func(id string) string {
		var st string
		if err := db.Pool.QueryRow(ctx, `SELECT status FROM access_requests WHERE id=$1`, id).Scan(&st); err != nil {
			t.Fatalf("status(%s): %v", id, err)
		}
		return st
	}

	if n := count(`SELECT COUNT(*) FROM user_application_assignments WHERE user_id=$1 AND application_id=$2`, user, appID); n != 0 {
		t.Fatalf("expired application assignment must be revoked, still present (%d rows)", n)
	}
	if st := status(appReq); st != "expired" {
		t.Fatalf("application request should be expired after a successful revoke, got %q", st)
	}
	if n := count(`SELECT COUNT(*) FROM user_roles WHERE user_id=$1 AND role_id=$2`, user, roleID); n != 0 {
		t.Fatalf("expired role assignment must still be revoked (regression), still present (%d rows)", n)
	}
	if st := status(roleReq); st != "expired" {
		t.Fatalf("role request should be expired, got %q", st)
	}
	// The unmapped type must NOT be marked expired — revocation failed, so no false success.
	if st := status(bogusReq); st != "fulfilled" {
		t.Fatalf("unmapped resource type must stay fulfilled (fail loud), got %q", st)
	}
}
