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

// The lifecycle sweep is the reconcile net for every way a user ends up
// disabled without going through the API: SCIM, a directory sync, a lifecycle
// policy, a direct row change. On the migrated schema: a disabled user's PAM
// entry surface ends within one tick, a deleted user's too, an enabled user's
// does not, a grant held through a group stays, the brokered entry session
// stays open in the ledger with no broker to end it, and a second tick ends
// nothing more.
func TestLifecycleSweepEndsThePamEntrySurface(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	// The sweep runs with RLS bypass (background, cross-org), like production.
	sweepCtx := orgctx.WithBypassRLS(ctx)

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	seedUser := func(name string, enabled bool) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, $4) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test", enabled).Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	disabled := seedUser("sweep-disabled", false)
	enabled := seedUser("sweep-enabled", true)
	// A user whose row is gone: their rows are attributed to an id nothing
	// resolves any more.
	const gone = "99999999-0000-0000-0000-000000000099"

	var entryID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
		VALUES ($1::uuid, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`,
		org, "sweep-"+suffix).Scan(&entryID); err != nil {
		t.Fatalf("seed entry: %v", err)
	}
	var groupID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO groups (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`,
		org, "sweep-group-"+suffix).Scan(&groupID); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	exec := func(what, sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %s: %v", what, err)
		}
	}
	exec("group membership", `INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		enabled, groupID, org)
	exec("group grant", `INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		VALUES ($1::uuid, $2::uuid, 'group', $3, '{connect}')`, org, entryID, groupID)
	for _, u := range []string{disabled, enabled, gone} {
		exec("user grant", `INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1::uuid, $2::uuid, 'user', $3, '{connect}')`, org, entryID, u)
		exec("approved launch", `INSERT INTO pam_entry_access_requests (org_id, entry_id, requester_id, status, expires_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'approved', NOW() + INTERVAL '1 hour')`, org, entryID, u)
		exec("lease", `INSERT INTO pam_active_checkouts (org_id, entry_id, principal_id, action, status, expires_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'connect', 'active', NOW() + INTERVAL '15 minutes')`, org, entryID, u)
		exec("temp link", `INSERT INTO temp_access_links (org_id, token, name, protocol, target_host, target_port, created_by, expires_at, status, pam_entry_id)
			VALUES ($1::uuid, $2, $3, 'ssh', 'target.example.test', 22, $4::uuid, NOW() + INTERVAL '1 day', 'active', $5::uuid)`,
			org, "tok-"+suffix+"-"+u[:8], "link-"+suffix, u, entryID)
		exec("brokered session", `INSERT INTO brokered_sessions (org_id, user_id, target_type, target, principal, status, expires_at)
			VALUES ($1::uuid, $2::uuid, 'ssh', 'target.example.test', 'root', 'active', NOW() + INTERVAL '10 minutes')`, org, u)
	}
	// Live entry sessions: one on a broker connection for each real user, and
	// one of the disabled user's that never reached a connection.
	for _, u := range []string{disabled, enabled} {
		exec("live entry session", `INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, guac_connection_id, status)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'ssh', $4, 'active')`, org, entryID, u, "conn-"+suffix+"-"+u[:8])
	}
	exec("orphan entry session", `INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, status)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'ssh', 'active')`, org, entryID, disabled)

	svc := &Service{db: db, logger: zap.NewNop()}

	allowed := func(userID string) bool {
		t.Helper()
		ok, err := svc.pamEntryAllowed(orgCtx, org, entryID, userID, nil, "connect")
		if err != nil {
			t.Fatalf("pamEntryAllowed(%s): %v", userID, err)
		}
		return ok
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	live := func(u string) (grants, approvals, leases, sessions, links, brokered int) {
		grants = count(`SELECT COUNT(*) FROM pam_entry_grants WHERE org_id=$1 AND principal_type='user' AND principal_id=$2 AND (expires_at IS NULL OR expires_at > NOW())`, org, u)
		approvals = count(`SELECT COUNT(*) FROM pam_entry_access_requests WHERE org_id=$1 AND requester_id=$2::uuid AND status IN ('pending','approved')`, org, u)
		leases = count(`SELECT COUNT(*) FROM pam_active_checkouts WHERE org_id=$1 AND principal_id=$2::uuid AND status='active'`, org, u)
		sessions = count(`SELECT COUNT(*) FROM pam_entry_sessions WHERE org_id=$1 AND user_id=$2::uuid AND status='active'`, org, u)
		links = count(`SELECT COUNT(*) FROM temp_access_links WHERE org_id=$1 AND created_by=$2::uuid AND status='active'`, org, u)
		brokered = count(`SELECT COUNT(*) FROM brokered_sessions WHERE org_id=$1 AND user_id=$2::uuid AND status='active'`, org, u)
		return
	}

	if !allowed(disabled) || !allowed(enabled) {
		t.Fatal("both users must hold the entry before the sweep")
	}

	svc.runLifecycleEnforcement(sweepCtx)

	if allowed(disabled) {
		t.Error("the disabled user may still connect after the sweep")
	}
	if !allowed(enabled) {
		t.Error("the enabled user lost the entry")
	}
	for _, u := range []string{disabled, gone} {
		g, a, l, _, k, b := live(u)
		if g != 0 || a != 0 || l != 0 || k != 0 || b != 0 {
			t.Errorf("user %s still holds grants=%d approvals=%d leases=%d links=%d brokered=%d", u, g, a, l, k, b)
		}
	}
	if g, a, l, s, k, b := live(enabled); g != 1 || a != 1 || l != 1 || s != 1 || k != 1 || b != 1 {
		t.Errorf("the enabled user's rows were touched: grants=%d approvals=%d leases=%d sessions=%d links=%d brokered=%d", g, a, l, s, k, b)
	}
	if n := count(`SELECT COUNT(*) FROM pam_entry_grants WHERE org_id=$1 AND principal_type='group' AND principal_id=$2 AND (expires_at IS NULL OR expires_at > NOW())`, org, groupID); n != 1 {
		t.Errorf("the group's grant must survive, got %d", n)
	}
	// With no broker configured the disabled user's brokered entry session
	// must stay active (never a termination on paper); the one that never
	// reached a connection is closed.
	if n := count(`SELECT COUNT(*) FROM pam_entry_sessions WHERE org_id=$1 AND user_id=$2::uuid AND status='active' AND guac_connection_id IS NOT NULL`, org, disabled); n != 1 {
		t.Errorf("the disabled user's brokered entry session must stay active with no broker to end it, got %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM pam_entry_sessions WHERE org_id=$1 AND user_id=$2::uuid AND status='active' AND guac_connection_id IS NULL`, org, disabled); n != 0 {
		t.Errorf("the disabled user's entry session with no broker connection was not closed, %d still active", n)
	}

	// A second tick changes nothing more.
	before := count(`SELECT COUNT(*) FROM pam_entry_grants WHERE org_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`, org)
	svc.runLifecycleEnforcement(sweepCtx)
	if after := count(`SELECT COUNT(*) FROM pam_entry_grants WHERE org_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`, org); after != before {
		t.Errorf("second tick changed live grants from %d to %d", before, after)
	}
	if !allowed(enabled) {
		t.Error("the enabled user lost the entry on the second tick")
	}
}
