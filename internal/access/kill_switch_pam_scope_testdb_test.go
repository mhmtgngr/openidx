package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The PAM entry half of the kill switch, on the migrated schema and through
// the route as it is mounted. Before this the emergency control left a user
// holding every PAM connection grant, launch approval, exclusive lease, live
// entry session, issued vendor link and brokered SSH or cloud session they
// had, and reported nothing about any of them.
//
// Both halves: the target user's rows end and pamEntryAllowed refuses them,
// while a bystander with the same rows on the same entry keeps every one of
// them, and a grant held through a group is the group's and stays. The live
// entry session that has a broker connection stays open in the ledger,
// because no broker is configured here and the ledger never claims a
// termination that did not happen; the response says so. A second press is
// a no-op.
func TestKillSwitchEndsThePamEntrySurface(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
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
	target := seedUser("ks-target")
	bystander := seedUser("ks-bystander")
	admin := seedUser("ks-admin")

	var entryID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
		VALUES ($1::uuid, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`,
		org, "kill-switch-"+suffix).Scan(&entryID); err != nil {
		t.Fatalf("seed entry: %v", err)
	}
	// The bystander also holds the entry through a group; the target does not
	// belong to it. The group's grant is the group's, not any member's.
	var groupID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO groups (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`,
		org, "kill-switch-group-"+suffix).Scan(&groupID); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	exec := func(what, sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %s: %v", what, err)
		}
	}
	exec("group membership", `INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		bystander, groupID, org)
	exec("group grant", `INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		VALUES ($1::uuid, $2::uuid, 'group', $3, '{connect}')`, org, entryID, groupID)

	// Every row the kill switch must end, once for the target and once for
	// the bystander.
	for _, u := range []string{target, bystander} {
		exec("user grant", `INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1::uuid, $2::uuid, 'user', $3, '{connect,reveal}')`, org, entryID, u)
		exec("approved launch", `INSERT INTO pam_entry_access_requests (org_id, entry_id, requester_id, status, expires_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'approved', NOW() + INTERVAL '1 hour')`, org, entryID, u)
		exec("pending launch", `INSERT INTO pam_entry_access_requests (org_id, entry_id, requester_id, status)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'pending')`, org, entryID, u)
		exec("lease", `INSERT INTO pam_active_checkouts (org_id, entry_id, principal_id, action, status, expires_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'connect', 'active', NOW() + INTERVAL '15 minutes')`, org, entryID, u)
		// A session the broker still serves: it names its connection.
		exec("live entry session", `INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, guac_connection_id, status)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'ssh', $4, 'active')`, org, entryID, u, "conn-"+suffix+"-"+u[:8])
		exec("temp link", `INSERT INTO temp_access_links (org_id, token, name, protocol, target_host, target_port, created_by, expires_at, status, pam_entry_id)
			VALUES ($1::uuid, $2, $3, 'ssh', 'target.example.test', 22, $4::uuid, NOW() + INTERVAL '1 day', 'active', $5::uuid)`,
			org, "tok-"+suffix+"-"+u[:8], "link-"+suffix, u, entryID)
		exec("brokered session", `INSERT INTO brokered_sessions (org_id, user_id, target_type, target, principal, status, expires_at)
			VALUES ($1::uuid, $2::uuid, 'ssh', 'target.example.test', 'root', 'active', NOW() + INTERVAL '10 minutes')`, org, u)
	}
	// And one entry session of the target's that never reached a broker
	// connection: nothing to terminate, so the ledger can close it.
	exec("orphan entry session", `INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, status)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'ssh', 'active')`, org, entryID, target)

	logger := zap.NewNop()
	svc := &Service{db: db, logger: logger, auditService: NewUnifiedAuditService(db, logger)}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", admin)
		c.Next()
	})
	router.POST("/api/v1/access/users/:id/kill-switch", svc.handleUserKillSwitch)

	press := func(userID string) KillSwitchResult {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/access/users/"+userID+"/kill-switch",
			strings.NewReader(`{"reason":"compromise suspected"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("kill switch for %s: %d %s", userID, w.Code, w.Body.String())
		}
		var res KillSwitchResult
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode kill switch result: %v", err)
		}
		return res
	}
	allowed := func(userID string) bool {
		t.Helper()
		ok, err := svc.pamEntryAllowed(orgCtx, org, entryID, userID, nil, "connect")
		if err != nil {
			t.Fatalf("pamEntryAllowed(%s): %v", userID, err)
		}
		return ok
	}
	count := func(what, sql string, args ...any) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", what, err)
		}
		return n
	}
	liveGrants := func(principalType, principalID string) int {
		return count("grants", `SELECT COUNT(*) FROM pam_entry_grants
			WHERE org_id = $1 AND entry_id = $2 AND principal_type = $3 AND principal_id = $4
			  AND (expires_at IS NULL OR expires_at > NOW())`, org, entryID, principalType, principalID)
	}
	openApprovals := func(u string) int {
		return count("approvals", `SELECT COUNT(*) FROM pam_entry_access_requests
			WHERE org_id = $1 AND requester_id = $2::uuid AND status IN ('pending','approved')`, org, u)
	}
	liveLeases := func(u string) int {
		return count("leases", `SELECT COUNT(*) FROM pam_active_checkouts
			WHERE org_id = $1 AND principal_id = $2::uuid AND status = 'active'`, org, u)
	}
	liveEntrySessions := func(u string) int {
		return count("entry sessions", `SELECT COUNT(*) FROM pam_entry_sessions
			WHERE org_id = $1 AND user_id = $2::uuid AND status = 'active'`, org, u)
	}
	activeLinks := func(u string) int {
		return count("temp links", `SELECT COUNT(*) FROM temp_access_links
			WHERE org_id = $1 AND created_by = $2::uuid AND status = 'active'`, org, u)
	}
	liveBrokered := func(u string) int {
		return count("brokered sessions", `SELECT COUNT(*) FROM brokered_sessions
			WHERE org_id = $1 AND user_id = $2::uuid AND status = 'active'`, org, u)
	}

	// Before: both users may connect.
	if !allowed(target) || !allowed(bystander) {
		t.Fatalf("both users must hold the entry before the kill switch: target=%v bystander=%v",
			allowed(target), allowed(bystander))
	}

	res := press(target)

	if res.PamEntryGrantsExpired != 1 {
		t.Errorf("pam_entry_grants_expired: want 1, got %d", res.PamEntryGrantsExpired)
	}
	if res.PamEntryApprovalsRevoked != 2 {
		t.Errorf("pam_entry_approvals_revoked: want 2 (one approved, one pending), got %d", res.PamEntryApprovalsRevoked)
	}
	if res.PamEntryLeasesReleased != 1 {
		t.Errorf("pam_entry_leases_released: want 1, got %d", res.PamEntryLeasesReleased)
	}
	// Only the session with no broker connection can be closed honestly.
	if res.PamEntrySessionsEnded != 1 {
		t.Errorf("pam_entry_sessions_ended: want 1 (the one with no broker connection), got %d", res.PamEntrySessionsEnded)
	}
	if res.TempAccessLinksRevoked != 1 {
		t.Errorf("pam_temp_links_revoked: want 1, got %d", res.TempAccessLinksRevoked)
	}
	if res.BrokeredSessionsEnded != 1 {
		t.Errorf("pam_brokered_sessions_ended: want 1, got %d", res.BrokeredSessionsEnded)
	}
	wantWarning := func(fragment string) {
		t.Helper()
		for _, w := range res.Warnings {
			if strings.Contains(w, fragment) {
				return
			}
		}
		t.Errorf("no warning containing %q in %v", fragment, res.Warnings)
	}
	wantWarning("PAM broker not configured")
	wantWarning("brokered_sessions")

	// Enforcement: the target is refused, the bystander is not.
	if allowed(target) {
		t.Error("target may still connect to the entry after the kill switch")
	}
	if !allowed(bystander) {
		t.Error("bystander lost the entry although the kill switch was not pointed at them")
	}

	// The rows, both sides.
	if n := liveGrants("user", target); n != 0 {
		t.Errorf("target still holds %d live user grants", n)
	}
	if n := liveGrants("user", bystander); n != 1 {
		t.Errorf("bystander's user grant must survive, got %d", n)
	}
	if n := liveGrants("group", groupID); n != 1 {
		t.Errorf("the group's grant must survive, got %d", n)
	}
	if n := openApprovals(target); n != 0 {
		t.Errorf("target still has %d open launch approvals", n)
	}
	if n := openApprovals(bystander); n != 2 {
		t.Errorf("bystander's launch approvals must survive, got %d", n)
	}
	if n := liveLeases(target); n != 0 {
		t.Errorf("target still holds %d leases", n)
	}
	if n := liveLeases(bystander); n != 1 {
		t.Errorf("bystander's lease must survive, got %d", n)
	}
	// The brokered entry session stays open in the ledger: no broker here
	// could have terminated it, and the ledger must not claim otherwise.
	if n := liveEntrySessions(target); n != 1 {
		t.Errorf("target's brokered entry session must stay active with no broker to end it, got %d live", n)
	}
	if n := liveEntrySessions(bystander); n != 1 {
		t.Errorf("bystander's entry session must survive, got %d", n)
	}
	if n := activeLinks(target); n != 0 {
		t.Errorf("target's temp link is still active (%d)", n)
	}
	if n := activeLinks(bystander); n != 1 {
		t.Errorf("bystander's temp link must survive, got %d", n)
	}
	if n := liveBrokered(target); n != 0 {
		t.Errorf("target's brokered session is still active (%d)", n)
	}
	if n := liveBrokered(bystander); n != 1 {
		t.Errorf("bystander's brokered session must survive, got %d", n)
	}

	// Idempotent: nothing left to end, and nothing of the bystander's touched.
	again := press(target)
	if again.PamEntryGrantsExpired != 0 || again.PamEntryApprovalsRevoked != 0 || again.PamEntryLeasesReleased != 0 ||
		again.PamEntrySessionsEnded != 0 || again.TempAccessLinksRevoked != 0 || again.BrokeredSessionsEnded != 0 {
		t.Errorf("second press is not a no-op: %+v", again)
	}
	if !allowed(bystander) {
		t.Error("bystander lost the entry on the second press")
	}
}
