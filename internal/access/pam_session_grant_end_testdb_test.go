package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// A PAM session lasts as long as the access that opened it (P5 of the
// third-party access framework). On the migrated schema, one session per case
// on one SSH entry, then one tick of the lifecycle sweep:
//
//   - ended: a session opened on a request's grant whose window closed (its
//     user still holds the standing view grant that let them ask), one
//     whose standing grant an administrator removed, one whose role
//     assignment expired, and one whose user left the group that carried it;
//   - kept: a session whose user still holds a standing grant, one held
//     through a role, one held through a group, one an administrator opened
//     without any grant (admin_bypass names 'grant'), and one recorded before
//     migration v217 (admin_bypass NULL);
//   - each ended session is audited once as pam.session_ended, reason
//     grant_ended, and a kept one not at all;
//   - a second pass ends nothing more and audits nothing more.
//
// And the launch records what the sweep reads: an administrator's connect
// without a grant writes admin_bypass {grant}, a granted user's writes {}.
func TestAPamSessionEndsWithTheGrantThatOpenedIt(t *testing.T) {
	gin.SetMode(gin.TestMode)
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
	octx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(octx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(octx, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
			org, name+"-"+suffix)
	}
	entry := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
		VALUES ($1::uuid, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`, org, "session-grant-"+suffix)
	grant := func(principalType, principalID, until string) {
		t.Helper()
		exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions, expires_at)
			VALUES ($1::uuid, $2::uuid, $3, $4, '{connect}', NULLIF($5, '')::timestamptz)`, org, entry, principalType, principalID, until)
	}
	session := func(userID string, bypass interface{}) string {
		return scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, admin_bypass)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'ssh', $4) RETURNING id::text`, org, entry, userID, bypass)
	}

	requested, removed, standing, viaRole, viaGroup, admin, legacy :=
		user("sg-requested"), user("sg-removed"), user("sg-standing"), user("sg-role"), user("sg-group"), user("sg-admin"), user("sg-legacy")
	roleLapsed, groupLeft := user("sg-role-lapsed"), user("sg-group-left")

	req := scalar(`INSERT INTO access_requests (requester_id, resource_type, resource_id, resource_name, status, expires_at, org_id)
		VALUES ($1::uuid, 'pam_entry', $2::uuid, 'session grant', 'fulfilled', NOW() + interval '1 hour', $3::uuid) RETURNING id::text`,
		requested, entry, org)
	exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions, expires_at, request_id)
		VALUES ($1::uuid, $2::uuid, 'user', $3, '{connect}', NOW() + interval '1 hour', $4::uuid)`, org, entry, requested, req)
	exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		VALUES ($1::uuid, $2::uuid, 'user', $3, '{view}')`, org, entry, requested)
	grant("user", removed, "")
	grant("user", standing, "")
	roleName := "sg-operators-" + suffix
	roleID := scalar(`INSERT INTO roles (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`, org, roleName)
	exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, viaRole, roleID, org)
	exec(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, NOW() + interval '1 hour')`, roleLapsed, roleID, org)
	grant("role", roleName, "")
	groupID := scalar(`INSERT INTO groups (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`, org, "sg-group-"+suffix)
	exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, viaGroup, groupID, org)
	exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, groupLeft, groupID, org)
	grant("group", groupID, "")

	none := []string{}
	sessions := map[string]string{
		"requested":  session(requested, none),
		"removed":    session(removed, none),
		"standing":   session(standing, none),
		"viaRole":    session(viaRole, none),
		"viaGroup":   session(viaGroup, none),
		"admin":      session(admin, []string{"grant"}),
		"legacy":     session(legacy, nil),
		"roleLapsed": session(roleLapsed, none),
		"groupLeft":  session(groupLeft, none),
	}

	// The request's window closes and an administrator removes a grant.
	exec(`UPDATE pam_entry_grants SET expires_at = NOW() WHERE request_id = $1::uuid`, req)
	exec(`DELETE FROM pam_entry_grants WHERE entry_id = $1::uuid AND principal_type = 'user' AND principal_id = $2`, entry, removed)
	// One user's role assignment runs out; another leaves the group.
	exec(`UPDATE user_roles SET expires_at = NOW() WHERE user_id = $1::uuid`, roleLapsed)
	exec(`DELETE FROM group_memberships WHERE user_id = $1::uuid`, groupLeft)

	logger := zap.NewNop()
	svc := &Service{db: db, config: &config.Config{}, logger: logger, auditService: NewUnifiedAuditService(db, logger)}
	sweepCtx := orgctx.WithBypassRLS(ctx)
	status := func(id string) string { return scalar(`SELECT status FROM pam_entry_sessions WHERE id = $1::uuid`, id) }
	audited := func(id string) string {
		return scalar(`SELECT COUNT(*)::text || ' ' || COALESCE(string_agg(details->>'reason', ','), '')
			FROM unified_audit_events WHERE event_type = 'pam.session_ended' AND details->>'session_id' = $1`, id)
	}
	svc.runLifecycleEnforcement(sweepCtx)
	want := map[string]string{
		"requested": "ended", "removed": "ended", "roleLapsed": "ended", "groupLeft": "ended",
		"standing": "active", "viaRole": "active", "viaGroup": "active", "admin": "active", "legacy": "active",
	}
	wantAudit := func(name string) string {
		if want[name] == "ended" {
			return "1 grant_ended"
		}
		return "0 "
	}
	for name, w := range want {
		if got := status(sessions[name]); got != w {
			t.Errorf("the %s session is %s after the sweep, want %s", name, got, w)
		}
		if got := audited(sessions[name]); got != wantAudit(name) {
			t.Errorf("the %s session has pam.session_ended events %q, want %q", name, got, wantAudit(name))
		}
	}
	endedAt := scalar(`SELECT ended_at::text FROM pam_entry_sessions WHERE id = $1::uuid`, sessions["requested"])
	svc.runLifecycleEnforcement(sweepCtx)
	if again := scalar(`SELECT ended_at::text FROM pam_entry_sessions WHERE id = $1::uuid`, sessions["requested"]); again != endedAt {
		t.Errorf("a second pass touched an ended session again: ended_at %s then %s", endedAt, again)
	}
	for name, w := range want {
		if got := status(sessions[name]); got != w {
			t.Errorf("after a second pass the %s session is %s, want %s", name, got, w)
		}
		if got := audited(sessions[name]); got != wantAudit(name) {
			t.Errorf("after a second pass the %s session has pam.session_ended events %q, want %q", name, got, wantAudit(name))
		}
	}

	t.Run("the launch records what the sweep reads", func(t *testing.T) {
		launcher := user("sg-launcher")
		website := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, url)
			VALUES ($1::uuid, $2, 'website', 'https://intranet.example.test') RETURNING id::text`, org, "site-"+suffix)
		exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1::uuid, $2::uuid, 'user', $3, '{connect}')`, org, website, launcher)
		connect := func(userID string, roles ...string) {
			t.Helper()
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
				c.Set("user_id", userID)
				c.Set("roles", roles)
				c.Next()
			})
			r.POST("/pam/entries/:id/connect", svc.handlePamConnect)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/pam/entries/"+website+"/connect", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("connect as %s: %d %s", userID, w.Code, w.Body.String())
			}
		}
		connect(launcher, "user")
		connect(admin, "admin")
		bypass := func(userID string) string {
			return scalar(`SELECT array_to_string(admin_bypass, ',') FROM pam_entry_sessions
				WHERE entry_id = $1::uuid AND user_id = $2::uuid ORDER BY started_at DESC LIMIT 1`, website, userID)
		}
		if got := bypass(launcher); got != "" {
			t.Errorf("a granted user's launch recorded admin_bypass %q, want none", got)
		}
		if got := bypass(admin); got != "grant" {
			t.Errorf("an administrator's launch without a grant recorded admin_bypass %q, want grant", got)
		}
	})
}

// A browser terminal closes once its ledger row is ended, and only then; its
// watcher stops with the connection without closing anything; and a closed
// terminal's row is marked ended.
func TestABrowserTerminalClosesWhenItsSessionEnds(t *testing.T) {
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
	octx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	var entry string
	if err := db.Pool.QueryRow(octx, `INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
		VALUES ($1::uuid, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`, org, "terminal-"+suffix).Scan(&entry); err != nil {
		t.Fatal(err)
	}
	newSession := func() string {
		var id string
		if err := db.Pool.QueryRow(octx, `INSERT INTO pam_entry_sessions (org_id, entry_id, protocol, admin_bypass)
			VALUES ($1::uuid, $2::uuid, 'ssh', '{}') RETURNING id::text`, org, entry).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	svc := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	defer func(old time.Duration) { pamTerminalWatchInterval = old }(pamTerminalWatchInterval)
	pamTerminalWatchInterval = 20 * time.Millisecond

	watched := newSession()
	closed := make(chan struct{})
	stop := make(chan struct{})
	go svc.watchPamTerminal(org, watched, stop, func() { close(closed) })
	select {
	case <-closed:
		t.Fatal("the terminal was closed while its session was active")
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := db.Pool.Exec(octx, `UPDATE pam_entry_sessions SET status = 'ended', ended_at = NOW() WHERE id = $1::uuid`, watched); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the terminal stayed open after its session was ended")
	}

	other := newSession()
	otherClosed := make(chan struct{}, 1)
	otherStop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		svc.watchPamTerminal(org, other, otherStop, func() { otherClosed <- struct{}{} })
		close(done)
	}()
	close(otherStop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher did not return when its connection closed")
	}
	if len(otherClosed) != 0 {
		t.Error("the watcher closed a terminal whose connection had already closed on its own")
	}
	svc.endPamTerminalRow(org, other)
	var status string
	if err := db.Pool.QueryRow(octx, `SELECT status FROM pam_entry_sessions WHERE id = $1::uuid`, other).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "ended" {
		t.Errorf("a closed terminal's session is %s, want ended", status)
	}
}
