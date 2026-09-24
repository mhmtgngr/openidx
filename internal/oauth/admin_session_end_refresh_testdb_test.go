package oauth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/access"
	"github.com/openidx/openidx/internal/admin"
	"github.com/openidx/openidx/internal/risk"
)

// The administrator's doors that end sessions, in internal/admin and
// internal/access: revoking one session or all of a user's from the Sessions
// page, breach containment, the kill switch, and revoking a device. Each is
// driven through its route as the console calls it, and each case takes Redis
// down first, because every one of them used to stop the refresh grant with
// the revoked_session marker alone -- or, for breach containment, with
// nothing -- so a Redis that was down, or restarted empty, left the ended
// sessions refreshing.

// asAdmin stands in for the gateway's authentication: the caller is adminID,
// holding the admin role.
func asAdmin(adminID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("user_id", adminID)
		c.Set("roles", []string{"admin"})
		c.Next()
	}
}

// adminAPI serves internal/admin's routes the way cmd/admin-api mounts them.
func (f *sessionEndFixture) adminAPI(adminID string) *gin.Engine {
	r := gin.New()
	g := r.Group("/api/v1/admin", inDefaultOrg, asAdmin(adminID))
	admin.RegisterRoutes(g, admin.NewService(f.db, f.rc, f.cfg, zap.NewNop()))
	return r
}

// accessAPI serves internal/access's routes the way cmd/access-service mounts
// them.
func (f *sessionEndFixture) accessAPI(adminID string) *gin.Engine {
	r := gin.New()
	access.RegisterRoutes(r, access.NewService(f.db, f.rc, f.cfg, zap.NewNop()), inDefaultOrg, asAdmin(adminID))
	return r
}

// redisDown stops Redis for the rest of the calling test, and starts it again
// when the test ends.
func (f *sessionEndFixture) redisDown(t *testing.T) {
	t.Helper()
	f.mini.Close()
	t.Cleanup(func() {
		if err := f.mini.Restart(); err != nil {
			t.Errorf("restart redis: %v", err)
		}
	})
}

func TestAnAdministratorEndingSessionsStopsTheirRefresh(t *testing.T) {
	f := newSessionEndFixture(t)
	operator := f.seedUser(t, "operator")
	adminAPI := f.adminAPI(operator)
	accessAPI := f.accessAPI(operator)
	bystander := f.seedUser(t, "bystander")
	_, bystanderDevice := f.newSession(t, bystander)
	stillRefreshes := func(t *testing.T) {
		t.Helper()
		bystanderDevice = f.refreshes(t, bystanderDevice, "another user's session")
	}

	t.Run("revoking one session from the Sessions page", func(t *testing.T) {
		user := f.seedUser(t, "revoked-one")
		sid, device := f.newSession(t, user)
		_, keptDevice := f.newSession(t, user)
		f.redisDown(t)
		code, body := f.send(t, adminAPI, http.MethodDelete, "/api/v1/admin/sessions/"+sid, "",
			map[string]string{"reason": "lost laptop"})
		if code != http.StatusOK {
			t.Fatalf("revoke session: %d %v", code, body)
		}
		f.cannotRefresh(t, device, "with Redis down, a session an administrator revoked")
		f.refreshes(t, keptDevice, "the user's session the administrator did not revoke")
		stillRefreshes(t)
	})
	t.Run("revoking all of a user's sessions", func(t *testing.T) {
		user := f.seedUser(t, "revoked-all")
		_, first := f.newSession(t, user)
		_, second := f.newSession(t, user)
		f.redisDown(t)
		code, body := f.send(t, adminAPI, http.MethodDelete, "/api/v1/admin/users/"+user+"/sessions", "",
			map[string]string{"reason": "offboarding"})
		if code != http.StatusOK {
			t.Fatalf("revoke all sessions: %d %v", code, body)
		}
		f.cannotRefresh(t, first, "with Redis down, a session an administrator revoked with the rest")
		f.cannotRefresh(t, second, "with Redis down, a session an administrator revoked with the rest")
		stillRefreshes(t)
	})
	t.Run("breach containment revoking the sessions", func(t *testing.T) {
		// Partial quarantine (a high-severity incident) revokes the affected
		// users' sessions and leaves the accounts enabled.
		contain := func(t *testing.T, user string) {
			t.Helper()
			var incident string
			if err := f.db.Pool.QueryRow(context.Background(), `
				INSERT INTO breach_incidents (type, severity, status, title, affected_user_ids, affected_sessions,
				                              quarantine_action, indicators, org_id)
				VALUES ('credential_stuffing', 'high', 'detected', 'test incident', ARRAY[$1::text], ARRAY[]::text[],
				        'none', '{}'::jsonb, $2::uuid)
				RETURNING id::text`, user, sessionEndOrg).Scan(&incident); err != nil {
				t.Fatalf("seed incident: %v", err)
			}
			code, body := f.send(t, adminAPI, http.MethodPost, "/api/v1/admin/ibdr/incidents/"+incident+"/respond", "", nil)
			if code != http.StatusOK {
				t.Fatalf("trigger incident response: %d %v", code, body)
			}
		}

		user := f.seedUser(t, "contained")
		sid, device := f.newSession(t, user)
		contain(t, user)
		f.cannotRefresh(t, device, "a session breach containment revoked")
		if !f.mini.Exists("revoked_session:" + sid) {
			t.Error("breach containment published no revoked_session marker for the session it revoked")
		}
		stillRefreshes(t)

		user = f.seedUser(t, "contained-redis-down")
		_, device = f.newSession(t, user)
		f.redisDown(t)
		contain(t, user)
		f.cannotRefresh(t, device, "with Redis down, a session breach containment revoked")
		stillRefreshes(t)
	})
	t.Run("the kill switch without disabling the account", func(t *testing.T) {
		user := f.seedUser(t, "killed")
		_, device := f.newSession(t, user)
		tv := f.mintRefresh(t, user, "")
		f.redisDown(t)
		code, body := f.send(t, accessAPI, http.MethodPost, "/api/v1/access/users/"+user+"/kill-switch", "",
			map[string]interface{}{"reason": "compromise suspected", "disable_user": false})
		if code != http.StatusOK {
			t.Fatalf("kill switch: %d %v", code, body)
		}
		f.cannotRefresh(t, device, "with Redis down, a session the kill switch revoked")
		f.cannotRefresh(t, tv, "with Redis down, a refresh token bound to no session, after the kill switch")
		stillRefreshes(t)
	})
	t.Run("revoking a device ends every chain of the sessions it ran under", func(t *testing.T) {
		user := f.seedUser(t, "device-owner")
		agent := "agent-" + f.suffix
		if _, err := f.db.Pool.Exec(context.Background(), `
			INSERT INTO enrolled_agents (agent_id, device_id, auth_token_hash, status, enrolled_by_user_id, org_id)
			VALUES ($1, $1, 'x', 'active', $2::uuid, $3::uuid)`, agent, user, sessionEndOrg); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		sess, err := f.ids.CreateSession(f.orgCtx, user, f.clientID, "203.0.113.9", "evidence-run", time.Hour)
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		deviceChain := "rt-device-" + sess.ID
		if err := f.svc.CreateRefreshToken(f.orgCtx, &RefreshToken{
			Token: deviceChain, ClientID: f.clientID, UserID: user, Scope: "openid offline_access",
			SessionID: sess.ID, AgentID: agent, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("mint device refresh token: %v", err)
		}
		// Another application the same browser session signed into, holding a
		// chain that names no device.
		otherChain := f.mintRefresh(t, user, sess.ID)
		_, elsewhere := f.newSession(t, user)
		f.redisDown(t)
		code, body := f.send(t, accessAPI, http.MethodPost,
			"/api/v1/access/users/"+user+"/devices/"+agent+"/revoke", "", map[string]string{"reason": "lost"})
		if code != http.StatusOK {
			t.Fatalf("revoke device: %d %v", code, body)
		}
		f.cannotRefresh(t, deviceChain, "the revoked device's own chain")
		f.cannotRefresh(t, otherChain, "with Redis down, another chain of a session the device revoke ended")
		f.refreshes(t, elsewhere, "the user's session that never ran on the device")
		stillRefreshes(t)
	})
}

// The risk engine's "revoke sessions" remediation has no caller yet. It marked
// the rows revoked and wrote no marker, so on the day it is wired it would end
// nothing a device notices unless it revokes the refresh tokens itself.
func TestRiskRemediationRevokingSessionsStopsTheirRefresh(t *testing.T) {
	f := newSessionEndFixture(t)
	user := f.seedUser(t, "remediated")
	_, device := f.newSession(t, user)
	tv := f.mintRefresh(t, user, "")
	bystander := f.seedUser(t, "bystander")
	_, bystanderDevice := f.newSession(t, bystander)

	if err := risk.NewService(f.db, f.rc, zap.NewNop()).RemediateRevokeSessions(f.orgCtx, user); err != nil {
		t.Fatalf("remediate: %v", err)
	}
	f.cannotRefresh(t, device, "a session the risk remediation revoked")
	f.cannotRefresh(t, tv, "a refresh token bound to no session, after the risk remediation")
	f.refreshes(t, bystanderDevice, "another user's session")
}
