package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// revokeSessionWithRedis is where oauth-service ends a session: the expiry and
// inactivity sweeps, the concurrent-session eviction, force-login, and
// /oauth/logout with only the browser cookie. It marked the row revoked and
// wrote a revoked_session marker that lives 25 hours, and it left the refresh
// tokens bound to the session as they were. The refresh grant reads the marker
// and the token's own row, not the session row, so a device that came back
// after the marker had aged out refreshed as if nothing had happened. A native
// client keeps its refresh token for 14 to 30 days.
//
// Each case ends a session through one of those doors, moves Redis past the
// marker's 25 hours, and presents the session's refresh token.
func TestASessionOAuthEndedStaysEndedAfterItsMarkerExpires(t *testing.T) {
	f := newSessionEndFixture(t)
	user := f.seedUser(t, "funnel")
	bystander := f.seedUser(t, "bystander")
	_, bystanderDevice := f.newSession(t, bystander)

	pastTheMarker := func() { f.mini.FastForward(25*time.Hour + time.Minute) }
	sweep := func() { f.svc.processExpiredSessions(orgctx.WithBypassRLS(context.Background())) }

	t.Run("the expiry sweep", func(t *testing.T) {
		// A session already past its expiry, as the sweep finds it.
		sess, err := f.ids.CreateSession(f.orgCtx, user, f.clientID, "203.0.113.9", "evidence-run", -time.Minute)
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		device := f.mintRefresh(t, user, sess.ID)
		sweep()
		f.ended(t, device, "a session the expiry sweep ended")
		pastTheMarker()
		f.ended(t, device, "25 hours later, a session the expiry sweep ended")
	})
	t.Run("the inactivity sweep", func(t *testing.T) {
		sid, device := f.newSession(t, user)
		if _, err := f.db.Pool.Exec(context.Background(),
			`UPDATE sessions SET last_seen_at = NOW() - interval '2 hours' WHERE id = $1::uuid`, sid); err != nil {
			t.Fatalf("age the session: %v", err)
		}
		sweep()
		f.ended(t, device, "a session the inactivity sweep ended")
		pastTheMarker()
		f.ended(t, device, "25 hours later, a session the inactivity sweep ended")
	})
	t.Run("the absolute timeout, counted from sign-in however active the session is", func(t *testing.T) {
		// The seeded Security tab sets no absolute timeout, so the default of
		// 24 hours applies. This session signed in 25 hours ago and refreshed
		// a moment ago: its expires_at is in the future and it is not idle.
		sid, device := f.newSession(t, user)
		if _, err := f.db.Pool.Exec(context.Background(), `
			UPDATE sessions SET started_at = NOW() - interval '25 hours', last_seen_at = NOW(),
			                    expires_at = NOW() + interval '1 hour'
			 WHERE id = $1::uuid`, sid); err != nil {
			t.Fatalf("age the session: %v", err)
		}
		young, youngDevice := f.newSession(t, user)
		if _, err := f.db.Pool.Exec(context.Background(),
			`UPDATE sessions SET started_at = NOW() - interval '23 hours' WHERE id = $1::uuid`, young); err != nil {
			t.Fatalf("age the session: %v", err)
		}
		sweep()
		f.ended(t, device, "a session past the absolute timeout")
		f.refreshes(t, youngDevice, "an active session inside the absolute timeout")
	})
	t.Run("a concurrent-session eviction", func(t *testing.T) {
		setSecurity := func(max int, strategy string) {
			t.Helper()
			if _, err := f.db.Pool.Exec(context.Background(), `
				UPDATE system_settings
				   SET value = jsonb_set(jsonb_set(value, '{security,max_concurrent_sessions}', to_jsonb($1::int)),
				                         '{security,concurrent_session_strategy}', to_jsonb($2::text))
				 WHERE key = 'system'`, max, strategy); err != nil {
				t.Fatalf("set the session policy: %v", err)
			}
		}
		setSecurity(2, "terminate_oldest")
		defer setSecurity(0, "deny_new")

		evicted := f.seedUser(t, "evicted")
		oldest, oldestDevice := f.newSession(t, evicted)
		if _, err := f.db.Pool.Exec(context.Background(),
			`UPDATE sessions SET started_at = NOW() - interval '1 hour' WHERE id = $1::uuid`, oldest); err != nil {
			t.Fatalf("age the session: %v", err)
		}
		_, newerDevice := f.newSession(t, evicted)
		// A third sign-in finds the limit reached and ends the oldest session.
		if action, _, err := f.svc.checkConcurrentSessions(f.orgCtx, evicted, f.clientID); err != nil || action != "" {
			t.Fatalf("eviction: action %q, err %v", action, err)
		}
		pastTheMarker()
		f.ended(t, oldestDevice, "25 hours later, the session the eviction ended")
		f.refreshes(t, newerDevice, "the session the eviction kept")
	})
	t.Run("force-login", func(t *testing.T) {
		sid, device := f.newSession(t, user)
		// The pending sign-in that asked which session to end, as the login
		// flow stores it when the concurrent-session limit prompts the user.
		pending := GenerateRandomToken(16)
		params, _ := json.Marshal(map[string]string{
			"user_id": user, "client_id": f.clientID, "redirect_uri": "https://app.example.test/callback",
			"scope": "openid offline_access", "state": "s",
		})
		f.mini.Set("login_session:"+pending, string(params))
		body, _ := json.Marshal(map[string]string{"terminate_session_id": sid, "login_session": pending})
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/oauth/force-login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req.WithContext(f.orgCtx)
		f.svc.handleForceLogin(c)

		f.ended(t, device, "the session force-login ended")
		pastTheMarker()
		f.ended(t, device, "25 hours later, the session force-login ended")
	})
	t.Run("logout with only the browser cookie", func(t *testing.T) {
		sid, device := f.newSession(t, user)
		cookie := GenerateRandomToken(32)
		f.mini.Set(ssoRedisPrefix+cookie, sid)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/oauth/logout", nil)
		req.AddCookie(&http.Cookie{Name: ssoCookieName, Value: cookie})
		c.Request = req.WithContext(f.orgCtx)
		f.svc.handleLogout(c)
		if w.Code != http.StatusOK {
			t.Fatalf("logout: %d %s", w.Code, w.Body.String())
		}

		f.ended(t, device, "the session the user signed out of")
		pastTheMarker()
		f.ended(t, device, "25 hours later, the session the user signed out of")
	})
	t.Run("another user's session keeps refreshing", func(t *testing.T) {
		f.refreshes(t, bystanderDevice, "another user's session")
	})
}

// A replayed refresh token revokes its family and marks the session behind it
// revoked in Redis for 24 hours, because "the session behind the chain is as
// compromised as the tokens". The session's other chains were left live under
// that marker: once it aged out they refreshed again.
func TestARefreshReplayEndsEveryChainOfItsSession(t *testing.T) {
	f := newSessionEndFixture(t)
	user := f.seedUser(t, "replayed")
	sid, stolen := f.newSession(t, user)
	// A second chain on the same session: another application the browser
	// session signed into.
	sibling := f.mintRefresh(t, user, sid)
	_, elsewhere := f.newSession(t, user)
	bystander := f.seedUser(t, "bystander")
	_, bystanderDevice := f.newSession(t, bystander)

	newest := f.refreshes(t, stolen, "the chain before the replay")
	f.cannotRefresh(t, stolen, "a replayed refresh token")
	f.ended(t, newest, "the newest token of a replayed chain")

	t.Run("the session's other chain stays refused once the marker has expired", func(t *testing.T) {
		f.ended(t, sibling, "another chain of the replayed session")
		f.mini.FastForward(24*time.Hour + time.Minute)
		f.ended(t, sibling, "24 hours later, another chain of the replayed session")
	})
	t.Run("the user's other session and another user's keep refreshing", func(t *testing.T) {
		f.refreshes(t, elsewhere, "the user's other session")
		f.refreshes(t, bystanderDevice, "another user's session")
	})
}
