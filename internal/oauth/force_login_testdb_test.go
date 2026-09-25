package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// POST /oauth/force-login is public. It is where a user whose sign-in hit the
// concurrent-session limit names the session to end, and it used to end
// terminate_session_id before it read the pending sign-in that says who is
// asking. So anyone who knew a session id -- the sid claim every relying party
// the session reached was handed -- could end it, and now that ending a
// session revokes its refresh tokens, end it for good.
func TestForceLoginEndsOnlyASessionOfTheUserSigningIn(t *testing.T) {
	f := newSessionEndFixture(t)
	user := f.seedUser(t, "signing-in")
	victim := f.seedUser(t, "victim")

	// pending stores a sign-in waiting at the concurrent-session prompt, as
	// the login handler stores it, and returns its id. userID "" stores one
	// that no password check has completed.
	pending := func(t *testing.T, userID string) string {
		t.Helper()
		params := map[string]string{
			"client_id": f.clientID, "redirect_uri": "https://app.example.test/callback",
			"scope": "openid offline_access", "state": "s",
		}
		if userID != "" {
			params["user_id"] = userID
		}
		raw, _ := json.Marshal(params)
		id := GenerateRandomToken(16)
		f.mini.Set("login_session:"+id, string(raw))
		return id
	}
	forceLogin := func(t *testing.T, terminate, loginSession string) (int, map[string]interface{}) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"terminate_session_id": terminate, "login_session": loginSession})
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/oauth/force-login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req.WithContext(f.orgCtx)
		f.svc.handleForceLogin(c)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	stillLive := func(t *testing.T, sid, device, what string) {
		t.Helper()
		live, err := f.svc.sessionIsLive(f.orgCtx, sid)
		if err != nil || !live {
			t.Errorf("%s: the session was ended (live=%v err=%v)", what, live, err)
		}
		if f.revokedInDB(t, device) {
			t.Errorf("%s: the session's refresh token was revoked", what)
		}
		if f.mini.Exists("revoked_session:" + sid) {
			t.Errorf("%s: a revoked_session marker was published", what)
		}
	}
	refused := func(t *testing.T, code int, body map[string]interface{}, wantErr, what string) {
		t.Helper()
		if code != http.StatusBadRequest || body["error"] != wantErr {
			t.Errorf("%s: status %d, body %v; want 400 %s", what, code, body, wantErr)
		}
		if body["redirect_url"] != nil {
			t.Errorf("%s: sign-in resumed and an authorization code was issued", what)
		}
	}

	t.Run("another user's session is refused and stays live", func(t *testing.T) {
		victimSession, victimDevice := f.newSession(t, victim)
		code, body := forceLogin(t, victimSession, pending(t, user))
		refused(t, code, body, "invalid_request", "ending another user's session")
		stillLive(t, victimSession, victimDevice, "another user's session")
		f.refreshes(t, victimDevice, "the other user's session")
	})
	t.Run("an id that names no session gets the same answer", func(t *testing.T) {
		code, body := forceLogin(t, "00000000-0000-0000-0000-00000000dead", pending(t, user))
		refused(t, code, body, "invalid_request", "an unknown session id")
	})
	t.Run("a missing sign-in is refused and nothing is ended", func(t *testing.T) {
		victimSession, victimDevice := f.newSession(t, victim)
		code, body := forceLogin(t, victimSession, "no-such-login-session")
		refused(t, code, body, "login_session_expired", "no pending sign-in")
		stillLive(t, victimSession, victimDevice, "a session named with no pending sign-in")
	})
	t.Run("a sign-in no password check completed is refused", func(t *testing.T) {
		own, ownDevice := f.newSession(t, user)
		code, body := forceLogin(t, own, pending(t, ""))
		refused(t, code, body, "invalid_request", "a pending sign-in without a user")
		stillLive(t, own, ownDevice, "a session named by a sign-in without a user")
	})
	t.Run("the user's own live session is ended and the sign-in resumes", func(t *testing.T) {
		own, ownDevice := f.newSession(t, user)
		loginSession := pending(t, user)
		code, body := forceLogin(t, own, loginSession)
		if code != http.StatusOK {
			t.Fatalf("force-login: %d %v", code, body)
		}
		redirect, _ := body["redirect_url"].(string)
		if !strings.Contains(redirect, "code=") {
			t.Errorf("no authorization code was issued: %v", body)
		}
		f.ended(t, ownDevice, "the session the user chose to end")
		if f.mini.Exists("login_session:" + loginSession) {
			t.Error("the pending sign-in was left in place after it resumed")
		}
	})
	t.Run("a session of the user that has already ended is refused", func(t *testing.T) {
		own, _ := f.newSession(t, user)
		if _, err := f.db.Pool.Exec(context.Background(),
			`UPDATE sessions SET revoked = true, revoked_at = NOW() WHERE id = $1::uuid`, own); err != nil {
			t.Fatal(err)
		}
		code, body := forceLogin(t, own, pending(t, user))
		refused(t, code, body, "invalid_request", "an ended session")
	})
}
