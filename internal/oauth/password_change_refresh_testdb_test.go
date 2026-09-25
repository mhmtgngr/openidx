package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/pwhash"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/revocation"
)

// A password change or reset is a session end for every session the old
// password opened. These tests drive the identity API the way the console and
// the reset page call it, with bearer tokens the issuer minted for real
// sessions, and then present each device's refresh token at the token
// endpoint.
//
// Before this, none of those paths ended anything. UpdatePassword and
// SetPassword wrote the new hash, the reset handler wrote it in its own
// transaction, and the directory paths wrote it to LDAP; not one of them
// revoked a refresh token or published a marker, and
// RevokeUserSessionsOnPasswordChange, which was written for exactly this, had
// no caller. So a user who changed their password because a device was lost
// left that device signed in.

const (
	// Both satisfy the identity service's password policy.
	pwBefore = "Before-Pass1!"
	pwAfter  = "After-Pass2!x"

	// adminRoleID is the admin role migrations seed in the default
	// organization.
	adminRoleID = "60000000-0000-0000-0000-000000000001"
)

// identityAPI serves the identity routes the way cmd/identity-service mounts
// them. A bearer token is verified against the fixture's issuer through its
// JWKS endpoint, so the session a token was minted on (its sid claim) reaches
// the handlers the way it does in production. The tenant is resolved in front,
// as the tenant middleware does.
func (f *sessionEndFixture) identityAPI(t *testing.T) *gin.Engine {
	t.Helper()
	jwks := gin.New()
	jwks.GET("/.well-known/jwks.json", f.svc.handleJWKS)
	srv := httptest.NewServer(jwks)
	t.Cleanup(srv.Close)
	f.cfg.OAuthJWKSURL = srv.URL + "/.well-known/jwks.json"

	r := gin.New()
	r.Use(inDefaultOrg)
	identity.RegisterRoutesForProfile(r, f.ids, identity.ProfileAll)
	return r
}

// inDefaultOrg resolves the tenant, as the tenant middleware in front of every
// service does.
func inDefaultOrg(c *gin.Context) {
	c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: sessionEndOrg}))
	c.Next()
}

func (f *sessionEndFixture) setPassword(t *testing.T, userID, password string) {
	t.Helper()
	hash, err := pwhash.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := f.db.Pool.Exec(context.Background(),
		`UPDATE users SET password_hash = $2 WHERE id = $1::uuid`, userID, hash); err != nil {
		t.Fatalf("set password: %v", err)
	}
}

func (f *sessionEndFixture) grantAdmin(t *testing.T, userID string) {
	t.Helper()
	if _, err := f.db.Pool.Exec(context.Background(), `
		INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		userID, adminRoleID, sessionEndOrg); err != nil {
		t.Fatalf("grant admin: %v", err)
	}
}

// makeDirectoryUser marks userID as an account whose password lives in LDAP.
// Directory sync stores a hash of a random password on such an account, which
// nobody can sign in with locally; so does this.
func (f *sessionEndFixture) makeDirectoryUser(t *testing.T, userID string) {
	t.Helper()
	f.setPassword(t, userID, "ldap-nologin-"+GenerateRandomToken(8))
	if _, err := f.db.Pool.Exec(context.Background(),
		`UPDATE users SET source = 'ldap', directory_id = gen_random_uuid() WHERE id = $1::uuid`, userID); err != nil {
		t.Fatalf("make directory user: %v", err)
	}
}

// bearer is the access token the issuer mints for userID on sessionID.
func (f *sessionEndFixture) bearer(t *testing.T, userID, sessionID string) string {
	t.Helper()
	tok, err := f.svc.GenerateJWT(f.orgCtx, userID, f.clientID, "openid profile email offline_access", 3600, sessionID)
	if err != nil {
		t.Fatalf("mint access token: %v", err)
	}
	return tok
}

// send makes one JSON request to api and returns the status and the decoded
// body.
func (f *sessionEndFixture) send(t *testing.T, api http.Handler, method, path, bearer string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// userinfoAccepts reports whether /oauth/userinfo still answers an access
// token. userinfo and introspection honour the per-user cutoff and the
// per-token blacklist, and nothing else.
func (f *sessionEndFixture) userinfoAccepts(t *testing.T, bearer string) bool {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	c.Request = req.WithContext(f.orgCtx)
	f.svc.handleUserInfo(c)
	switch w.Code {
	case http.StatusOK:
		return true
	case http.StatusUnauthorized:
		return false
	}
	t.Fatalf("userinfo answered %d: %s", w.Code, w.Body.String())
	return false
}

// directoryThatAccepts stands in for an LDAP or Active Directory server that
// takes every change it is sent.
type directoryThatAccepts struct{}

func (directoryThatAccepts) AuthenticateUser(context.Context, string, string, string) error {
	return nil
}

func (directoryThatAccepts) ChangePassword(context.Context, string, string, string, string) error {
	return nil
}

func (directoryThatAccepts) ResetPassword(context.Context, string, string, string) error {
	return nil
}

// A user changing their own password ends every other session they hold and
// keeps the one they made the change from. POST /users/me/change-password is
// what the console's Profile page calls.
func TestAPasswordChangeEndsEveryOtherSession(t *testing.T) {
	f := newSessionEndFixture(t)
	api := f.identityAPI(t)
	f.ids.SetDirectoryService(directoryThatAccepts{})

	changePassword := func(t *testing.T, bearer string) {
		t.Helper()
		code, body := f.send(t, api, http.MethodPost, "/api/v1/identity/users/me/change-password", bearer,
			map[string]string{"currentPassword": pwBefore, "newPassword": pwAfter})
		if code != http.StatusOK {
			t.Fatalf("change password: %d %v", code, body)
		}
	}

	user := f.seedUser(t, "changer")
	f.setPassword(t, user, pwBefore)
	here, hereDevice := f.newSession(t, user)
	lost, lostDevice := f.newSession(t, user)
	// A device signed in through the device authorization grant holds a
	// refresh token bound to no session. It is one of the user's other
	// devices all the same.
	tv := f.mintRefresh(t, user, "")
	lostAccess := f.bearer(t, user, lost)

	bystander := f.seedUser(t, "bystander")
	_, bystanderDevice := f.newSession(t, bystander)
	bystanderAccess := f.bearer(t, bystander, "")

	changePassword(t, f.bearer(t, user, here))

	t.Run("the session the change was made from keeps refreshing", func(t *testing.T) {
		hereDevice = f.refreshes(t, hereDevice, "the session the password was changed from")
	})
	t.Run("the user's other sessions cannot refresh", func(t *testing.T) {
		f.ended(t, lostDevice, "another session of the user who changed their password")
		f.ended(t, tv, "a refresh token bound to no session")
		if !f.mini.Exists("revoked_session:" + lost) {
			t.Error("no revoked_session marker was published for the session the change ended")
		}
		if f.mini.Exists("revoked_session:" + here) {
			t.Error("the session the change was made from was marked revoked")
		}
	})
	t.Run("the other sessions' access tokens are refused at userinfo", func(t *testing.T) {
		if f.userinfoAccepts(t, lostAccess) {
			t.Error("an access token of a session the password change ended is still answered by userinfo")
		}
	})
	t.Run("another user's session and access token are untouched", func(t *testing.T) {
		f.refreshes(t, bystanderDevice, "another user's session")
		if !f.userinfoAccepts(t, bystanderAccess) {
			t.Error("another user's access token was refused after this user changed their password")
		}
	})
	// The marker lives in Redis, which can be down or restarted empty. The
	// refresh tokens' own rows are what has to hold then.
	t.Run("with Redis down, the other sessions still cannot refresh", func(t *testing.T) {
		user := f.seedUser(t, "changer-redis-down")
		f.setPassword(t, user, pwBefore)
		here, hereDevice := f.newSession(t, user)
		_, lostDevice := f.newSession(t, user)
		access := f.bearer(t, user, here)

		f.mini.Close()
		defer func() {
			if err := f.mini.Restart(); err != nil {
				t.Fatalf("restart redis: %v", err)
			}
		}()
		changePassword(t, access)
		f.ended(t, lostDevice, "with Redis down, another session of the user who changed their password")
		f.refreshes(t, hereDevice, "with Redis down, the session the password was changed from")
	})
	t.Run("a directory account's change ends the other sessions too", func(t *testing.T) {
		user := f.seedUser(t, "changer-ldap")
		f.makeDirectoryUser(t, user)
		here, hereDevice := f.newSession(t, user)
		_, lostDevice := f.newSession(t, user)

		changePassword(t, f.bearer(t, user, here))
		f.ended(t, lostDevice, "another session of a directory user who changed their password")
		f.refreshes(t, hereDevice, "the session a directory user changed their password from")
	})
}

// A reset is made because the password is lost or no longer trusted, so it
// ends every session of the user, including one that is signed in right now:
// the forgotten-password link, an administrator setting a password, and an
// administrator resetting a directory account's.
func TestAPasswordResetEndsEverySession(t *testing.T) {
	f := newSessionEndFixture(t)
	api := f.identityAPI(t)
	f.ids.SetDirectoryService(directoryThatAccepts{})

	admin := f.seedUser(t, "admin")
	f.grantAdmin(t, admin)
	adminSession, adminDevice := f.newSession(t, admin)
	adminAccess := f.bearer(t, admin, adminSession)

	bystander := f.seedUser(t, "bystander")
	_, bystanderDevice := f.newSession(t, bystander)

	// user returns a user with two sessions and a refresh token bound to no
	// session, and the devices that hold them.
	type victim struct {
		id      string
		devices []string
	}
	user := func(t *testing.T, name string) victim {
		t.Helper()
		id := f.seedUser(t, name)
		f.setPassword(t, id, pwBefore)
		_, a := f.newSession(t, id)
		_, b := f.newSession(t, id)
		return victim{id: id, devices: []string{a, b, f.mintRefresh(t, id, "")}}
	}
	ended := func(t *testing.T, v victim, how string) {
		t.Helper()
		for _, d := range v.devices {
			f.ended(t, d, "a session of a user whose password was reset "+how)
		}
		bystanderDevice = f.refreshes(t, bystanderDevice, "another user's session")
		if !f.mini.Exists(revocation.UserTokensRevokedAtKey(v.id)) {
			t.Errorf("the reset %s left the user's outstanding access tokens valid at userinfo", how)
		}
	}
	forgotten := func(t *testing.T, v victim, token string) {
		t.Helper()
		if _, err := f.db.Pool.Exec(context.Background(), `
			INSERT INTO password_reset_tokens (user_id, token, expires_at, org_id)
			VALUES ($1::uuid, $2, NOW() + interval '1 hour', $3::uuid)`, v.id, token, sessionEndOrg); err != nil {
			t.Fatalf("seed reset token: %v", err)
		}
		code, body := f.send(t, api, http.MethodPost, "/api/v1/identity/users/reset-password", "",
			map[string]string{"token": token, "password": pwAfter})
		if code != http.StatusOK {
			t.Fatalf("reset password: %d %v", code, body)
		}
	}

	t.Run("the forgotten-password link", func(t *testing.T) {
		v := user(t, "forgot")
		forgotten(t, v, "reset-"+f.suffix+"-1")
		ended(t, v, "through the emailed link")
	})
	t.Run("an administrator setting the password", func(t *testing.T) {
		v := user(t, "set-by-admin")
		code, body := f.send(t, api, http.MethodPost, "/api/v1/identity/users/"+v.id+"/set-password", adminAccess,
			map[string]string{"password": pwAfter})
		if code != http.StatusOK {
			t.Fatalf("set password: %d %v", code, body)
		}
		ended(t, v, "by an administrator")
		adminDevice = f.refreshes(t, adminDevice, "the administrator's own session")
	})
	t.Run("an administrator resetting a directory account", func(t *testing.T) {
		v := user(t, "reset-ldap")
		f.makeDirectoryUser(t, v.id)
		code, body := f.send(t, api, http.MethodPost, "/api/v1/identity/users/"+v.id+"/reset-password", adminAccess,
			map[string]string{"newPassword": pwAfter})
		if code != http.StatusOK {
			t.Fatalf("reset directory password: %d %v", code, body)
		}
		ended(t, v, "in the directory by an administrator")
	})
	t.Run("with Redis down, the forgotten-password link still ends every session", func(t *testing.T) {
		v := user(t, "forgot-redis-down")
		f.mini.Close()
		defer func() {
			if err := f.mini.Restart(); err != nil {
				t.Fatalf("restart redis: %v", err)
			}
		}()
		forgotten(t, v, "reset-"+f.suffix+"-2")
		for _, d := range v.devices {
			f.ended(t, d, "with Redis down, a session of a user whose password was reset")
		}
		bystanderDevice = f.refreshes(t, bystanderDevice, "with Redis down, another user's session")
	})
}

// The lifecycle action revoke_sessions deleted the session rows and cut the
// access tokens, and said in a comment that deleting the rows ended the refresh
// path. The refresh grant read the token's own row and the marker, neither of
// which that wrote, so every device the user was signed in on kept refreshing.
// Each session now ends the way the Sessions page ends one.
func TestLifecycleRevokeSessionsEndsTheRefreshPath(t *testing.T) {
	f := newSessionEndFixture(t)
	wf := &identity.LifecycleWorkflow{
		Name:        "sign out " + f.suffix,
		EventType:   "leaver",
		TriggerType: "manual",
		Actions:     []map[string]interface{}{{"type": "revoke_sessions"}},
		Enabled:     true,
	}
	if err := f.ids.CreateLifecycleWorkflow(f.orgCtx, wf); err != nil {
		t.Fatalf("create workflow: %v", err)
	}
	run := func(t *testing.T, userID string) {
		t.Helper()
		exec, err := f.ids.ExecuteLifecycleWorkflow(f.orgCtx, wf.ID, userID, "")
		if err != nil {
			t.Fatalf("execute workflow: %v", err)
		}
		if exec.Status != "completed" {
			t.Fatalf("workflow %s: %v", exec.Status, exec.ActionsFailed)
		}
	}

	bystander := f.seedUser(t, "bystander")
	_, bystanderDevice := f.newSession(t, bystander)

	t.Run("every session of the user stops refreshing", func(t *testing.T) {
		user := f.seedUser(t, "leaver")
		one, first := f.newSession(t, user)
		_, second := f.newSession(t, user)
		tv := f.mintRefresh(t, user, "")
		run(t, user)
		f.ended(t, first, "a session the lifecycle action revoked")
		f.ended(t, second, "a session the lifecycle action revoked")
		f.ended(t, tv, "a refresh token bound to no session, after the lifecycle action revoked the user's sessions")
		if !f.mini.Exists("revoked_session:" + one) {
			t.Error("no revoked_session marker was published for a session the lifecycle action ended")
		}
	})
	t.Run("another user's session keeps refreshing", func(t *testing.T) {
		bystanderDevice = f.refreshes(t, bystanderDevice, "another user's session")
	})
	t.Run("with Redis down, the sessions still stop refreshing", func(t *testing.T) {
		user := f.seedUser(t, "leaver-redis-down")
		_, device := f.newSession(t, user)
		f.mini.Close()
		defer func() {
			if err := f.mini.Restart(); err != nil {
				t.Fatalf("restart redis: %v", err)
			}
		}()
		run(t, user)
		f.ended(t, device, "with Redis down, a session the lifecycle action revoked")
		bystanderDevice = f.refreshes(t, bystanderDevice, "with Redis down, another user's session")
	})
}
