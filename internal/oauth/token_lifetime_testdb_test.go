package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// A token that carries a time-bound role ends no later than the role (section
// 6.5 of the third-party access framework). On the migrated schema, through
// the refresh grant at the token endpoint:
//
//   - a user whose roles are standing gets the client's lifetime;
//   - a user holding a role until ten minutes from now gets a token, and an
//     expires_in, of at most ten minutes, though the client's lifetime is an
//     hour;
//   - a role whose window is already over is not in the token and does not
//     shorten it;
//   - of two windows, the earlier one ends the token;
//   - the authorization code grant and the device authorization grant cut
//     the access token, its expires_in and the ID token the same way.
func TestATokenCarryingATimeBoundRoleEndsWithIt(t *testing.T) {
	f := newSessionEndFixture(t)
	ctx := context.Background()
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := f.db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	var lifetime int
	if err := f.db.Pool.QueryRow(ctx, `UPDATE oauth_clients SET access_token_lifetime = 3600 WHERE client_id = $1 RETURNING access_token_lifetime`,
		f.clientID).Scan(&lifetime); err != nil {
		t.Fatalf("set the client's lifetime: %v", err)
	}
	role := func(name string) string {
		t.Helper()
		var id string
		if err := f.db.Pool.QueryRow(ctx, `INSERT INTO roles (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`,
			sessionEndOrg, name+"-"+f.suffix).Scan(&id); err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
		return id
	}
	assign := func(userID, roleID, until string) {
		t.Helper()
		if until == "" {
			exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`, userID, roleID, sessionEndOrg)
			return
		}
		exec(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, NOW() + $4::interval)`,
			userID, roleID, sessionEndOrg, until)
	}
	// issue refreshes a new session's token and returns expires_in and the
	// access token's own lifetime, from its iat to its exp.
	issue := func(userID string) (expiresIn, tokenLife int64, roles []interface{}) {
		t.Helper()
		_, tok := f.newSession(t, userID)
		code, _, body := f.refresh(t, tok)
		access, _ := body["access_token"].(string)
		if code != 200 || access == "" {
			t.Fatalf("refresh: %d %v", code, body)
		}
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(access, claims); err != nil {
			t.Fatalf("parse the access token: %v", err)
		}
		in, _ := body["expires_in"].(float64)
		exp, _ := claims["exp"].(float64)
		iat, _ := claims["iat"].(float64)
		roles, _ = claims["roles"].([]interface{})
		return int64(in), int64(exp - iat), roles
	}
	standingRole, shortRole, longRole, lapsedRole := role("tl-standing"), role("tl-short"), role("tl-long"), role("tl-lapsed")

	standing := f.seedUser(t, "tl-standing")
	assign(standing, standingRole, "")
	assign(standing, lapsedRole, "-1 minute")
	if in, life, roles := issue(standing); in != int64(lifetime) || life != int64(lifetime) || len(roles) != 1 {
		t.Errorf("standing roles and a lapsed one: expires_in %d, token lifetime %d, roles %v; want %d, %d and the standing role alone",
			in, life, roles, lifetime, lifetime)
	}

	elevated := f.seedUser(t, "tl-elevated")
	assign(elevated, standingRole, "")
	assign(elevated, longRole, "30 minutes")
	assign(elevated, shortRole, "10 minutes")
	in, life, roles := issue(elevated)
	if in > 600 || in < 590 || life != in {
		t.Errorf("a role until ten minutes from now: expires_in %d, token lifetime %d; want both about 600, the earlier window", in, life)
	}
	if len(roles) != 3 {
		t.Errorf("the token carries %v; want the three live roles", roles)
	}

	// The other two grants that mint a user's token take the same lifetime,
	// for the ID token too.
	lifeOf := func(raw string) int64 {
		t.Helper()
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
			t.Fatalf("parse a token: %v", err)
		}
		exp, _ := claims["exp"].(float64)
		iat, _ := claims["iat"].(float64)
		return int64(exp - iat)
	}
	post := func(handler func(*gin.Context), form url.Values) map[string]interface{} {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c.Request = req.WithContext(f.orgCtx)
		handler(c)
		body := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != http.StatusOK {
			t.Fatalf("token endpoint: %d %v", w.Code, body)
		}
		return body
	}
	checkCapped := func(what string, body map[string]interface{}) {
		t.Helper()
		in, _ := body["expires_in"].(float64)
		access, _ := body["access_token"].(string)
		if in > 600 || in < 590 || lifeOf(access) != int64(in) {
			t.Errorf("%s: expires_in %v, access token lifetime %d; want both about 600", what, in, lifeOf(access))
		}
		if id, _ := body["id_token"].(string); id != "" && lifeOf(id) != int64(in) {
			t.Errorf("%s: the ID token lives %d; want %v, as the access token", what, lifeOf(id), in)
		}
	}

	t.Run("the authorization code grant", func(t *testing.T) {
		code := "tl-code-" + f.suffix
		exec(`INSERT INTO oauth_authorization_codes (code, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, expires_at, org_id)
			VALUES ($1, $2, $3::uuid, 'https://rp.example.test/cb', 'openid', '', '', '', '', NOW() + interval '5 minutes', $4::uuid)`,
			code, f.clientID, elevated, sessionEndOrg)
		body := post(f.svc.handleAuthorizationCodeGrant, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "client_id": {f.clientID},
			"client_secret": {f.secret}, "redirect_uri": {"https://rp.example.test/cb"},
		})
		if body["id_token"] == nil {
			t.Fatalf("no ID token: %v", body)
		}
		checkCapped("the authorization code grant", body)
	})

	t.Run("the device authorization grant", func(t *testing.T) {
		deviceCode := "tl-device-" + f.suffix
		exec(`INSERT INTO oauth_device_codes (device_code_hash, user_code, client_id, scope, state, user_id, org_id, interval_secs, expires_at)
			VALUES ($1, $2, $3, 'openid', 'approved', $4::uuid, $5::uuid, 5, NOW() + interval '10 minutes')`,
			hashDeviceCode(deviceCode), "TLDV-"+f.suffix[len(f.suffix)-4:], f.clientID, elevated, sessionEndOrg)
		body := post(f.svc.handleDeviceCodeGrant, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {deviceCode},
			"client_id": {f.clientID}, "client_secret": {f.secret},
		})
		checkCapped("the device authorization grant", body)
	})
}
