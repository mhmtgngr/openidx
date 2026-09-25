package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/revocation"
)

// A logout that names the user (id_token_hint) writes the per-user revocation
// marker, and the marker used to be compared with a token's iat in whole
// seconds with `<=`. So a user who signed out and straight back in inside one
// second got a token /oauth/userinfo refused, and the OpenID conformance suite
// -- which starts its next module inside that second -- met it on every
// logout. These pin the repair and the property it must not cost: a token
// that dates from before the logout, even in the same second, is still
// refused.

const testPKCEVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 App. B; hashes to testCodeChallenge

func withSigningKey(t *testing.T, svc *Service) *rsa.PrivateKey {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	svc.privateKey, svc.publicKey = pk, &pk.PublicKey
	return pk
}

// introspectActive asks the mounted /oauth/introspect, as client "c", whether
// the token is active.
func introspectActive(t *testing.T, r *gin.Engine, token string) bool {
	t.Helper()
	w := serve(r, http.MethodPost, "/oauth/introspect", formType,
		url.Values{"client_id": {"c"}, "token": {token}}.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("introspect: %d %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body["active"] == true
}

// Through the real introspection route, with tokens shaped as each release
// mints them and a marker written the way the logout writes it.
func TestTheRevocationCutoffIsComparedToTheMicrosecond(t *testing.T) {
	svc := newLoginUITestService(t, "", ssoTestClient())
	pk := withSigningKey(t, svc)
	r := routedService(t, svc, ssoTestOrg, nil)

	const user = "44444444-0000-0000-0000-000000000001"
	second := time.Now().Add(-time.Minute).Truncate(time.Second)
	logout := second.Add(500 * time.Millisecond)
	if err := svc.redis.Client.Set(context.Background(), revocation.UserTokensRevokedAtKey(user),
		revocation.MarkerValue(logout), revocation.MarkerTTL).Err(); err != nil {
		t.Fatal(err)
	}

	token := func(iat time.Time, grantedAt *time.Time) string {
		claims := jwt.MapClaims{
			"sub": user, "client_id": "c", "aud": "c", "scope": "openid",
			"iat": iat.Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}
		if grantedAt != nil {
			claims[revocation.GrantedAtClaim] = grantedAt.UnixMicro()
		}
		return mintToken(t, claims, pk)
	}
	at := func(d time.Duration) *time.Time { v := second.Add(d); return &v }

	for _, tc := range []struct {
		name   string
		token  string
		active bool
	}{
		{"signed in again after the logout, same second", token(second, at(600*time.Millisecond)), true},
		{"issued before the logout, same second", token(second, at(400*time.Millisecond)), false},
		{"from an older release (iat only), same second", token(second, nil), false},
		{"from a code issued before the logout, redeemed the next second",
			token(second.Add(time.Second), at(400*time.Millisecond)), false},
		{"from an older release, the next second", token(second.Add(time.Second), nil), true},
	} {
		if got := introspectActive(t, r, tc.token); got != tc.active {
			t.Errorf("%s: active = %v, want %v", tc.name, got, tc.active)
		}
	}
}

// The whole path, against a real database, through the mounted routes: codes
// issued under a browser session, an RP-initiated logout by id_token_hint, and
// a sign-in straight afterwards inside the same second.
func TestASignInAfterALogoutInTheSameSecondIsNotRevoked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, db := ssoSetupDB(t)
	pk := withSigningKey(t, svc)
	r := routedService(t, svc, ssoTestOrg, nil)
	ctx := context.Background()

	authorize := func(t *testing.T, cookie string) string {
		t.Helper()
		q := authorizeRequest(nil)
		w := serve(r, http.MethodGet, "/oauth/authorize?"+q.Encode(), "", "", "Cookie", ssoCookieName+"="+cookie)
		u := locationOf(t, w)
		code := u.Query().Get("code")
		if code == "" {
			t.Fatalf("no code: %s", u)
		}
		return code
	}
	exchange := func(t *testing.T, code string) (int, map[string]interface{}) {
		t.Helper()
		w := serve(r, http.MethodPost, "/oauth/token", formType, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"c"},
			"redirect_uri": {ssoTestRedirect}, "code_verifier": {testPKCEVerifier},
		}.Encode())
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body
	}
	accessToken := func(t *testing.T, code string) string {
		t.Helper()
		status, body := exchange(t, code)
		tok, _ := body["access_token"].(string)
		if status != http.StatusOK || tok == "" {
			t.Fatalf("exchange: %d %v", status, body)
		}
		return tok
	}

	// One attempt: returns false when the logout and the sign-in after it did
	// not land in the same second, so the case under test was not exercised.
	attempt := func(t *testing.T) bool {
		userID := uuid.New().String()
		_, before := ssoSession(t, svc, db, ssoTestOrg, userID, time.Minute, time.Hour, false)

		// Before the logout: a token in use, a code not yet redeemed, and a
		// code whose session binding is gone (as a code from the JSON consent
		// endpoint has none).
		oldToken := accessToken(t, authorize(t, before))
		pendingCode := authorize(t, before)
		unboundCode := authorize(t, before)
		svc.redis.Client.Del(ctx, "authcode_session:"+unboundCode)

		// Start the logout at the top of a second, so what follows lands in it.
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 5*time.Millisecond)))
		hint := mintToken(t, jwt.MapClaims{"sub": userID, "aud": "c", "iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix()}, pk)
		if w := serve(r, http.MethodGet, "/oauth/logout?id_token_hint="+url.QueryEscape(hint), "", ""); w.Code != http.StatusOK {
			t.Fatalf("logout: %d %s", w.Code, w.Body.String())
		}
		marker, err := svc.redis.Client.Get(ctx, revocation.UserTokensRevokedAtKey(userID)).Result()
		if err != nil {
			t.Fatalf("the logout wrote no revocation marker: %v", err)
		}

		// Straight back in: a new session, a new code, a new token.
		_, after := ssoSession(t, svc, db, ssoTestOrg, userID, 0, time.Hour, false)
		newToken := accessToken(t, authorize(t, after))

		claims, err := svc.parseVerifiedClaims(newToken, false)
		if err != nil {
			t.Fatal(err)
		}
		cutoff, _ := revocation.ParseMarker(marker)
		if !cutoff.Revokes(revocation.IssuedAt{Seconds: int64(claims["iat"].(float64))}) {
			return false // crossed into the next second; nothing was tested
		}
		if _, ok := claims[revocation.GrantedAtClaim]; !ok {
			t.Fatalf("an access token from the authorization-code grant carries no %s", revocation.GrantedAtClaim)
		}

		if !introspectActive(t, r, newToken) {
			t.Error("a sign-in completed after the logout, in the same second, was refused as revoked")
		}
		if introspectActive(t, r, oldToken) {
			t.Error("a token issued before the logout survived it")
		}
		if status, body := exchange(t, pendingCode); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("a code issued under the session the logout ended was redeemed: %d %v", status, body)
		}
		// No session binding to refuse it by: the token is minted, and must
		// still date from when its code was issued -- before the logout.
		if introspectActive(t, r, accessToken(t, unboundCode)) {
			t.Error("a code issued before the logout, redeemed after it, bought a token the logout does not revoke")
		}
		return true
	}

	for i := 0; i < 3; i++ {
		if attempt(t) || t.Failed() {
			return
		}
		t.Log("the sign-in after the logout crossed a second boundary; trying again")
	}
	t.Fatal("could not fit a logout and a sign-in into one second in three attempts")
}
