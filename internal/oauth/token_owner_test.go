package oauth

// Measured before the fix, with two registered clients in ONE tenant and a
// refresh token issued to the second:
//
//	introspect by the FIRST client  -> {"active":true,"client_id":"other-app",
//	                                    "sub":"<the end user>","scope":"openid offline_access"}
//	revoke     by the FIRST client  -> other-app's token revoked
//
// One application could learn who was using another, and could sign that
// application's users out. RFC 7009 §2.1 requires the revocation check in as
// many words; RFC 7662 §2.2 gives introspection the answer to use instead.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const tokenOwnerFamily = "55555555-0000-0000-0000-000000000001"

// call drives one of the two endpoints THROUGH the client-auth middleware, so
// the authenticated identity reaches the handler the way it does in production.
// Driving the handler alone would prove nothing about the wiring — the same
// mistake that let a hard-coded scope survive mutation earlier in this package.
func (f *refreshGrantFixture) callAsClient(t *testing.T, path string, h gin.HandlerFunc, form url.Values, clientID, secret string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	c.Request = req.WithContext(f.ctx)

	// The real chain: authenticate, then handle.
	f.svc.requireTokenEndpointClientAuth()(c)
	if !c.IsAborted() {
		h(c)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

func (f *refreshGrantFixture) accessTokenFor(t *testing.T, clientID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":       grantUser,
		"aud":       clientID,
		"client_id": clientID,
		"scope":     "openid",
		"iss":       "https://refresh-grant.test",
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// A refresh token belonging to another client introspects as if it did not
// exist, and still introspects normally for its own client.
func TestIntrospectionOnlyAnswersForTheCallersOwnRefreshToken(t *testing.T) {
	f := newRefreshGrantFixture(t)
	f.mintRefresh(t, "owned-by-other", "other-app", grantUser, "openid offline_access", tokenOwnerFamily, "", time.Now().Add(time.Hour))

	code, body := f.callAsClient(t, "/oauth/introspect", f.svc.handleIntrospect,
		url.Values{"token": {"owned-by-other"}}, "app", "s3cret")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if active, _ := body["active"].(bool); active {
		t.Fatalf("a client introspected another client's refresh token: %v", body)
	}
	for _, leaked := range []string{"sub", "client_id", "scope"} {
		if v, ok := body[leaked]; ok {
			t.Fatalf("the refusal leaked %q = %v", leaked, v)
		}
	}

	// Its own client still gets the answer, so this is a gate and not a
	// wholesale disabling of the endpoint.
	_, own := f.callAsClient(t, "/oauth/introspect", f.svc.handleIntrospect,
		url.Values{"token": {"owned-by-other"}}, "other-app", "other-secret")
	if active, _ := own["active"].(bool); !active {
		t.Fatalf("the owning client was refused its own token: %v", own)
	}
	if own["sub"] != grantUser {
		t.Fatalf("the owning client did not get sub: %v", own)
	}
}

// The same for an access token, which names its client in a claim.
func TestIntrospectionOnlyAnswersForTheCallersOwnAccessToken(t *testing.T) {
	f := newRefreshGrantFixture(t)
	victim := f.accessTokenFor(t, "other-app")

	_, body := f.callAsClient(t, "/oauth/introspect", f.svc.handleIntrospect,
		url.Values{"token": {victim}}, "app", "s3cret")
	if active, _ := body["active"].(bool); active {
		t.Fatalf("a client introspected another client's access token: %v", body)
	}

	_, own := f.callAsClient(t, "/oauth/introspect", f.svc.handleIntrospect,
		url.Values{"token": {victim}}, "other-app", "other-secret")
	if active, _ := own["active"].(bool); !active {
		t.Fatalf("the owning client was refused its own access token: %v", own)
	}
}

// RFC 7009 §2.1: a client cannot revoke a token that was not issued to it.
func TestRevocationRefusesAnotherClientsRefreshToken(t *testing.T) {
	f := newRefreshGrantFixture(t)
	f.mintRefresh(t, "not-yours", "other-app", grantUser, "openid offline_access", tokenOwnerFamily, "", time.Now().Add(time.Hour))

	code, _ := f.callAsClient(t, "/oauth/revoke", f.svc.handleRevoke,
		url.Values{"token": {"not-yours"}, "token_type_hint": {"refresh_token"}}, "app", "s3cret")
	if code != http.StatusOK {
		t.Fatalf("a refusal must still answer 200, got %d", code)
	}
	if _, revoked := f.tokenState(t, "not-yours"); revoked {
		t.Fatal("one client revoked another client's refresh token")
	}

	// And the owner can still revoke it.
	if _, _ = f.callAsClient(t, "/oauth/revoke", f.svc.handleRevoke,
		url.Values{"token": {"not-yours"}, "token_type_hint": {"refresh_token"}}, "other-app", "other-secret"); true {
	}
	if _, revoked := f.tokenState(t, "not-yours"); !revoked {
		t.Fatal("the owning client could not revoke its own refresh token")
	}
}

// The same for an access token: the blacklist entry is not written for a token
// the caller does not own, so the victim's token keeps working.
func TestRevocationRefusesAnotherClientsAccessToken(t *testing.T) {
	f := newRefreshGrantFixture(t)
	victim := f.accessTokenFor(t, "other-app")

	f.callAsClient(t, "/oauth/revoke", f.svc.handleRevoke,
		url.Values{"token": {victim}}, "app", "s3cret")

	// Ask the owner: still active means the foreign revocation did nothing.
	_, own := f.callAsClient(t, "/oauth/introspect", f.svc.handleIntrospect,
		url.Values{"token": {victim}}, "other-app", "other-secret")
	if active, _ := own["active"].(bool); !active {
		t.Fatal("one client revoked another client's access token")
	}

	// The owner's own revocation does work.
	f.callAsClient(t, "/oauth/revoke", f.svc.handleRevoke,
		url.Values{"token": {victim}}, "other-app", "other-secret")
	_, after := f.callAsClient(t, "/oauth/introspect", f.svc.handleIntrospect,
		url.Values{"token": {victim}}, "other-app", "other-secret")
	if active, _ := after["active"].(bool); active {
		t.Fatal("the owning client could not revoke its own access token")
	}
}

// A request that never passed the client-auth middleware owns nothing. The two
// endpoints are registered behind it, so this cannot happen in the router; the
// helper still has to fail closed rather than treating "no caller" as "any
// caller", which is the shape the whole finding had.
func TestAnUnauthenticatedRequestOwnsNothing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if authenticatedClientID(c) != "" {
		t.Fatal("a context with no authenticated client must name nobody")
	}
	if callerOwns(c, "any-client") {
		t.Fatal("a request with no authenticated client must own nothing")
	}
}
