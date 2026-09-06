package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// The token endpoint and the revocation endpoint had no test that named them.
// Both are reachable unauthenticated, and both decide what a bearer token is
// worth: handleToken picks the grant, handleRevoke decides whether a token
// stops working. What follows exercises the parts that need no database —
// the dispatch table and the signature check — because those are the parts
// that decide whether a request gets as far as the database at all.

func postForm(t *testing.T, h gin.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	w, _ := postFormAllowingPanic(t, h, form)
	return w
}

// postFormAllowingPanic drives a handler and reports whether it panicked.
//
// The test service is built without a database on purpose (test_helper_test.go
// gives it RSA keys and miniredis and nothing else), so a grant handler that
// reaches for a client row panics on the nil pool. For the dispatch test that
// is not a problem to work around, it is the OBSERVATION: reaching the
// database means the switch routed the request to a grant handler rather than
// answering unsupported_grant_type. Every other test in this file uses
// postForm, where a panic fails the test as usual.
func postFormAllowingPanic(t *testing.T, h gin.HandlerFunc, form url.Values) (w *httptest.ResponseRecorder, panicked bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w = httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		h(c)
	}()
	return w, panicked
}

// TestHandleTokenDispatchesEveryRegisteredGrant pins the dispatch table.
//
// The assertion is deliberately narrow: not "the grant succeeds" (that needs a
// database and a client), but "the request was RECOGNISED". A grant type that
// falls through to the default arm is refused as unsupported_grant_type, which
// is indistinguishable from a client asking for something the product never
// implemented — and that is exactly how a grant gets dropped in a refactor
// without anything going red.
func TestHandleTokenDispatchesEveryRegisteredGrant(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()

	// Every grant the metadata document advertises. Keep this in step with
	// handleToken's switch; a new grant with no entry here is untested.
	grants := []string{
		"authorization_code",
		"refresh_token",
		"client_credentials",
		grantTypeTokenExchange,
		grantTypeDeviceCode,
	}
	for _, grant := range grants {
		t.Run(grant, func(t *testing.T) {
			w, panicked := postFormAllowingPanic(t, ctx.Service.handleToken, url.Values{"grant_type": {grant}})
			if strings.Contains(w.Body.String(), "unsupported_grant_type") {
				t.Fatalf("grant %q reached the default arm: %s", grant, w.Body.String())
			}
			if !panicked && w.Code == 0 {
				t.Fatalf("grant %q neither answered nor reached a handler", grant)
			}
		})
	}
}

func TestHandleTokenRefusesAnUnknownGrant(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()

	for _, grant := range []string{"", "password", "implicit", "AUTHORIZATION_CODE", "authorization_code "} {
		t.Run("grant="+grant, func(t *testing.T) {
			w := postForm(t, ctx.Service.handleToken, url.Values{"grant_type": {grant}})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if !strings.Contains(w.Body.String(), "unsupported_grant_type") {
				t.Fatalf("body = %s, want unsupported_grant_type", w.Body.String())
			}
		})
	}
}

func TestHandleTokenAnswersPreflightWithoutDispatching(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodOptions, "/oauth/token", nil)
	ctx.Service.handleToken(c)

	if w.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d, want 204", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("OPTIONS body = %q, want empty", w.Body.String())
	}
}

// signedAccessToken mints a token with the service's own key, the way
// generateTokensForUser does.
func signedAccessToken(t *testing.T, ctx *TestOIDCContext, exp time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test-user-123",
		"iss": ctx.Service.issuer,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
	})
	signed, err := tok.SignedString(ctx.Service.privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func blacklisted(t *testing.T, ctx *TestOIDCContext, token string) bool {
	t.Helper()
	n, err := ctx.RedisClient.Exists(context.Background(), accessTokenBlacklistKey(token)).Result()
	if err != nil {
		t.Fatalf("redis exists: %v", err)
	}
	return n > 0
}

// TestHandleRevokeBlacklistsOnlyTokensThisServiceIssued is the security-shaped
// half of RFC 7009. The endpoint is unauthenticated by design and always
// answers 200 (a 4xx would let a caller probe which tokens exist), so the only
// thing standing between it and an attacker writing arbitrary Redis keys is
// the signature check before the blacklist write.
func TestHandleRevokeBlacklistsOnlyTokensThisServiceIssued(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()

	valid := signedAccessToken(t, ctx, time.Now().Add(time.Hour))
	w := postForm(t, ctx.Service.handleRevoke, url.Values{"token": {valid}})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !blacklisted(t, ctx, valid) {
		t.Fatal("a token this service signed was not blacklisted")
	}

	// A token signed by somebody else's key. Same shape, same claims, valid
	// JWT — and not ours.
	other := NewTestOIDCContext(t)
	defer other.Cleanup()
	forged := signedAccessToken(t, other, time.Now().Add(time.Hour))

	w = postForm(t, ctx.Service.handleRevoke, url.Values{"token": {forged}})
	if w.Code != http.StatusOK {
		t.Fatalf("forged token status = %d, want 200 (RFC 7009 never confirms a token)", w.Code)
	}
	if blacklisted(t, ctx, forged) {
		t.Fatal("a token signed by another key was written to the blacklist")
	}
}

func TestHandleRevokeIgnoresGarbageAndExpiredTokens(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()

	for name, token := range map[string]string{
		"not a jwt":       "hello",
		"empty":           "",
		"three dots":      "a.b.c",
		"alg none forged": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.",
	} {
		t.Run(name, func(t *testing.T) {
			w := postForm(t, ctx.Service.handleRevoke, url.Values{"token": {token}})
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if blacklisted(t, ctx, token) {
				t.Fatalf("%q was written to the blacklist", token)
			}
		})
	}

	// Already expired: correctly signed, but there is nothing left to revoke,
	// and a blacklist entry with a negative TTL is a Redis error, not a
	// control.
	expired := signedAccessToken(t, ctx, time.Now().Add(-time.Minute))
	w := postForm(t, ctx.Service.handleRevoke, url.Values{"token": {expired}})
	if w.Code != http.StatusOK {
		t.Fatalf("expired status = %d, want 200", w.Code)
	}
	if blacklisted(t, ctx, expired) {
		t.Fatal("an already-expired token was blacklisted")
	}
}

// The hint is a hint. RFC 7009 §2.1: a server MAY use it as an optimisation
// but MUST NOT depend on it, so `token_type_hint=refresh_token` on what is
// actually an access token still has to answer 200 — and the one thing it
// changes is that the access-token branch is skipped.
func TestHandleRevokeTreatsTheTypeHintAsAHint(t *testing.T) {
	ctx := NewTestOIDCContext(t)
	defer ctx.Cleanup()

	token := signedAccessToken(t, ctx, time.Now().Add(time.Hour))
	w := postForm(t, ctx.Service.handleRevoke, url.Values{
		"token":           {token},
		"token_type_hint": {"refresh_token"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if blacklisted(t, ctx, token) {
		t.Fatal("token_type_hint=refresh_token still took the access-token branch")
	}

	// Any other hint value, including a bogus one, takes the access-token
	// branch — that is the fail-safe direction.
	w = postForm(t, ctx.Service.handleRevoke, url.Values{
		"token":           {token},
		"token_type_hint": {"nonsense"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !blacklisted(t, ctx, token) {
		t.Fatal("an unrecognised hint skipped the access-token branch")
	}
}
