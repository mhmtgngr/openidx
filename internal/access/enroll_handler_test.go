package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/revocation"
)

// The enroll door must refuse a caller that presents no session, token, or
// passkey — this is the Tier-0 gate's fail-closed default.
func TestEnrollRejectsWithoutEntitlement(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/access/enroll", strings.NewReader(`{}`))
	c.Request.Header.Set("Content-Type", "application/json")

	svc := &Service{logger: zap.NewNop()}
	svc.handleEnroll(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("no entitlement → %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "entitlement required") {
		t.Errorf("body = %q, want 'entitlement required'", w.Body.String())
	}
}

// A passkey-only body is refused with a clear message (deferred, not faked).
func TestEnrollPasskeyDeferred(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/access/enroll",
		strings.NewReader(`{"passkey":{"id":"abc"}}`))
	c.Request.Header.Set("Content-Type", "application/json")

	svc := &Service{logger: zap.NewNop()}
	svc.handleEnroll(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("passkey-only → %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "passkey enrollment not supported") {
		t.Errorf("body = %q, want the passkey-deferred message", w.Body.String())
	}
}

// A forged/unsigned bearer must NOT be accepted as a session (JWKS unconfigured
// on the bare Service → VerifyBearerToken fails closed), so the caller falls
// through to the no-entitlement 401 rather than being trusted.
func TestEnrollForgedBearerFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/access/enroll", strings.NewReader(`{}`))
	c.Request.Header.Set("Content-Type", "application/json")
	// An unsigned/forged JWT-looking token.
	c.Request.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciJ9.")

	svc := &Service{logger: zap.NewNop()} // oauthJWKSURL empty → verification fails closed
	svc.handleEnroll(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("forged bearer → %d, want 401 (must not be trusted)", w.Code)
	}
}

// enrollmentJWTExpired is the guard that fixes the mobile "JWT expired 31 days
// ago" bug: the mint path must treat a stale/absent/garbage OTT as expired so it
// re-issues a fresh one instead of handing back the cached copy forever.
func TestEnrollmentJWTExpired(t *testing.T) {
	sign := func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		s, _ := tok.SignedString([]byte("test-key-unimportant-parseunverified"))
		return s
	}

	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{"future exp is fresh", sign(jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}), false},
		{"past exp is expired", sign(jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()}), true},
		{"about-to-lapse within skew is expired", sign(jwt.MapClaims{"exp": time.Now().Add(30 * time.Second).Unix()}), true},
		{"missing exp is expired", sign(jwt.MapClaims{"sub": "x"}), true},
		{"garbage is expired", "not-a-jwt", true},
		{"empty is expired", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := enrollmentJWTExpired(c.token); got != c.want {
				t.Errorf("enrollmentJWTExpired(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// enrolBearer signs an access token for bearerSubject in org (none when org is
// empty) with the given scope, minted at iat. It uses the key bearerJWKS serves.
func enrolBearer(t *testing.T, org, scope string, iat time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": bearerSubject, "client_id": "openidx-desktop", "roles": []interface{}{"user"},
		middleware.APIAccessClaim: true,
		"iat":                     iat.Unix(),
		"exp":                     iat.Add(time.Hour).Unix(),
	}
	if scope != "" {
		claims["scope"] = scope
	}
	if org != "" {
		claims[middleware.OrgIDClaim] = org
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = bearerKid
	tok.Header["typ"] = middleware.AccessTokenType
	signed, err := tok.SignedString(bearerKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// doorCall drives handleEnroll with a bearer, in org A.
func doorCall(t *testing.T, s *Service, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = inOrg(httptest.NewRequest(http.MethodPost, "/api/v1/access/enroll", strings.NewReader(`{}`)), bearerOrgA)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("Authorization", "Bearer "+bearer)
	s.handleEnroll(c)
	return w
}

// A verified bearer buys an overlay identity only when it was issued for
// device enrolment. The door used to take any access token of the
// organization -- a console session token, which lives in the browser's
// storage, included -- and mint a week-long enrolment JWT for it. A token
// without the agent.enroll scope is refused with 403 insufficient_scope and
// no credential; one with it is a session, as before.
func TestEnrollRequiresTheEnrolScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{logger: zap.NewNop(), oauthJWKSURL: bearerJWKS(t)}

	w := doorCall(t, s, enrolBearer(t, bearerOrgA, "openid profile email", time.Now()))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a console token answered %d, want 403: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["code"] != "insufficient_scope" {
		t.Errorf("refusal code = %q, want insufficient_scope", body["code"])
	}
	if _, leaked := body["ziti_enrollment_jwt"]; leaked {
		t.Error("the refusal carries an enrolment JWT")
	}

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = inOrg(httptest.NewRequest(http.MethodPost, "/api/v1/access/enroll", strings.NewReader(`{}`)), bearerOrgA)
	c.Request.Header.Set("Authorization", "Bearer "+enrolBearer(t, bearerOrgA, "openid "+enrollScope, time.Now()))
	sub, method, err := s.resolveEnrollSubject(c, &darkEnrollRequest{})
	if err != nil || sub != bearerSubject || method != "session" {
		t.Errorf("a token with the scope: subject %q, method %q, error %v; want %q by session", sub, method, err, bearerSubject)
	}
}

// A bearer the kill switch, a device revoke or a leaver's disable has cut
// buys nothing at the door: the user's revocation cutoff is read as
// /oauth/userinfo reads it. A token minted after the cutoff still enrols, and
// a revocation store that cannot answer refuses rather than guessing.
func TestEnrollRefusesARevokedBearer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	s := &Service{
		logger: zap.NewNop(), oauthJWKSURL: bearerJWKS(t),
		redis: &database.RedisClient{Client: rc, Revocation: rc},
	}
	ctx := context.Background()
	now := time.Now()

	// Everything the subject held up to thirty seconds ago is revoked.
	if err := rc.Set(ctx, revocation.UserTokensRevokedAtKey(bearerSubject),
		revocation.MarkerValue(now.Add(-30*time.Second)), 0).Err(); err != nil {
		t.Fatal(err)
	}
	w := doorCall(t, s, enrolBearer(t, bearerOrgA, enrollScope, now.Add(-60*time.Second)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked token answered %d, want 401: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["code"] != "token_revoked" {
		t.Errorf("refusal code = %q, want token_revoked", body["code"])
	}

	fresh := enrolBearer(t, bearerOrgA, enrollScope, now)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = inOrg(httptest.NewRequest(http.MethodPost, "/api/v1/access/enroll", strings.NewReader(`{}`)), bearerOrgA)
	c.Request.Header.Set("Authorization", "Bearer "+fresh)
	if sub, method, err := s.resolveEnrollSubject(c, &darkEnrollRequest{}); err != nil || sub != bearerSubject || method != "session" {
		t.Errorf("a token minted after the cutoff: subject %q, method %q, error %v; want a session", sub, method, err)
	}

	// The per-token blacklist counts too.
	if err := rc.Set(ctx, revocation.AccessTokenBlacklistKey(fresh), "1", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if w := doorCall(t, s, fresh); w.Code != http.StatusUnauthorized {
		t.Errorf("a blacklisted token answered %d, want 401: %s", w.Code, w.Body.String())
	}

	mini.Close()
	w = doorCall(t, s, enrolBearer(t, bearerOrgA, enrollScope, now))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("with the revocation store down the door answered %d, want 503: %s", w.Code, w.Body.String())
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["code"] != "revocation_unavailable" {
		t.Errorf("refusal code = %q, want revocation_unavailable", body["code"])
	}
}

// Without a revocation store configured at all, the check is skipped (and
// logged), not failed: a build with no Redis is a deployment choice, not a
// store that cannot answer.
func TestEnrollWithoutARevocationStoreStillEnrolsAScopedBearer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{logger: zap.NewNop(), oauthJWKSURL: bearerJWKS(t)}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = inOrg(httptest.NewRequest(http.MethodPost, "/api/v1/access/enroll", strings.NewReader(`{}`)), bearerOrgA)
	c.Request.Header.Set("Authorization", "Bearer "+enrolBearer(t, bearerOrgA, enrollScope, time.Now()))
	if sub, method, err := s.resolveEnrollSubject(c, &darkEnrollRequest{}); err != nil || sub != bearerSubject || method != "session" {
		t.Errorf("subject %q, method %q, error %v; want a session", sub, method, err)
	}
}

func TestClaimsScopeAllows(t *testing.T) {
	cases := []struct {
		scope interface{}
		want  bool
	}{
		{"openid agent.enroll", true},
		{"agent.enroll", true},
		{"openid profile agent.enrollment", false},
		{"", false},
		{nil, false},
		{[]string{"agent.enroll"}, false},
	}
	for _, c := range cases {
		claims := map[string]interface{}{}
		if c.scope != nil {
			claims["scope"] = c.scope
		}
		if got := claimsScopeAllows(claims, enrollScope); got != c.want {
			t.Errorf("claimsScopeAllows(%v) = %v, want %v", c.scope, got, c.want)
		}
	}
}
