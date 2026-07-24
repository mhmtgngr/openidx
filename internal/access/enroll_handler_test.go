package access

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
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
