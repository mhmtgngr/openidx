package access

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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
