package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// authProbe runs the hard Auth gate (unreachable JWKS) behind the given
// Authorization header and reports whether the protected handler was reached
// and the response status.
func authProbe(t *testing.T, authHeader string) (handlerReached bool, status int) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/protected", Auth("http://127.0.0.1:0/jwks"), func(c *gin.Context) {
		handlerReached = true
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return handlerReached, w.Code
}

// TestAuth_RejectsUnverifiableTokens is the primary authentication-enforcement
// guarantee: unlike SoftAuth, the hard Auth gate must ABORT with 401 (never reach
// the protected handler) for a missing, non-bearer, malformed, or alg=none token.
func TestAuth_RejectsUnverifiableTokens(t *testing.T) {
	noneTok, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "attacker"}).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("build none-alg token: %v", err)
	}

	cases := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"non-bearer scheme", "Basic dXNlcjpwYXNz"},
		{"bearer but malformed token", "Bearer not.a.jwt"},
		{"alg=none bypass attempt", "Bearer " + noneTok},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached, status := authProbe(t, tc.header)
			if reached {
				t.Errorf("%s: protected handler was reached despite an unverifiable token (auth bypass)", tc.name)
			}
			if status != http.StatusUnauthorized {
				t.Errorf("%s: want 401, got %d", tc.name, status)
			}
		})
	}
}
