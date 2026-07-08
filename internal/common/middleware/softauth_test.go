package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// softAuthProbe runs SoftAuth (with an unreachable JWKS URL) behind the given
// Authorization header and reports whether the downstream handler saw an
// attached identity (user_id) and the response status.
func softAuthProbe(t *testing.T, authHeader string) (identityAttached bool, status int) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/s", SoftAuth("http://127.0.0.1:0/jwks"), func(c *gin.Context) {
		_, ok := c.Get("user_id")
		identityAttached = ok
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/s", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return identityAttached, w.Code
}

// TestSoftAuth_NeverAttachesIdentityForUnverifiableToken is the anti-bypass
// guarantee: SoftAuth must let the request through (soft) but must NOT attach an
// identity when the token is missing, malformed, alg=none, or otherwise
// unverifiable. Attaching identity here would be an authentication bypass.
func TestSoftAuth_NeverAttachesIdentityForUnverifiableToken(t *testing.T) {
	// alg=none token with a sub — the classic bypass attempt.
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
			attached, status := softAuthProbe(t, tc.header)
			if attached {
				t.Errorf("%s: SoftAuth attached an identity for an unverifiable token (auth bypass)", tc.name)
			}
			if status != http.StatusOK {
				t.Errorf("%s: SoftAuth must not block (got status %d, want 200)", tc.name, status)
			}
		})
	}
}
