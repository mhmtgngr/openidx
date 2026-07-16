package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	dto "github.com/prometheus/client_model/go"
)

// counterValue reads the current value of a plain prometheus counter.
func counterValue(t *testing.T, c interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

// TestAuthMiddlewareSurvivesIssuerOutage is the end-to-end Tier 0 drill through
// the real Auth() gin middleware: once a token has verified, an outage of the
// JWKS issuer (and the shared DB behind it) must NOT lock out an already-issued,
// still-valid token. It also asserts the serve-stale metric fires so operators
// can see the belt engage.
func TestAuthMiddlewareSurvivesIssuerOutage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	resetJWKSCache()
	withJWKSWindows(t, time.Hour, time.Hour)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "drill-kid-1"
	jt := newFlippableJWKSServer(t, kid, &key.PublicKey)

	router := gin.New()
	router.Use(Auth(jt.srv.URL))
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"user": c.GetString("user_id")})
	})

	tok := signRS256(t, key, kid, jwt.MapClaims{
		"sub": "drill-user",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	authGet := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// 1) Prime: issuer up, token verifies (200).
	if w := authGet(); w.Code != http.StatusOK {
		t.Fatalf("prime request: got %d, want 200 (body=%s)", w.Code, w.Body.String())
	}

	staleBefore := counterValue(t, jwksServeStaleTotal)

	// 2) Issuer down + fresh TTL elapsed → refresh will fail on next lookup.
	jt.down.Store(true)
	expireCacheNow()

	// 3) The still-valid token MUST keep working (served from stale cache).
	w := authGet()
	if w.Code != http.StatusOK {
		t.Fatalf("during issuer outage: got %d, want 200 — verify path did not survive (body=%s)", w.Code, w.Body.String())
	}

	// 4) The serve-stale metric must have incremented so the outage is visible.
	if got := counterValue(t, jwksServeStaleTotal); got <= staleBefore {
		t.Fatalf("expected jwks_serve_stale_total to increase (before=%v, after=%v)", staleBefore, got)
	}
}
