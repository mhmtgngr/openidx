package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	dto "github.com/prometheus/client_model/go"

	"github.com/openidx/openidx/internal/common/jwksverify"
)

// The key cache and the serve-stale belt are tested where they live, in
// internal/common/jwksverify. This drill stays here because what it proves is
// about THIS package: that the real Auth() gin middleware -- the thing every
// service actually mounts -- inherits the belt rather than short-circuiting it.
// The scaffolding below is deliberately a local copy: it touches nothing
// unexported, and sharing it would mean a test-support package that both
// halves import just to hand each other an httptest server.

// flippableJWKSServer serves a JWKS document and can be flipped to "down" to
// simulate the issuer (and the database behind it) being unreachable.
type flippableJWKSServer struct {
	srv  *httptest.Server
	down atomic.Bool
}

func newFlippableJWKSServer(t *testing.T, kid string, pub *rsa.PublicKey) *flippableJWKSServer {
	t.Helper()
	jt := &flippableJWKSServer{}
	jwks := JWKS{Keys: []JWKSKey{{
		Kty: "RSA", Use: "sig", Kid: kid, Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	jt.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if jt.down.Load() {
			http.Error(w, "issuer down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jt.srv.Close)
	return jt
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

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
	jwksverify.ResetCache()
	t.Cleanup(jwksverify.SetWindows(time.Hour, time.Hour))

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

	staleBefore := counterValue(t, jwksverify.ServeStaleTotal)

	// 2) Issuer down + fresh TTL elapsed → refresh will fail on next lookup.
	jt.down.Store(true)
	jwksverify.ExpireCache()

	// 3) The still-valid token MUST keep working (served from stale cache).
	w := authGet()
	if w.Code != http.StatusOK {
		t.Fatalf("during issuer outage: got %d, want 200 — verify path did not survive (body=%s)", w.Code, w.Body.String())
	}

	// 4) The serve-stale metric must have incremented so the outage is visible.
	if got := counterValue(t, jwksverify.ServeStaleTotal); got <= staleBefore {
		t.Fatalf("expected jwks_serve_stale_total to increase (before=%v, after=%v)", staleBefore, got)
	}
}
