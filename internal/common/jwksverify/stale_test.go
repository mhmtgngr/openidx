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

	"github.com/golang-jwt/jwt/v5"
)

// jwksTestServer serves a JWKS document but can be flipped to "down" to simulate
// the OAuth/JWKS endpoint (and the shared DB behind it) being unavailable.
type jwksTestServer struct {
	srv  *httptest.Server
	down atomic.Bool
	hits atomic.Int64
}

func newFlippableJWKSServer(t *testing.T, kid string, pub *rsa.PublicKey) *jwksTestServer {
	t.Helper()
	jt := &jwksTestServer{}
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	jwks := JWKS{Keys: []JWKSKey{{
		Kty: "RSA", Use: "sig", Kid: kid, Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(eBytes),
	}}}
	jt.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jt.hits.Add(1)
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

// withJWKSWindows temporarily overrides the freshness/stale windows for a test
// and restores them afterward.
func withJWKSWindows(t *testing.T, ttl, maxStale time.Duration) {
	t.Helper()
	oldTTL, oldStale := jwksTTL, jwksMaxStale
	jwksTTL, jwksMaxStale = ttl, maxStale
	t.Cleanup(func() { jwksTTL, jwksMaxStale = oldTTL, oldStale })
}

// expireCacheNow forces the fresh window to be already past so the next lookup
// takes the refresh path, without waiting real time. lastRefreshOK/keys are left
// intact so serve-stale can engage.
func expireCacheNow() {
	globalJWKSCache.mu.Lock()
	globalJWKSCache.expiresAt = time.Now().Add(-time.Second)
	globalJWKSCache.mu.Unlock()
}

// TestServeStaleJWKSOnRefreshFailure is the Tier 0 availability guarantee: once a
// key set has been fetched, a valid token keeps verifying even when the JWKS/DB
// endpoint is down, until the max-stale window is exceeded.
func TestServeStaleJWKSOnRefreshFailure(t *testing.T) {
	resetJWKSCache()
	withJWKSWindows(t, time.Hour, time.Hour) // long max-stale for the happy stale case

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "stale-kid-1"
	jt := newFlippableJWKSServer(t, kid, &key.PublicKey)

	tok := signRS256(t, key, kid, jwt.MapClaims{
		"sub": "user-1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	// 1) Prime the cache while the issuer is up.
	if _, err := VerifyBearerToken(jt.srv.URL, tok); err != nil {
		t.Fatalf("prime verify failed: %v", err)
	}

	// 2) Issuer goes down AND the fresh TTL elapses → refresh will fail.
	jt.down.Store(true)
	expireCacheNow()

	// 3) The already-issued token MUST still verify (served from stale cache).
	claims, err := VerifyBearerToken(jt.srv.URL, tok)
	if err != nil {
		t.Fatalf("expected stale-cache verify to succeed during issuer outage, got: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("sub = %v, want user-1", claims["sub"])
	}
}

// TestStaleJWKSExpiresAfterMaxStale proves the belt is bounded: past the
// max-stale window we stop trusting the cached keys and fail closed.
func TestStaleJWKSExpiresAfterMaxStale(t *testing.T) {
	resetJWKSCache()
	withJWKSWindows(t, time.Hour, 0) // zero max-stale: any staleness is too much

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "stale-kid-2"
	jt := newFlippableJWKSServer(t, kid, &key.PublicKey)

	tok := signRS256(t, key, kid, jwt.MapClaims{
		"sub": "user-2",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	if _, err := VerifyBearerToken(jt.srv.URL, tok); err != nil {
		t.Fatalf("prime verify failed: %v", err)
	}

	jt.down.Store(true)
	expireCacheNow()

	if _, err := VerifyBearerToken(jt.srv.URL, tok); err == nil {
		t.Fatal("expected verification to fail past the max-stale window, but it succeeded")
	}
}

// TestNoStaleServeWithoutSuccessfulFetch proves we never "serve stale" from a
// cache that was never successfully populated (nothing to trust).
func TestNoStaleServeWithoutSuccessfulFetch(t *testing.T) {
	resetJWKSCache()
	withJWKSWindows(t, time.Hour, time.Hour)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "stale-kid-3"
	jt := newFlippableJWKSServer(t, kid, &key.PublicKey)
	jt.down.Store(true) // never serves a valid document

	tok := signRS256(t, key, kid, jwt.MapClaims{
		"sub": "user-3",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	if _, err := VerifyBearerToken(jt.srv.URL, tok); err == nil {
		t.Fatal("expected failure when the cache was never primed, got success")
	}
}
