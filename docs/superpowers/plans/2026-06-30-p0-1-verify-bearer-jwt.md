# P0-1 — Verify bearer JWTs in the access proxy: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the unsigned-JWT auth bypass: the access proxy's bearer path must build a session only from a signature-and-expiry-verified token.

**Architecture:** Add one cached, exported verifier (`VerifyBearerToken`) to `internal/common/middleware`, mirroring the existing `Auth()` middleware's proven parse (RS256 pin → kid → cached JWKS key → required `exp`). Route `getSessionFromBearer` through it; on any verification error, return no session (fail-closed). The two channel-trusted post-exchange `parseTokenClaims` callers are left unchanged.

**Tech Stack:** Go, `github.com/golang-jwt/jwt/v5`, Gin, zap, `crypto/rsa`+`httptest` for tests.

---

## Task 1: `VerifyBearerToken` helper (TDD)

**Files:**
- Modify: `internal/common/middleware/middleware.go`
- Test: `internal/common/middleware/verify_bearer_test.go` (create)

The package already imports `github.com/golang-jwt/jwt/v5` (line 18), `crypto/rsa`, `encoding/base64`, `math/big`, `net/http`, `time`, `fmt`, `encoding/json`, and defines the cached `getSigningKey(jwksURL, kid)` (line 114), the `JWKS`/`JWK` decode types, and `parseRSAPublicKey`. Reuse all of it.

- [ ] **Step 1: Write the failing test**

Create `internal/common/middleware/verify_bearer_test.go`:

```go
package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newJWKSServer serves a JWKS containing pub under the given kid, and returns
// the server (caller closes) and its URL.
func newJWKSServer(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	jwks := JWKS{Keys: []JWKSKey{{
		Kty: "RSA", Use: "sig", Kid: kid, Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(eBytes),
	}}}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestVerifyBearerToken(t *testing.T) {
	resetJWKSCache() // see Step 3
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "test-kid-1"
	srv := newJWKSServer(t, kid, &key.PublicKey)
	defer srv.Close()
	jwksURL := srv.URL

	t.Run("valid token verifies and returns claims", func(t *testing.T) {
		resetJWKSCache()
		tok := signRS256(t, key, kid, jwt.MapClaims{
			"sub": "user-123", "email": "u@example.test",
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		})
		claims, err := VerifyBearerToken(jwksURL, tok)
		if err != nil {
			t.Fatalf("expected valid, got error: %v", err)
		}
		if claims["sub"] != "user-123" {
			t.Fatalf("sub = %v, want user-123", claims["sub"])
		}
	})

	t.Run("unsigned alg=none token is rejected", func(t *testing.T) {
		resetJWKSCache()
		// Build an alg=none token manually (jwt lib won't sign "none").
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"` + kid + `"}`))
		pl := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker","roles":["admin"],"exp":` +
			itoa(time.Now().Add(time.Hour).Unix()) + `}`))
		forged := hdr + "." + pl + "."
		if _, err := VerifyBearerToken(jwksURL, forged); err == nil {
			t.Fatal("alg=none token must be rejected")
		}
	})

	t.Run("token signed by a different key is rejected", func(t *testing.T) {
		resetJWKSCache()
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		tok := signRS256(t, other, kid, jwt.MapClaims{
			"sub": "user-123", "exp": float64(time.Now().Add(time.Hour).Unix()),
		})
		if _, err := VerifyBearerToken(jwksURL, tok); err == nil {
			t.Fatal("wrong-key signature must be rejected")
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		resetJWKSCache()
		tok := signRS256(t, key, kid, jwt.MapClaims{
			"sub": "user-123", "exp": float64(time.Now().Add(-time.Hour).Unix()),
		})
		if _, err := VerifyBearerToken(jwksURL, tok); err == nil {
			t.Fatal("expired token must be rejected")
		}
	})

	t.Run("token missing exp is rejected", func(t *testing.T) {
		resetJWKSCache()
		tok := signRS256(t, key, kid, jwt.MapClaims{"sub": "user-123"})
		if _, err := VerifyBearerToken(jwksURL, tok); err == nil {
			t.Fatal("token without exp must be rejected")
		}
	})

	t.Run("token missing kid is rejected", func(t *testing.T) {
		resetJWKSCache()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "user-123", "exp": float64(time.Now().Add(time.Hour).Unix()),
		})
		s, _ := tok.SignedString(key) // no kid header
		if _, err := VerifyBearerToken(jwksURL, s); err == nil {
			t.Fatal("token without kid must be rejected")
		}
	})
}

// itoa avoids importing strconv just for the forged-token literal.
func itoa(n int64) string { return jwtNumToString(n) }
```

(`jwtNumToString` / `resetJWKSCache` are added in Steps 2–3.)

- [ ] **Step 2: Run it to confirm it fails to compile / fails**

Run: `go test ./internal/common/middleware/ -run TestVerifyBearerToken -v`
Expected: FAIL — `undefined: VerifyBearerToken`, `undefined: resetJWKSCache`, `undefined: jwtNumToString`.

- [ ] **Step 3: Add the test helpers (cache reset + small int→string)**

Append to `internal/common/middleware/verify_bearer_test.go`:

```go
import "strconv"

// resetJWKSCache clears the package JWKS cache so each subtest fetches fresh
// keys from its own httptest server (the cache is process-global).
func resetJWKSCache() {
	globalJWKSCache.mu.Lock()
	globalJWKSCache.keys = make(map[string]*rsa.PublicKey)
	globalJWKSCache.expiresAt = time.Time{}
	globalJWKSCache.mu.Unlock()
}

func jwtNumToString(n int64) string { return strconv.FormatInt(n, 10) }
```

Merge the `strconv` import into the existing import block (don't add a second `import` clause). `globalJWKSCache` is the package var at `middleware.go:49`.

- [ ] **Step 4: Implement `VerifyBearerToken`**

Add to `internal/common/middleware/middleware.go` (e.g. directly after `getFirstSigningKey`, ~line 183):

```go
// VerifyBearerToken validates a bearer JWT against the OAuth JWKS and returns
// its claims. It enforces the same guarantees as Auth(): an RS256 algorithm pin
// (rejecting "none"/HS256 and alg-confusion), a kid→JWKS signing-key lookup via
// the shared 1-hour key cache, and a required, unexpired exp. It is for services
// that authenticate a bearer OUTSIDE the Auth() middleware (e.g. the access
// reverse proxy resolving a forwarded bearer). Any verification failure returns
// an error; callers MUST treat a non-nil error as "unauthenticated" and build no
// session from it.
func VerifyBearerToken(jwksURL, tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok || alg == "" {
			return nil, fmt.Errorf("token missing alg header")
		}
		if alg != "RS256" {
			return nil, fmt.Errorf("unexpected signing algorithm: %s (only RS256 is allowed)", alg)
		}
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("token method is not RSA despite alg header")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing kid header")
		}
		return getSigningKey(jwksURL, kid)
	})
	if err != nil {
		return nil, err
	}
	if token == nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("token missing exp")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("token expired")
	}
	return claims, nil
}
```

- [ ] **Step 5: Run the tests to confirm they pass**

Run: `go test ./internal/common/middleware/ -run TestVerifyBearerToken -v`
Expected: PASS (all six subtests).

- [ ] **Step 6: Commit**

```bash
git add internal/common/middleware/middleware.go internal/common/middleware/verify_bearer_test.go
git commit -m "feat(middleware): cached VerifyBearerToken (RS256 + JWKS + exp)"
```

## Task 2: Route the proxy bearer path through the verifier

**Files:**
- Modify: `internal/access/service.go` (import block; `getSessionFromBearer` ~line 2452)

`getSessionFromBearer` currently calls `s.parseTokenClaims(token)` (no verification). `s.oauthJWKSURL` is already a Service field (`service.go:116`, set at `:304`). `zap` and `strings`/`fmt` are already imported; the `internal/common/middleware` package is NOT yet imported by the access package (verified) — add it.

- [ ] **Step 1: Add the middleware import**

In `internal/access/service.go`, add to the import block:

```go
	"github.com/openidx/openidx/internal/common/middleware"
```

(Place it with the other `github.com/openidx/openidx/internal/...` imports. No import cycle: `common/middleware` imports only `internal/common/orgctx`.)

- [ ] **Step 2: Rewrite `getSessionFromBearer` to verify**

Replace the body of `getSessionFromBearer` (`service.go:2452-2480`):

```go
func (s *Service) getSessionFromBearer(c *gin.Context) *ProxySession {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// SECURITY (P0-1): verify the bearer's signature + expiry against the OAuth
	// JWKS before trusting any claim. A forged/unsigned token must yield no
	// session — the request then falls through to unauthenticated handling,
	// exactly as a missing cookie does. Never build a ProxySession from
	// unverified claims. If JWKS is unconfigured, verification fails → no
	// session (fail-closed: bearer auth is unavailable, never forgeable).
	claims, err := middleware.VerifyBearerToken(s.oauthJWKSURL, token)
	if err != nil {
		s.logger.Debug("bearer token rejected", zap.Error(err))
		return nil
	}

	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	var roles []string
	if r, ok := claims["roles"].([]interface{}); ok {
		for _, role := range r {
			roles = append(roles, fmt.Sprint(role))
		}
	}

	return &ProxySession{
		UserID: userID,
		Email:  email,
		Name:   name,
		Roles:  roles,
	}
}
```

Do NOT remove `parseTokenClaims` — it still serves the two channel-trusted callers (`service.go:1426`, `multi_idp.go:275`).

- [ ] **Step 3: Build + vet**

Run: `go build ./internal/access/ && go vet ./internal/access/`
Expected: no output (success). If `parseTokenClaims` is now reported unused, that means a caller was missed — re-check; it must remain used by the two callback paths.

- [ ] **Step 4: Run access unit tests**

Run: `go test ./internal/access/`
Expected: ok.

- [ ] **Step 5: Commit**

```bash
git add internal/access/service.go
git commit -m "fix(access): verify bearer JWT signature+expiry before building a session (P0-1)"
```

## Task 3: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build, vet, format, orgscope**

```bash
go build ./...
go vet ./...
gofmt -l internal/common/middleware/middleware.go internal/common/middleware/verify_bearer_test.go internal/access/service.go
go run ./tools/orgscope -fail ./internal
```
Expected: clean (empty gofmt output; orgscope "0 possible unscoped queries").

- [ ] **Step 2: Run the touched-package tests**

```bash
go test ./internal/common/middleware/... ./internal/access/...
```
Expected: ok for both.

## Self-review notes

- **Spec coverage:** Component 1 → Task 1; Component 2 → Task 2; test matrix → Task 1 subtests; build/vet/gofmt/orgscope → Task 3. All covered.
- **Type consistency:** `VerifyBearerToken(string, string) (map[string]interface{}, error)` used identically in the test and the caller; `getSigningKey(jwksURL, kid)` and `globalJWKSCache` match `middleware.go:114/49`; `JWKS`/`JWK` field names (`Kty`,`Use`,`Kid`,`Alg`,`N`,`E`) must match the package's struct — verify against the `JWKS`/`JWK` definitions when writing the test and adjust the literal if a field name differs.
- **No placeholders.** Revocation / `iss` / `aud` and the two post-exchange callers are explicitly out of scope per the spec.
