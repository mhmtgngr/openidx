# P0-1 — Verify bearer JWTs in the access proxy (close the unsigned-JWT auth bypass)

## Context

The access reverse proxy accepts `Authorization: Bearer <jwt>` as an
authentication method. `getSessionFromBearer` (`internal/access/service.go:2452`)
calls `parseTokenClaims` (`:2587`), which **only base64-decodes the JWT payload**
— no signature verification, no `exp` check, no `alg` pin — and builds a
fully-authorized `ProxySession` from whatever `sub`/`email`/`name`/`roles` the
token claims. That session's roles feed the route role gate (`hasAnyRole`) and
the `X-Forwarded-User` / `X-Forwarded-Roles` headers sent to the upstream.

It is reachable on the proxy data path: `buildAccessContext`
(`context_evaluator.go:440`) and `service.go:1653` both fall back to
`getSessionFromBearer` when there is no proxy-session cookie.

**Impact (verified by code read):** an attacker forges an unsigned JWT
(`{"alg":"none"}` or any self-signed token) with arbitrary `sub` and
`roles:["admin",…]`, sends it as a bearer, and passes forward-auth for any
bearer-accessed proxied route — a complete authentication bypass. This is audit
finding **P0-1**.

## Approach

**Reuse the repo's already-correct verification; do not reinvent it.**
`internal/common/middleware` already contains the canonical secure path used by
every service's `Auth()` middleware: `jwt.Parse` with

- an **RS256 algorithm pin** (`alg` must be present and `RS256` — rejects
  `none`, `HS256`, and the alg-confusion attacks),
- a **kid → JWKS public key** lookup via the cached `getSigningKey` (1-hour
  JWKS cache; correct for the proxy hot path), and
- an **`exp`** expiry check.

The existing exported helper `FetchJWKS` is a per-call (uncached) keyfunc meant
for one-off ID-token checks — wrong for the per-request proxy path. So we add one
small **cached, exported** verifier and route the proxy's bearer path through it.

### Component 1 — `middleware.VerifyBearerToken`

Add to `internal/common/middleware/middleware.go`:

```go
// VerifyBearerToken validates a bearer JWT against the OAuth JWKS and returns
// its claims. It enforces the same guarantees as the Auth() middleware — an
// RS256 algorithm pin (rejecting "none"/HS256 and alg-confusion), a kid→JWKS
// signing-key lookup via the shared 1-hour key cache, and a required, unexpired
// exp — and is for services that authenticate a bearer OUTSIDE the Auth()
// middleware (e.g. the access reverse proxy resolving a forwarded bearer). It
// returns an error on any verification failure; callers must treat a non-nil
// error as "unauthenticated" and build no session from it.
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

Notes:
- Returns `map[string]interface{}` (which `jwt.MapClaims` already is) so callers
  need not import `golang-jwt` — the access service extracts claims exactly as it
  does today.
- Stricter than `Auth()` on one axis — `exp` is **required**, not just enforced
  when present — which is correct for an OAuth access token (always carries
  `exp`) and removes the no-expiry edge case.
- Uses the package-private `getSigningKey`, so it shares the existing
  `globalJWKSCache` — no extra JWKS round-trips on the proxy hot path.

### Component 2 — route the proxy bearer path through it

Rewrite `getSessionFromBearer` (`internal/access/service.go:2452`):

```go
func (s *Service) getSessionFromBearer(c *gin.Context) *ProxySession {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// SECURITY: verify the bearer's signature + expiry against the OAuth JWKS
	// before trusting any claim. A forged/unsigned token must yield no session
	// (the request then falls through to unauthenticated handling, exactly as a
	// missing cookie does). Never build a ProxySession from unverified claims.
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
	return &ProxySession{UserID: userID, Email: email, Name: name, Roles: roles}
}
```

`s.oauthJWKSURL` is already set on the Service (`service.go:116/304`). If it is
empty (JWKS not configured), `getSigningKey` fails → `VerifyBearerToken` errors
→ no session, i.e. **fail-closed**: with no way to verify, bearer auth is simply
unavailable rather than forgeable.

## Out of scope (deliberate)

- **The other two `parseTokenClaims` callers** — the OAuth callback
  (`service.go:1426`) and the external-IdP callback (`multi_idp.go:275`) — parse
  a token **just obtained from a token endpoint via a server-to-server code
  exchange over TLS**, not a client-supplied bearer. That channel is trusted
  (OIDC Core §3.1.3.7 permits skipping ID-token signature checks for tokens
  received directly from the token endpoint), so they are not the bypass and are
  left unchanged. `parseTokenClaims` therefore stays (it keeps these two
  callers); only the bearer path stops using it.
- **Revocation check** on the bearer — the audit tracks this separately as P1
  (with idle-timeout enforcement). P0-1 is the signature/expiry forge. Noted as
  the immediate follow-up.
- **`iss`/`aud` validation** — `Auth()` doesn't validate them either; adding it
  is optional future hardening and would risk behavior drift, so it's excluded
  here to keep the fix focused on the bypass.

## Testing

Unit test `TestVerifyBearerToken` in `internal/common/middleware` (a real RSA
keypair generated in-test; a tiny `httptest` server serving a JWKS with the
public key under a known `kid`):

- **valid** RS256 token signed by the test key, with future `exp` → returns
  claims; `sub` matches.
- **`alg:none`** / unsigned token → error (the core bypass; must NOT verify).
- **wrong key** (signed by a different RSA key) → error.
- **expired** (`exp` in the past) → error.
- **missing `exp`** → error.
- **missing `kid`** → error.

`go build ./...`, `go vet ./...`, `gofmt`, `go run ./tools/orgscope -fail
./internal` (no SQL added), and `go test ./internal/common/middleware/...
./internal/access/...` all green.

## Verification checklist

- [ ] `VerifyBearerToken` added; uses cached `getSigningKey`; requires RS256 +
  `kid` + unexpired `exp`.
- [ ] `getSessionFromBearer` builds a session only from verified claims; returns
  `nil` on any verification error.
- [ ] Unit tests cover valid / unsigned / wrong-key / expired / missing-exp /
  missing-kid.
- [ ] build / vet / gofmt / orgscope / unit tests green.
- [ ] (post-merge, live) a forged unsigned bearer to a bearer-accessed route no
  longer authenticates; a genuine OAuth access token still does.
