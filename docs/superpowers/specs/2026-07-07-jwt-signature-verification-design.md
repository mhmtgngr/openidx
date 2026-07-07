# OAuth logout/session endpoints: verify JWT signatures

**Goal:** Three OAuth handlers parse caller JWTs with `jwt.Parser.ParseUnverified` (no signature
check) and then act on the unverified `sub` — CodeQL `go/missing-jwt-signature-check` (high ×3), and a
real vulnerability: a forged/unsigned JWT lets an attacker target **any** user. Verify signatures.

**Verified current state (2026-07-07, `internal/oauth/service.go`):**
- **`handleLogoutAll` (:3609)** — reads the `Bearer` token, `ParseUnverified` → `sub`, then revokes
  **all** of that user's sessions. A forged JWT (any `sub`, no valid signature) force-logs-out any user.
- **`handleSessionInfo` (:3658)** — `ParseUnverified` the Bearer token → returns session/policy info for
  that `sub` → cross-user info disclosure.
- **`handleEndSession` (:3514 + the bearer fallback ~:3532)** — `ParseUnverified` the `id_token_hint`
  (and, as a fallback, the Bearer) → `sub` → drives session logout. (It *already* signature-verifies the
  Bearer at ~:3547 to mark it revoked — so the verified path/key already exists here.)
- **Correct pattern already in the file:** `handleUserInfo` (:3176) does
  `jwt.Parse(tokenString, func(*jwt.Token){return s.publicKey, nil})` then `!token.Valid → 401`.
  `s.publicKey` is the service's `*rsa.PublicKey` (set from the KeyManager signing key).
  `KeyManager.ValidateJWT` (keys.go) additionally pins the method to `*jwt.SigningMethodRSA`.
- OIDC RP-initiated logout permits `id_token_hint` to be **expired**, so that one must verify the
  **signature** but tolerate expiry.

## Design

### Shared helper (`internal/oauth/service.go`)
```go
// parseVerifiedClaims signature-verifies a JWT against the service's RSA signing key (RS256 pinned,
// preventing alg-confusion) and returns its claims. allowExpired skips exp/nbf validation — used only
// for the OIDC id_token_hint, which the spec permits to be expired — while STILL requiring a valid
// signature. Returns an error if the signature is invalid (or, unless allowExpired, if expired).
func (s *Service) parseVerifiedClaims(tokenString string, allowExpired bool) (jwt.MapClaims, error) {
	keyfunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.publicKey, nil
	}
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"})}
	if allowExpired {
		opts = append(opts, jwt.WithoutClaimsValidation())
	}
	token, err := jwt.NewParser(opts...).Parse(tokenString, keyfunc)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("token signature verification failed: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}
```

### Apply it
- **`handleLogoutAll`**: replace the `ParseUnverified` block with
  `claims, err := s.parseVerifiedClaims(tokenStr, false); if err != nil { 401 invalid_token; return }`,
  then read `sub` from `claims`. (An unsigned/forged token is now rejected before any revocation.)
- **`handleSessionInfo`**: same — `parseVerifiedClaims(tokenStr, false)`, 401 on error, then read claims.
- **`handleEndSession`**:
  - `id_token_hint`: `claims, err := s.parseVerifiedClaims(idTokenHint, true)` (expiry-tolerant); set
    `userID` from `claims["sub"]` only when `err == nil` (a bad-signature hint is ignored, not trusted).
  - Bearer fallback: `claims, err := s.parseVerifiedClaims(bearerToken, false)`; set `userID` only when
    `err == nil`. (Consolidate with the existing verified parse used for revocation-marking so the token
    is verified once.)
  - Behavior preserved: end-session stays best-effort (no hard 401 — it's a logout), but it will no
    longer act on an **unverified** `sub`.

RS256 pinning + `s.publicKey` keyfunc matches `KeyManager.ValidateJWT`; `jwt.WithoutClaimsValidation()`
(golang-jwt/v5) verifies the signature while skipping exp/nbf — the right tool for `id_token_hint`.

## Testing / verification
Mirror the existing oauth handler tests (a `Service` with a KeyManager; mint signed tokens via
`token.SignedString(key)` as in `keys_test.go` / `introspect_revocation_test.go`):
- **`handleLogoutAll` / `handleSessionInfo`**: a token signed with the **wrong** key (or `ParseUnverified`-style
  unsigned/`alg=none`) → **401** and **no** session revocation / no info returned; a **correctly-signed**
  token → 200 and acts on the real `sub`.
- **`handleEndSession`**: a `id_token_hint` with a **bad signature** → `userID` not set (no logout for
  that sub); a correctly-signed but **expired** hint → still accepted (sub used); a wrong-key Bearer
  fallback → not trusted.
- `go build ./... && go vet ./internal/oauth/ && gofmt -l && go test ./internal/oauth/` green;
  `golangci-lint run ./internal/oauth/` clean.
- Post-PR: confirm the 3 `go/missing-jwt-signature-check` alerts clear on the merge-ref.

## Scope / risk
- `internal/oauth/service.go` only (+ its test). Real security fix, **box-relevant** (the oauth service
  runs on the box) → release + deploy after merge.
- Behavior change: forged/unsigned tokens to logout-all/session-info now correctly 401 (previously
  "worked"); legitimately-signed tokens are unaffected. end-session remains best-effort but ignores
  unverified subjects.
- Out of scope: the other real critical/high alerts (2 ziti `mgmtRequest` SSRF at 1719/1748,
  `go/path-injection` ×7, `go/weak-sensitive-data-hashing` ×5, `js/empty-password-in-configuration-file`)
  — separate follow-ups after this.
