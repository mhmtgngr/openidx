# P1 — Honor revocation in OAuth token introspection (`/oauth/introspect`)

## Context

`handleIntrospect` (`internal/oauth/service.go:2878`, the RFC 7662 token
introspection endpoint) parses the access token, verifies its signature and
validity, and returns `{"active": true, …claims}` — but **never checks
revocation**. A token revoked via `/oauth/revoke` or `/oauth/logout-all` still
introspects as `active: true` until its (~15-minute) `exp`. A resource server
relying on introspection therefore keeps honoring a token the user/admin already
killed.

The sibling `handleUserInfo` (`:2981`, the revocation check at `:3019`) already
does this correctly via `s.IsAccessTokenRevoked(ctx, token, sub, iat)`. The
revocation store is Redis-backed: a per-token blacklist (`/oauth/revoke`,
`/oauth/logout`) plus a per-user "revoked-before-T" cutoff (`/oauth/logout-all`).

### What is NOT broken (audit findings verified stale)

- **Idle + absolute session expiry are enforced.** `StartSessionWorker`
  (`cmd/oauth-service/main.go:181`) runs leader-gated every 60s and revokes both
  expired (Phase 1) and idle-past-policy (Phase 2) sessions
  (`session_worker.go`). The audit's "idle-timeout never enforced" no longer
  holds.
- `auth.TokenService.WithRevocationRequired` has only marginal callers
  (`admin`, `mfa`); the live token paths use `s.IsAccessTokenRevoked` directly.

So this spec is scoped to the one genuine live gap: introspection.

## Approach

In `handleIntrospect`, on the **access-token** path (signature-valid JWT), after
reading `sub` and `iat` from the claims and **before** returning the active
response, consult the same revocation check `handleUserInfo` uses:

```go
userID, _ := claims["sub"].(string)
var issuedAt int64
if iatF, ok := claims["iat"].(float64); ok {
    issuedAt = int64(iatF)
}
if revoked, err := s.IsAccessTokenRevoked(c.Request.Context(), token, userID, issuedAt); err != nil {
    // Fail closed: a token whose revocation state can't be verified must not
    // read active. (Introspection's contract is the boolean, so this is
    // active:false, not userinfo's 401.)
    s.logger.Warn("introspect: revocation check failed", zap.Error(err))
    c.JSON(200, gin.H{"active": false})
    return
} else if revoked {
    c.JSON(200, gin.H{"active": false})
    return
}
// … existing active:true response …
```

Key semantic difference from `handleUserInfo`: introspection returns **HTTP 200
with `active:false`** for a revoked/unverifiable token (RFC 7662 §2.2), not a
401. This is the one intentional divergence from the userinfo pattern.

`token` here is the introspected token string (the `token` form field already in
scope at the top of the handler); `IsAccessTokenRevoked` hashes it for the
blacklist key.

## Out of scope (deliberate)

- **Refresh-token branch** (the JWT-parse-fail path): already gates on
  `oauth_refresh_tokens` row existence + `expires_at > NOW()`; revocation
  removes/expires that row, so it's covered. Unchanged.
- **Access-proxy bearer revocation** — the access reverse proxy verifies a
  bearer's signature + expiry (P0-1) but not revocation; closing that is a
  *cross-service* change (the access service would need oauth's Redis revocation
  keys or a per-request introspect call). Tracked as a separate follow-up.
- **Idle-timeout / `WithRevocationRequired`** — verified already-handled /
  marginal (see Context); untouched.

## Testing

A test in `internal/oauth` (mirroring the existing introspect/revoke test setup
that uses `Store.RevokeAccessToken`):

- Issue/mint an access token, introspect it → `active == true`.
- `Store.RevokeAccessToken(ctx, token)` (per-token blacklist), introspect again →
  `active == false`.
- (If the harness supports it) a logout-all cutoff also yields `active == false`
  for a token issued before the cutoff.

`go build ./...`, `go vet ./internal/oauth/...`, `gofmt`, `go run ./tools/orgscope
-fail ./internal` (no new SQL), and `go test ./internal/oauth/...` all green.

## Verification checklist

- [ ] `handleIntrospect` calls `IsAccessTokenRevoked` on the access-token path
  before returning active.
- [ ] Revoked token → `200 {"active": false}`; revocation-check error → fail
  closed (`active:false`).
- [ ] Non-revoked token still → `active:true` with claims (no regression).
- [ ] Test covers revoked → inactive and non-revoked → active.
- [ ] build / vet / gofmt / orgscope / oauth tests green.
