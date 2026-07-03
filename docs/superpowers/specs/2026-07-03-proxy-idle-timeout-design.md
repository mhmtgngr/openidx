# Enforce idle timeout on access-proxy sessions (readiness W3.11)

> First Workstream 3 (hardening) item — **verify-first**, now **confirmed a real gap**.
> Proxy routes carry a per-route `idle_timeout` (default 900s), and `proxy_sessions.last_active_at`
> is updated on every proxied request, but **nothing enforces idle expiry**: the hot path
> (`getSessionFromRequest`) checks only the absolute `expires`, and no background sweep revokes
> idle sessions (`continuous_verify` revokes on posture/risk, not inactivity). So `idle_timeout`
> is dead config on the data plane — a session stays valid until `absolute_timeout` regardless of
> inactivity.

## Verification (done)

- `internal/access/service.go` `getSessionFromRequest` (~2444): loads the session blob from Redis,
  checks `sessionData["expires"]` only. No idle check.
- The Redis blob (created ~2415) carries `id/user_id/email/name/roles/token/expires` — **no
  `last_active`** — and is `Set` with a fixed 12h TTL.
- No worker enforces proxy idle: `grep` shows no `last_active_at`+`idle_timeout` comparison anywhere;
  `continuous_verify.go` revokes on re-verification, not inactivity.
- Contrast: OAuth *login* sessions do get idle handling elsewhere; this gap is specific to the
  **access-proxy** data-plane session.

## Fix (in `internal/access/service.go` only)

1. **Stamp `last_active` in the blob** at creation (~2415): add `"last_active": time.Now().Unix()`.
2. **Surface it** in `getSessionFromRequest`: parse `last_active` and set `session.LastActiveAt`.
3. **Enforce in `handleProxy`** (the caller that has the `route`): for the cookie session (not the
   bearer path — bearer carries its own JWT expiry), after `getSessionFromRequest`:
   ```
   if route.IdleTimeout > 0 && !session.LastActiveAt.IsZero() &&
      time.Since(session.LastActiveAt) > time.Duration(route.IdleTimeout)*time.Second {
       // idle-expired: revoke (best-effort delete Redis key + mark DB revoked) and
       // redirect to login exactly as a missing session does
   }
   ```
4. **Slide the window on activity**: extend `updateSessionActivity` (called on every proxied request
   at ~1748) to also refresh the blob's `last_active` to now and re-`Set` it preserving the
   **remaining** absolute TTL (read current TTL; fall back to 12h). It needs the token hash, so
   change its signature to take `*gin.Context` (it already runs in the request path; sole caller is
   `handleProxy`) and read the `_openidx_proxy_session` cookie. The absolute `expires` field is
   untouched, so absolute expiry still applies independently.

Net: a proxy session dies after `idle_timeout` of inactivity (sliding) OR at `absolute_timeout`,
whichever first — matching the route config's intent. Bearer-token requests are unaffected.

## Testing
- Unit (`internal/access`, no infra): a focused test on the idle decision — construct a
  `ProxySession` with `LastActiveAt` in the past and assert the `handleProxy` idle predicate treats
  it as expired for a route with `idle_timeout` set, and as valid within the window / when
  `idle_timeout == 0`. If the predicate is inline, extract it into a small pure helper
  `isIdleExpired(route, session, now) bool` so it's unit-testable without Redis/HTTP.
- `go build ./...`, `go vet`, `gofmt`, `go run ./tools/orgscope -fail ./internal` clean.
- Manual/box (optional): set a short `idle_timeout` on a route, confirm a session re-auths after
  inactivity but survives active use.

## Out of scope
Per-route idle when one cookie spans multiple routes with different `idle_timeout`s (the check uses
the current route's value each request, which is correct per-request). W3.12 (OPA ValidateProduction)
and W3.13 (VAULT_KEK) are separate items.

## Critical files
- `internal/access/service.go` (blob stamp, `getSessionFromRequest`, `handleProxy` idle check,
  `updateSessionActivity` refresh) + a colocated unit test for `isIdleExpired`.
