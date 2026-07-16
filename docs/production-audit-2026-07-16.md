# End-to-End Production Audit — User & Management Journeys

> A walk of the real user journeys (login → use the console → manage users)
> hunting for production-fail bugs, focused on the frontend↔backend contract.
> Dated 2026-07-16. Fixes for the P1/P2 items below are committed; the remaining
> items are recommendations.

## Method

Traced the admin console (`web/admin-console/src`, React/TS) against the Go
backend (`internal/`, `cmd/`) along three journeys:

1. **Login** — PKCE authorize → code exchange → token storage → `isAuthenticated`.
2. **Use** — the axios client, token attach, refresh, error/degradation handling.
3. **Manage** — user CRUD page ↔ identity-service routes and field shapes.

## Findings

### 🔴 P1 — PKCE S256/plain mismatch made login impossible on non-HTTPS deploys — FIXED

**Where:** `web/admin-console/src/lib/auth.tsx` (`generateCodeChallenge` +
`login`), verified against `internal/oauth/service.go` `VerifyPKCE`.

**What broke:** `crypto.subtle` (needed for S256) is only present in a *secure
context* (HTTPS or `http://localhost`). In any other context (plain-HTTP
deployment, or a LAN IP without TLS) it is `undefined`. The old code fell back to
using the **plain verifier as the challenge** but `login()` *always* sent
`code_challenge_method=S256`. The backend then computed `SHA256(verifier)` and
compared it to the plain verifier — which never matches — so the token exchange
returned `invalid_grant` and **no one could log in**. Silent and total for that
deployment shape.

**Fix:** `generateCodeChallenge` now returns `{ challenge, method }`, and `login`
sends the method that matches the challenge (`S256` in a secure context, `plain`
otherwise). Login works in both; a warning nudges operators to serve over HTTPS.

### 🔴 P1 — Console ignored the backend's 503 brownout, turning a DB failover into a user-facing failure — FIXED

**Where:** `web/admin-console/src/lib/api.ts` response interceptor, vs
`internal/oauth/unavailable.go` (the Tier 2 backend work).

**What broke:** The backend now returns `503 temporarily_unavailable` + a
`Retry-After` header during a transient dependency brownout (e.g. an RDS
failover) — deliberately retryable so the blip is invisible. The live axios
client had **no 503 handling**, so it rejected immediately and every open page
showed an error during a failover the backend intended to absorb.

**Fix:** the interceptor now retries idempotent (GET/HEAD/OPTIONS) requests on
503 up to 3 times, honoring `Retry-After` (capped), with backoff. A brief DB blip
now stays invisible on read paths, matching the backend's intent. (Writes are not
auto-retried — they may not be idempotent — and correctly surface the 503.)

### 🟡 P2 — Dead-code `api/client.ts` was an auth landmine — FIXED

**Where:** `web/admin-console/src/lib/api/client.ts` (imported by no page today).

**What was wrong (latent):** it read the token from `openidx_access_token` /
`openidx_refresh_token` while login writes `token` / `refresh_token` (so every
request would 401), and it refreshed via `POST /api/v1/identity/refresh` — **a
route that does not exist** on the backend (so every refresh would 404 → forced
logout). Harmless while unused, but a trap: wiring one page to it silently breaks
auth for that page.

**Fix:** aligned the storage keys with `auth.tsx` and pointed refresh at the real
OAuth token endpoint (`grant_type=refresh_token`, form-encoded). If adopted, it
now works. **Better follow-up:** delete this client entirely and standardize on
`lib/api.ts`, OR migrate everything to it — two API clients is the root smell.

### 🟡 P2 (security) — Backend accepts and defaults to PKCE `plain` — HARDENED

**Where:** `internal/oauth/service.go` (`handleAuthorizationCodeGrant` PKCE
verification), `internal/oauth/authorize_flow.go:207-215`, `VerifyPKCE`.

When a `code_challenge` is present but no method, the backend defaults to
`plain`, and `VerifyPKCE` accepts `plain` (a bare string compare, no protection
against authorization-code interception). This is still *needed* for the
insecure-context frontend fallback above, so it can't be removed outright.

**Fix:** the token-exchange PKCE check now **rejects `plain` when
`APP_ENV=production`** (`s.config.IsProduction()`), returning `invalid_grant`. A
prod console is served over HTTPS, so it always uses S256 — plain in prod could
only help an attacker. The dev/insecure-context fallback still works in non-prod.

## Verified sound (no action)

- **User management CRUD contract matches.** The users page
  (`web/admin-console/src/pages/users.tsx`) hits `GET/POST/PUT/DELETE
  /api/v1/identity/users`, `/users/:id/roles`, `/users/:id/reset-password`,
  `/users/import`, `/users/export` — all registered in
  `internal/identity/service.go:3064+` with matching SCIM field mapping
  (`userName`, `name.givenName`). Create/edit/delete/import/export/role-assign all
  line up.
- **Primary auth path is consistent.** `auth.tsx` + `lib/api.ts` agree on token
  keys (`token`/`refresh_token`) and use the real `/oauth/token` refresh
  (`grant_type=refresh_token`).
- **Session-revocation handling** on refresh is present (`session_revoked`
  branch), so a revoked session redirects to login rather than looping.

## Recommended follow-ups (not yet done)

1. Collapse the two API clients into one (`lib/api.ts`), deleting `api/client.ts`.
2. Fix the local vitest env (missing `happy-dom` dev dep) so the console test
   suite — including `api-contract.test.ts` — actually runs in CI.
3. Add a small e2e/browser test that logs in over an insecure context to catch a
   future PKCE method/challenge desync (the class of bug behind P1 #1).
