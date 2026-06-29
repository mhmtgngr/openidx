# OpenIDX v2.0 GA production-readiness audit — 2026-06-29

Read-only sweep across five dimensions (tenant-isolation residuals, secrets/config,
init-db↔migrations drift, CI/CD & dependencies, auth/session fail-closed). Findings
are prioritized **P0** (GA-blocking / live defect), **P1** (fix before GA), **P2**
(hardening). The two top P0s were verified directly against code + the live DB.

## P0 — GA-blocking (two are live defects now)

### P0-1 · Access-proxy bearer auth trusts UNSIGNED JWTs (auth bypass) — VERIFIED
`internal/access/service.go:2583` `parseTokenClaims` splits on `.`, base64-decodes
the payload, and unmarshals the claims — **no signature verification, no `exp`
check**. `getSessionFromBearer` (`:2448`) builds a fully-authorized `ProxySession`
(roles → the route role gate `hasAnyRole`, and `X-Forwarded-User/Roles` to the
upstream) from those unverified claims. An attacker can forge
`Authorization: Bearer <unsigned-jwt>` with arbitrary `sub`/`roles` and pass
forward-auth for any bearer-accessed proxied route. **Fix:** verify the bearer with
the OAuth public key (as `handleUserInfo` does) and reject on bad signature/expiry;
also run the revocation check. Never build a session from unverified claims.

### P0-2 · API-key auth (and other pre-tenant-resolution lookups) fail closed under the RLS role — LIVE on the box
`internal/apikeys/service.go:320` validates a key via `SELECT … FROM api_keys
WHERE key_hash=$1` on `s.db.Pool` with **no `WithBypassRLS` and no `app.org_id`**
(correct intent — it's pre-tenant-resolution, keyed by the globally-unique hash).
But `api_keys` is FORCE-RLS, so under the `openidx_app` role the fail-closed policy
(`org_id = NULLIF(current_setting('app.org_id'),'') → NULL → false`) returns **0
rows** → "invalid api key" for **every** key. Verified live: as `openidx_app` with
no GUC, `SELECT count(*) FROM api_keys` = **0**. The v1.8 cutover (shipped as
v1.8.0) activated this on the box. **Same trap for every other pre-resolution
lookup against a FORCE-RLS table** — session-token logout (`access/service.go`),
password-reset / email-verification tokens, OAuth client lookup. **Fix:** wrap each
pre-resolution lookup in `orgctx.WithBypassRLS(ctx)` (safe — keyed by a
globally-unique credential), reading `org_id` out of the row as it already does.
Audit all such lookups; add an integration test that exercises API-key + token
auth under `openidx_app`. *(The tenant-isolation harness didn't catch this — it
tested data-plane row visibility, not the pre-auth lookups.)*

### P0-3 · 58 tables exist in `init-db.sql` but in NO migration → 500s on migrate/RDS/Helm installs
`deployments/docker/init-db.sql` defines 58 tables that no `internal/migrations/*.go`
creates; **56 are read/written by app code** (e.g. `unified_audit_events`,
`saml_service_providers`, `email_templates`, `magic_links`, the `mfa_*` set,
social/federation tables, `lifecycle_*`, `ispm_*`, `guacamole_*`, `bulk_operations*`,
`audit_archives`/`retention`, `admin_audit_log`). Fresh **migrate-based** installs
(managed Postgres / RDS / Helm) lack them → guaranteed 500s on those features. This
is the recurring init-db↔migrations drift at scale (prior incidents fixed ~15
tables; 58 remain). **Fix:** a reconcile migration (v54+) creating all 58 verbatim
(`IF NOT EXISTS`), per the v38–v45 pattern — then collapse to one schema source of
truth (see Root cause).

### P0-4 · Hardcoded APISIX admin key committed and used by the production stack
`deployments/docker/apisix/config.yaml:7,27` ships a literal `key:
edd1c9f034335f136f87ad84b625c8f1` with broad `admin_allow_ip`; `docker-compose.yml:100`
mounts it and `docker-compose.prod.yml` extends that mount without override → a
`prod` bring-up exposes a static, in-repo gateway control-plane key. **Fix:**
template the key from a secret/env (as `apisix-edge/config.yaml` already does with
`CHANGE_ME_ADMIN_KEY`), tighten `admin_allow_ip`.

### P0-5 · No branch protection on `main` → hard gates are unenforced at merge
`gh api …/branches/main/protection` → `404 Branch not protected`; rulesets empty.
Every "hard gate" (lint, orgscope, vulnerability-check, integration, Required
Checks) is decorative — a red/`UNSTABLE` PR can be squash-merged (observed all
cycle, and the orgscope/lint regressions earlier this session reached `main` exactly
this way). **Fix:** require `Required Checks` (and ideally Docker Build / CodeQL) as
required status checks on `main`, strict/up-to-date, require PRs.

## P1 — fix before GA

- **`openidx_app` cutover not in `docker-compose.yml` / `.env` / `docker-compose.prod.yml`** — those still use the `openidx` superuser, so RLS is **inert** on compose/prod deploys (only the box's systemd env was cut over). Cut compose/prod over too (and fix P0-2 first, or the cutover breaks API-key auth there).
- **OAuth introspection ignores revocation** (`oauth/service.go:2878` `handleIntrospect` never calls `IsAccessTokenRevoked`) — a revoked token introspects `active:true` until its 15-min TTL. `WithRevocationRequired(true)` (`auth/token.go:106`) exists but has **zero prod callers** (fail-open on Redis error). Idle-timeout is configured (`IdleTimeout`, `last_active_at` written) but **never enforced** (`getSessionFromRequest` checks only absolute `expires`).
- **`apisix-edge/config.yaml:35-41`** binds the admin API to `0.0.0.0:9280` with `allow_admin: 0.0.0.0/0` (only the `CHANGE_ME` placeholder guards it).
- **Prod `DATABASE_URL` uses `sslmode=disable`** (`docker-compose.prod.yml`); `ValidateProduction()` checks the standalone `DatabaseSSLMode` field, not the URL's `sslmode`, so the two can drift (gate satisfied while the wire is plaintext). `ziti_admin_password` weak default isn't covered by the prod validator either.
- **Stale security dep bumps (open ~4–5 months):** `x/crypto` (#43), `x/oauth2` (#44), `golang-jwt/v5` (#29), `go-webauthn` (#22), `pgx/v5` (#30), `go-redis/v9` (#45). `govulncheck` is clean today, but these are auth/transport-critical — current them for GA.
- **`docs.yml` workflow persistently failing on `main`** (`mike` `duplicated version and alias`) — fix with `--update-aliases`.
- **Migration ledger stale on the box** (`schema_migrations` max = 45; v46–v53 applied out-of-band / not recorded). Run migrations to head everywhere; add a startup/CI assert that `max(ledger.version) == len(loader registry)`.

## P2 — hardening

- `CrossOrgAuditor` (`audit/cross_org.go:38`) swallows the mandatory cross-org audit insert error (`_, _ = pool.Exec`) — a failed audit lets the cross-org access proceed unlogged; it may itself fail-closed under `openidx_app` (P0-2 class). Log at minimum; consider hard-fail.
- IP threat-list check (`context_evaluator.go:393`) fails **open** on DB error (admits threat IPs).
- Dead runtime-DDL code that would break as `openidx_app` if ever wired: `audit/store.go:282` `ensurePartition`, oauth `EnsureClientsTable/ConsentTable/SigningKeysTable` (no callers). Delete or move to migrations.
- Reverse drift: 7 migration-only tables (`kiosk_policies`, `policy_recommendations`, `compliance_gaps`, `remote_support_sessions`, `saml_sessions`, …) absent from `init-db.sql` (fresh docker installs miss them).
- LDAP `skip_tls_verify` and OPA dev fail-open aren't surfaced in `ValidateProduction()` (both env/flag-gated, low risk).

## What's clean (verified)

- Platform-admin cross-org audit trail wired into all 8 service mains; bypass-path
  and `//orgscope:ignore` directives are overwhelmingly legitimate (background
  sweeps / globally-unique keys / install-wide diagnostics).
- A real fail-closed `ValidateProduction()` blocks startup on weak JWT/encryption/
  session secrets, wildcard CORS, disabled CSRF, TLS skip-verify, debug OTP.
- Core `org_id → organizations` FKs present (users/applications/proxy_routes/
  oauth_clients/sessions/audit_events). `govulncheck` clean. Rate-limiter,
  governance `/evaluate`, `userinfo`, `TenantResolver`, and `handleAuthDecide` all
  fail **closed**. Session cookies `Secure(prod)/HttpOnly/SameSite`; tokens from
  `crypto/rand`; no `TODO(unwired)` markers remain. `INTERNAL_SERVICE_TOKEN` is
  safe-by-construction (empty disables the shortcut, falls back to JWT).
- `openidx_app` has SELECT on all 109 public tables + default privileges (no static
  grant gaps); the only withheld privilege is CREATE-on-schema (intended).

## Root cause (two systemic issues)

1. **Two divergent schema sources** (`init-db.sql` vs `internal/migrations`) — drives
   P0-3 and the reverse drift, and has bitten ≥4 times. Collapse to one source for
   GA: run migrations even in docker-compose, reduce `init-db.sql` to
   extensions/roles/seed, and add a CI assert that the init-db table set == migration
   table set == applied ledger.
2. **No merge-time gate enforcement** (P0-5) — well-written gates that nothing
   requires. Enables every regression-reaches-`main` incident this cycle.

## Suggested fix order

1. **P0-2** (live API-key break — fix the pre-resolution bypass + test) and **P0-1**
   (unsigned-JWT bypass) — security-critical, one is live.
2. **P0-5** (branch protection) — cheap, stops the bleeding for everything else.
3. **P0-4** (APISIX key), **P0-3** (58-table reconcile migration).
4. P1 cluster (revocation/idle-timeout, compose cutover, sslmode, dep bumps, docs.yml).
5. P2 hardening.
