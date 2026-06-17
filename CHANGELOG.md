# Changelog

All notable changes to OpenIDX are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Multi-tenancy — RLS belt + per-org primitives (v1.8.0)

Defense-in-depth: Postgres Row-Level Security so a missing app-layer org filter
still cannot leak across tenants, plus the per-org primitives.

#### Added
- Migration **v37**: activates RLS on all 68 org-scoped tables — policies
  rewritten to `app.bypass_rls='on' OR org_id = current_setting('app.org_id')`
  with `ENABLE` + `FORCE ROW LEVEL SECURITY` (fail-closed when the GUC is unset).
- Pool-checkout GUC injection (`internal/common/database/rls.go`): each
  connection is stamped with the request's tenant scope from `orgctx`; no query
  call-site changes. `orgctx.WithBypassRLS` is the explicit opt-in for
  background/cross-org jobs (wired into ~25 ticker/sweep entrypoints + the migrator).
- Two-tenant RLS ship-gate test (`test/integration/cross_org_test.go:TestRLSBelt`):
  a raw cross-org `SELECT` returns 0 rows even with the app filter "broken".
- Per-org rate-limit buckets; `compliance_reader` org-scoped read-only audit role;
  admin-console **Branding** page; `docs/multitenancy-upgrade-runbook.md`.

#### Changed
- **BREAKING (operational):** with RLS forced, direct SQL against org-scoped
  tables sees no rows unless the session sets `app.org_id` (or
  `app.bypass_rls='on'`). See the upgrade runbook.

### Multi-tenancy — App-layer enforcement (v1.7.0)

The v2.0 multi-tenancy epic's enforcement milestone. Every service query now
reads `org_id` from request context and filters/populates by it
(`orgscope ./internal` = 0), and tenant isolation is **activated**.

#### Added
- Cross-org integration test (`test/integration/cross_org_test.go`): a token
  scoped to org A gets **404** (not 403) reading org B's data; a platform admin
  (`super_admin`) may read cross-org via `X-Org-ID` and every such access writes
  an `audit_events` row (`platform_admin_cross_org_access`).
- Platform-admin bypass + mandatory audit, wired through the `TenantResolver`
  (`OnPlatformCrossOrg` hook + `auth.SuperAdminPredicate`).
- Per-tenant JWT `iss` and per-tenant OIDC discovery, derived from the org slug
  and `TENANT_BASE_DOMAIN`.
- Admin-console tenant selector (super_admin-only) that scopes requests via
  `X-Org-Slug`.
- `orgscope` is now a hard CI gate (`-fail`).

#### Changed
- **BREAKING (config):** `DEFAULT_ORG_FALLBACK` now defaults to **false** — a
  request that resolves no tenant is rejected (400) instead of being scoped to
  the default org. Single-tenant installs must set `DEFAULT_ORG_FALLBACK=true`.
- JWT `iss` is per-tenant when `TENANT_BASE_DOMAIN` is set (token-format change;
  global issuer otherwise, so single-tenant installs are unaffected).

## [1.6.0] - 2026-06-11

**Multi-tenancy Foundation milestone.** First of four releases in
the v2.0 multi-tenant SaaS isolation epic (`docs/v2-multitenancy-
design.md`). v1.6.0 lays the schema + plumbing groundwork **without
changing any behavior** for existing single-tenant installs — the
ship gate for this milestone is "existing functionality unchanged."

Multi-tenancy enforcement comes in v1.7.0 (service-layer query
scoping) and v1.8.0 (RLS belt + per-org primitives). v1.6.0 is the
foundation other releases build on.

### Added

- **`internal/common/orgctx` package** (#136). Pure-additive
  `context.Context` carrier for the resolved organization (UUID id
  + slug) and a platform-admin marker. The tenant-resolution
  middleware writes into it; v1.7.0 service code reads from it.
  `With` / `From` / `MustFrom` / `WithPlatformAdmin` /
  `IsPlatformAdmin` exposed with `ErrNoOrgContext` sentinel. 10
  unit tests.

- **`internal/common/middleware.TenantResolver`** (#140). The gin
  middleware that resolves the request's organization from
  `X-Org-Slug` header (gateway-set from subdomain), JWT `org_id`
  claim already attached by the Auth middleware, or `X-Org-ID`
  header (platform-admin only). Falls back to the install's
  default org so single-tenant installs keep working unchanged.
  Defines the `OrgLookup` interface and `ErrOrgNotFound`
  sentinel. 16 unit tests covering every resolution path.

- **`tools/orgscope` CLI** (#141). Static helper that walks
  `internal/` looking for SQL statements targeting a scoped
  table without an `org_id` reference. Filters out gin's
  `c.Query("client_id")`-style false positives by checking that
  the string literal starts with a SQL keyword. Mirrors v36's
  scoped-table list (68 tables, with documented install-wide
  exclusions). Wired into Go CI as an **informational job**
  ("Org-scope lint") that posts findings to the run summary but
  never gates a PR — v1.7.0 will promote to `-fail` once the
  service-layer refactors complete. Baseline on current `main`:
  ~1096 findings, each a concrete v1.7.0 refactor target. 28
  unit + fixture tests.

- **`docs/v2-multitenancy-design.md`** (#135). The architectural
  design doc the v1.0 plan called out as a v2 prerequisite.
  Captures three approved decisions (tenant resolution model,
  app-layer + Postgres RLS defense-in-depth, automatic `'default'`
  org backfill for existing installs), the four-milestone delivery
  plan (v1.6 → v2.0), out-of-scope items, risk register, sizing.

### Changed (schema)

- **Migration v34** (#137) — `org_id UUID NULL` column +
  `idx_<table>_org_id` index added to ~55 tables that migration
  v25 didn't reach (api_keys, mfa_*, oauth_*_tokens, ziti_*,
  scim_*, directory_*, privacy_*, posture_*, governance tables,
  …). Idempotent via `IF NOT EXISTS`. Six tables explicitly **not**
  scoped because they are install-wide rather than tenant-data:
  `organizations`, `permissions`, `system_settings`,
  `ip_threat_list`, `posture_check_types`, `policy_sync_state`.

- **Migration v35** (#138) — Backfills the default organization
  UUID (`00000000-0000-0000-0000-000000000010`, created by v25)
  into every NULL `org_id` row across v34's scoped set. Idempotent
  via `WHERE org_id IS NULL` guards. Down is narrower: only
  reverses rows currently holding the default UUID, so multi-org
  installs (none today) stay intact.

- **Migration v36** (#139) — Final foundation migration. For each
  of the 68 scoped tables, applies `SET DEFAULT '<default-org-
  uuid>'` (preserves ship gate — INSERTs that omit `org_id`
  silently land in default), `SET NOT NULL`, `ADD CONSTRAINT
  fk_<t>_org … REFERENCES organizations(id) ON DELETE RESTRICT`,
  and `CREATE POLICY pol_<t>_org_scope … PERMISSIVE … USING
  (true)`. **RLS is NOT enabled** on the tables — v1.8.0 owns
  activation by `ALTER POLICY` to a real org filter + `ALTER TABLE
  … ENABLE ROW LEVEL SECURITY`. v1.7.0's final PR will `DROP
  DEFAULT` once every INSERT path is org-context-aware.

### Notes for operators

- **No operator action required.** Migrations are
  forward-only-idempotent and `default` org is created
  automatically. The install behaves as a single-tenant install
  did before, just with the multi-tenancy plumbing ready
  underneath.
- **Migration v36 caveat:** `SET NOT NULL` on a table with very
  many rows (audit_events, login_history at scale) runs a
  validation scan. v35 backfilled every existing row so the scan
  succeeds, but for the largest installs we recommend the
  migration runs during a maintenance window.
- `tools/orgscope` baseline (~1096 unscoped queries) is **not**
  a regression — it documents the surface v1.7.0 will refactor.
  The CI job posts the count informationally; PRs are not gated.

### What's NOT in this release

- No enforcement of org scoping. Service code still ignores
  `orgctx`. Queries do not filter by `org_id` yet. RLS is not
  enabled. (v1.7.0 owns the app-layer enforcement; v1.8.0 owns
  RLS.)
- No tenant signup UI, billing, hard quotas, per-tenant signing
  keys, schema/db-per-tenant — those are explicitly out of scope
  for the entire v2.0 epic; see the design doc.

## [1.5.0] - 2026-06-11

A docs-only release that closes the last open P2 backlog item from
the v1.0 plan. No code change; safe to skip if you're already on
v1.4.0 and don't need the new operator-facing docs.

### Added
- **`docs/SECURITY-HARDENING.md`** (#133). Production-readiness
  checklist where every "hard requirement" row maps to a check in
  `Config.ValidateProduction()` — the in-process blocking startup
  gate that already refuses to bring up a misconfigured production
  deploy. Covers the secrets / transport / CSRF-CORS-audit-stream /
  debug-knob sections the validator gates on, plus an "outside the
  validator" section for the operational items that aren't config
  flags. The policy at the bottom nails down validator-first,
  doc-update-in-the-same-PR.
- **`docs/SECURITY-TENANCY.md`** (#133). Explicit, prose statement
  of the single-tenant assumption the v1.0 plan made and the v1.x
  releases preserved. Describes what is shared (data layer,
  identity, authorization, audit), what we do support (federation
  across IdPs, per-app authz, per-customer deployments), and what
  we don't (row-level tenant isolation, per-tenant signing keys,
  per-tenant rate limits, per-tenant audit isolation) — and why
  each is intentional, not a gap.

### Changed
- **`SECURITY.md`** Deployment section trimmed (#133). The previous
  generic OWASP-ish bullet list duplicated marketing copy from the
  README and overlapped with the new hardening doc by 90%. Replaced
  with two pointers to `SECURITY-HARDENING.md` and
  `SECURITY-TENANCY.md` plus the lock-step policy. Vuln reporting
  and supported-versions sections are unchanged.
- **`README.md`** Overview (#133). Adds a prominent blockquote that
  states the single-tenant assumption in one sentence and links to
  `docs/SECURITY-TENANCY.md`. First-impression accuracy for readers
  who would otherwise spend time evaluating us against a multi-
  tenant SaaS use case we don't support.
- **`docs/GETTING-STARTED.md`** "Initialize Database" step (#133).
  The old step told operators to run `\i migrations/001_create_tables.sql`
  — a pre-historic flow. Replaced with the supported path: build
  `cmd/migrate`, run `migrate up`, verify with `migrate status`.
  Plus a top-of-doc callout pointing readers at the new hardening
  and tenancy docs before any production deploy.

### Notes
- v1.4.0 deployments upgrade in place. The release tags the v1.5.0
  binaries identically to v1.4.0; if you don't pull the docs, the
  upgrade is a no-op.

## [1.4.0] - 2026-06-11

A short, focused security-hardening release. Three independent P1/P2
items the v1.0 plan called out, each landed as its own commit with
defense-in-depth tests:

### Changed
- **Dynamic UPDATE builders now run behind a column allow-list**
  (#129). Both `updateSAMLServiceProvider`
  (`internal/oauth/saml_sp.go`) and the
  `/access/paths/:pathID/classification` handler
  (`internal/access/app_publish.go`) used to build their SQL with
  `fmt.Sprintf("col = $%d", argIdx)` scattered through one if-block
  per column. The literals were hardcoded so the pattern was not
  actively exploitable, but the blast radius was wide: one refactor
  wiring a request-derived string into a Sprintf would have introduced
  a real SQL-injection vector. The new `buildUpdateClause` helper
  takes a per-caller column allow-list, validates each candidate
  against both that map and a strict identifier regex
  (`^[a-z_][a-z0-9_]{0,62}$`), and refuses to build the query when
  anything else slips through. Unit tests pin the rejection paths.
- **Migration lock acquisition retries up to 30 s before giving up**
  (#130). Previously `acquireLock` returned instantly on conflict —
  fine for a single admin-driven `cmd/migrate up`, but it raced in
  containerized environments where the migrate job and the
  identity-service / oauth-service replicas were all coming up against
  the same database at startup. Whichever migrator won the race ran
  the migrations; every other process exited with "lock is already
  held" and the orchestrator restarted them in a crash loop. The lock
  now retries every 500 ms for up to 30 s before reporting failure.
  Stale-lock recovery (15 min) is unchanged. A real DB error (not
  `errLockBusy`) still surfaces on the first try — only conflicts
  retry. Six unit tests pin the new behavior including
  context-cancellation handling.
- **CSRF protection is on by default** (#131). The
  `csrf_enabled` default flipped from `false` to `true`. The
  production gate (`ValidateProduction`) caught the old default
  anyway, but every non-prod environment had to remember to opt in.
  Operators now opt out (`CSRF_ENABLED=false`) only when they know
  they need to.

### Fixed
- **`internal/access/ziti.go` was hardcoding
  `tls.Config{InsecureSkipVerify: true}` unconditionally** (#131).
  The line ran before the CA-loading branch, which then bolted a
  `RootCAs` pool onto the TLS config — but `InsecureSkipVerify=true`
  nullifies every CA after it, so the verification path was doing
  nothing for security and the connection was insecure regardless of
  the operator's intent. Replaced with:
  - Load `ZitiIdentityDir/ca.pem` → use it for proper validation
    (the desired path).
  - Missing CA + `ZitiInsecureSkipVerify=true` → log a warning and
    use `InsecureSkipVerify` (the dev-loop escape hatch).
  - Missing CA + `ZitiInsecureSkipVerify=false` → refuse to start
    with a hint pointing at both knobs (the production refusal).

### Security
- **`ValidateProduction()` now rejects two new misconfigurations**
  (#131):
  - `redis_tls_skip_verify=true`
  - `ziti_insecure_skip_verify=true`
  Both are dev-loop escape hatches against self-signed certs in a
  local docker stack; in production they silently erase the trust
  chain on the link they cover. The blocking startup gate
  (`security_check.ValidateProductionConfig`) now ensures production
  deploys can't ship with either flag on.

### Notes
- All v1.3.0 deployments upgrade in place. The CSRF default flip and
  the new skip-verify production gates are the only behavioral
  changes most operators will see; the SQL builder and migration lock
  refactors are internal.

## [1.3.0] - 2026-06-11

A focused follow-on release driven by the P1.5 backend-test sweep —
which surfaced (and made us fix) two real OAuth-flow bugs and one
missing schema migration that production deployments had been
silently broken on since the QR-login feature shipped.

### Added
- **Backend unit-test coverage on previously untested seams** (#122):
  - `internal/oauth/authorize_handler_test.go` — the methods on
    `*AuthorizeHandler` (`validateRedirectURI`, `validateResponseType`,
    `validateScope`, `validatePKCEParameters`, `parseAuthorizeRequest`)
    were 0% covered; new file takes them to 100% without bringing up
    a Service / Redis / DB.
  - `internal/common/netutil/ssrf_test.go` — entire package was
    untested. `DefaultSSRFConfig`, `ValidateURL` (scheme / localhost /
    private-IP / no-hostname / allowlist-miss branches),
    `domainMatches`, `isPrivateIP` (RFC 1918 + RFC 4193 boundaries),
    `isLocalhostIP`, `IsPrivateURL`, `KnownPublicAPIs` sanity. Uses
    literal IPs so the test stays off DNS. **Package coverage
    0 % → 66.2 %**.
  - `internal/common/events/bus_test.go` — entire package was
    untested. `Event` constructor + fluent setters + `JSON`,
    `MemoryBus` subscribe / wildcard / all / with-filter / unsubscribe /
    publish-returns-last-error / close-rejects-publish /
    `PublishAsync`-delivers, and the package-level global-bus wrappers.
    **Package coverage 0 % → 100 %**.
- **Integration coverage for stepup + passwordless** (#123, #126,
  #127). Two new test files (`test/integration/stepup_test.go`,
  `test/integration/passwordless_test.go`) exercise 13 routes /
  ~25 cases. The stepup happy-path round-trip and the QR-login
  create / poll happy paths are now part of the gating integration
  suite.
- **Database migration v33: `qr_login_sessions`** (#127). The table
  `internal/identity/passwordless.go` has been `INSERT`-ing into since
  the QR-login feature shipped — but which no migration ever created.
  Every `POST /oauth/qr-login/create` therefore 500'd at the first
  `INSERT` against "relation does not exist". Surfaced by PR #126's
  integration tests; was previously masked by the broken-session-id
  validator (see Fixed below). Schema mirrors the column set the
  package already reads/writes (id, unique session_token, qr_code_data,
  status enum, nullable user_id, JSONB device blobs, IP, four
  lifecycle timestamps) plus indexes on `(status, created_at)` and a
  partial `user_id` index for the post-scan lookups.

### Fixed
- **`/oauth/stepup-*` returned 401 for every valid bearer token**
  (#126, closes #124). The three step-up routes were registered
  against the bare `/oauth` group with no auth middleware in front of
  them. The handlers read `user_id` and `session_id` from the gin
  context — but nothing populated them, because no middleware ran the
  JWT parse. The fix wraps the routes with `authMiddleware` the same
  way the `/oauth/authorize` consent endpoint already does. As a
  defense-in-depth follow-on, `handleAuthorizationCodeGrant` also now
  falls back to a DB lookup for the user's most-recent active session
  when the Redis `authcode_session:<code>` bridge is empty, so the
  access token always carries a usable `sid` claim.
- **`isValidSessionID` rejected every real `login_session`** (#126,
  closes #125). The validator required a strict 36-character UUID,
  but `/oauth/authorize` produces `login_session` via
  `GenerateRandomToken(32)` — a 44-character padded base64url token.
  The mismatch broke QR login, MFA OTP, passkey, and magic-link-verify
  end to end against the actual auth flow. `isValidSessionID` now
  accepts either form: a 36-character UUID, OR a 32..128-character
  base64url token with optional `=` padding. Both still exclude `:`,
  `/`, whitespace, and control bytes — Redis-key injection / path
  traversal stays blocked. Unit tests expanded to 23 cases covering
  the UUID happy path, the base64url happy path with and without
  padding, length boundaries, and the full injection-shaped rejection
  set.

### Notes
- All v1.2.0 deployments upgrade in place. Migration v33 applies on
  startup through the standard migration runner; the table is empty
  on first use and the OAuth service starts populating it
  immediately.

## [1.2.0] - 2026-06-10

A follow-on minor release closing the rest of the P1 and P2 backlog items
queued behind v1.1.0, plus a full sweep through the admin-console test
suite. Every admin-console page is now covered.

### Added
- **GDPR DSAR processor.** `Service.ExecuteDSAR` now actually fulfills
  data-subject access requests instead of marking them "received":
  - `export` (Article 15) compiles 12 categories of subject data (profile,
    consents, sessions, audit events, roles, groups, app assignments,
    access requests, MFA TOTP, MFA WebAuthn, MFA push, prior DSARs).
  - `delete` (Article 17) erases the subject's records.
  - `restrict` (Article 18) flags the subject for restricted processing.
  A background processor (`StartDSARProcessor`) auto-executes new `export`
  requests; `delete` and `restrict` stay manual on purpose. Backed by
  schema migration v32 (privacy tables) (#118).
- **Outbound resilience.** New `internal/common/resilience` package wraps
  external OAuth / SAML / OIDC discovery calls behind a circuit breaker
  (`ResilientHTTPClient` + per-host `Registry`). Long IdP outages no
  longer drag the whole login path down (#117).
- **Frontend test coverage: 100%.** Every page under
  `web/admin-console/src/pages/` (87 in total) now has a vitest suite.
  Suite is 114 files / 684 tests. Patterns established for fixtures with
  TanStack Query, Radix listeners, fetch-direct pages, route params, and
  `useAuth` mocks (#120).

### Changed
- **Application access requests are fulfilled end-to-end.** Approving an
  access request whose `resource_type == application` now provisions the
  application binding through `internal/provisioning`. Prior to this it
  marked the request approved and warned (#117).
- **Certification reviews now enforce decisions.** Reviewing an item
  with `decision == revoke` (whether per-item or via the campaign's
  `revokeUnreviewedItems`) actually revokes the underlying role / group /
  app assignment instead of just recording the decision (#117).

### Fixed
- **Session-cleanup race-detector flake.** `TestSessionService_Session-`
  `ExpirationCleanup` no longer relies on `miniredis.FastForward`, which
  raced the cleanup goroutine when `-race` was on. The test uses a real
  1 s TTL plus a 1.1 s sleep; the helper also closes its Redis client
  via `t.Cleanup` so leaked goroutines don't carry across tests (#119).

### Notes
- v1.1.0 deployments upgrade in place. The new privacy tables (migration
  v32) apply on startup through the standard migration runner.

## [1.1.0] - 2026-06-09

The first minor release after v1.0.0 — three weeks of post-release hardening
focused on real security gaps that integration tests surfaced, plus the
infrastructure to keep them from coming back.

### Added
- **`POST /api/v1/identity/users/:id/set-password`** — direct admin
  password-set endpoint. Hashes via `Service.SetPassword` so password-history
  and policy enforcement apply. Closes the "admin onboards a non-SSO user"
  gap that previously had no API path (#112).
- **`GET /api/v1/identity/users/me/sessions`** — the self-access counterpart
  of the existing admin-only `/users/:id/sessions`. Sources user id from the
  JWT (#114).
- **`GET /api/v1/identity/users/me/mfa/status`** — self-service MFA status
  endpoint. Returns the user's enabled primary factors as an array, distinct
  from the admin-console toggle map at `/mfa/methods`. Backup recovery codes
  are intentionally excluded — they're not a primary factor on their own
  (#114).
- **Integration test suite is now mandatory in CI**. The full 24-test suite
  (Postgres + Redis ephemeral services, real identity + oauth-service
  binaries) runs on every PR; any regression in identity / OAuth / MFA /
  WebAuthn / session flows blocks the merge (#115).

### Changed
- **Token revocation is now enforced at `/oauth/userinfo`.** PR #82 made
  `internal/auth.ValidateToken` fail-closed on revocation, but the OAuth
  service had its own JWT-parse path that never consulted the revocation
  store — `/oauth/revoke`, `/oauth/logout`, and `/oauth/logout-all` were
  redirect-theater. Now backed by two Redis-keyed mechanisms:
  - Per-token blacklist keyed by `sha256(token)`, TTL = remaining token
    lifetime. Used by `/oauth/revoke` and single-session `/oauth/logout`
    (when called with a Bearer).
  - Per-user revocation cutoff (`oauth:user_tokens_revoked_at:<userID>`).
    Used by `/oauth/logout-all` and by OIDC RP-initiated `/oauth/logout`
    when no Bearer is supplied — every token whose `iat ≤ cutoff` is
    rejected by `/oauth/userinfo` (#112, #114).
- **Refresh-token rotation now happens on every `grant_type=refresh_token`
  exchange** (RFC 6749 §6 / RFC 6819 §5.2.2.3). A new random refresh token
  is issued, the old one is deleted *after* the new one's INSERT succeeds,
  and the response carries the rotated token. Clients that don't store the
  rotated token will get `invalid_grant` on the next refresh — this is the
  intended security improvement (#114).
- **`Service.CreateUser` now mirrors the generated UUID back to the
  caller's struct**, so `c.JSON(201, user)` returns a usable `id` and the
  downstream "user.created" webhook + email-verification token insert see a
  real value instead of an empty string (#112).
- **SCIM `active` field now properly maps to the database `enabled` column**
  in `FromUser`. Previously, SCIM-conformant clients posting
  `{"active": true}` silently created users with `enabled=false`, and every
  admin handler queried `WHERE enabled = true` (#112).
- `handleAdminSetPassword` validates `:id` as a UUID up-front (#112).
- `handleRevoke` now signature-verifies the access token before blacklisting
  it (closes a CodeQL "missing JWT signature check" finding) (#112).

### Database
- **Migration v30**: `ALTER TABLE user_roles ADD COLUMN expires_at TIMESTAMPTZ`.
  The column was already referenced by `GenerateJWT` and the role-expiry
  cleaner, but never existed in the v1 schema — every JWT issuance returned
  an empty `roles` claim, which then 403'd the post-#79 admin-API authz gate
  (#105).
- **Migration v31**: `ALTER TABLE oauth_refresh_tokens ADD COLUMN session_id
  UUID`. The column was added when session-bound rotation landed but never
  made it into the schema migrations. Postgres rejected every INSERT, the
  error was swallowed in `handleAuthorizationCodeGrant`, and clients got
  refresh tokens that were never persisted — every `grant_type=refresh_token`
  then 400'd with `invalid_grant` (#114).

### Fixed
- `audit-service` registers the Redis health check it had been silently
  missing — every other service in the fleet was already checking Redis (#109).
- SAML SP metadata: corrected SA5008 XML tag conflicts on
  `Organization{Name,DisplayName,URL}` (#99).
- `internal/oauth/service.go` and `internal/identity/service.go` cleared
  CodeQL "log entries from user input" findings introduced by the new admin
  endpoints (#112).
- Ratelimit test window flake (#98).
- Frontend type-check and test command scripts (#88, #89).
- Race-condition CI job added (#91).
- CVE bumps: Go toolchain 1.25.11, `go-jose/v4` 4.1.4 (#104, #97).

### Test coverage
- `internal/migrations` unit tests for `allMigrations()` integrity (versions
  contiguous, no gaps, no empty SQL) and `splitSQL` behavior pins (#111).
- `internal/oauth.generateStepUpToken` sign/verify round-trip + claim
  shape (#111).
- `internal/oauth.isValidSessionID` regex-gate locked down across 15 cases
  including path traversal, separator injection, newline injection (#111).
- Frontend smoke coverage on top admin pages (#101).

### Docs
- `docs/PRODUCTION-READINESS.md` — end-to-end "can I deploy this?"
  assessment, 35-item pre-deployment checklist, full feature inventory,
  known-gaps register, deployment paths for Docker Compose / Helm /
  Terraform-EKS (#113).

### Upgrade notes
- **OAuth clients** with refresh tokens: after upgrade, the first
  `grant_type=refresh_token` exchange rotates the token. Persist the new
  `refresh_token` from the response; the old one is invalidated. Clients
  that ignore the rotated token will fail at the *second* refresh, not the
  first — make sure your client code stores the new value.
- **Browser SPAs** relying on the legacy "access token survives logout"
  bug: after upgrade, RP-initiated logout actually kills the access token.
  This is the desired behavior; UI flows that depended on the old leak
  should be reviewed.
- **Database**: two new migrations (v30, v31). Both are
  `ALTER TABLE ADD COLUMN IF NOT EXISTS` with nullable columns — backward
  compatible, fast on production-sized tables, no downtime required.

## [1.0.0] - 2026-05-22

The first tagged release: a hardened, single-tenant, self-hostable v1.

### Added
- Production deployment runbook (`docs/DEPLOYMENT.md`) anchored to the
  `ValidateProduction()` startup gate.
- Observability stack wired into the canonical compose file (Prometheus,
  Alertmanager, Grafana with provisioned dashboards, Loki/Promtail, Jaeger).
- GHCR image pipeline: multi-arch (amd64/arm64) images published to
  `ghcr.io/mhmtgngr/openidx/<service>` on every `main` push and `vX.Y.Z` tag,
  now version-stamped (the tag or commit SHA) and surfaced at `/health`.
- Helm `values-prod.yaml` (pinned tags, autoscaling, NetworkPolicies, external
  secrets, managed datastores) and a Helm chart CI workflow.
- Terraform remote-state backend bootstrap (`deployments/terraform/bootstrap/`)
  and a Terraform fmt/validate CI workflow.
- Compile gate for the build-tagged integration test suite, plus an ephemeral
  Postgres/Redis integration-test CI job.
- Backup/restore: real S3 upload and restore-from-S3 wired through the
  `Storage` interface (the previously-unused `S3Storage` backend), with a
  corrected disaster-recovery runbook.

### Changed
- Project status / feature docs rewritten to reflect the real (much more
  complete) state of the codebase.
- Adopted golangci-lint v2 and cleared the lint backlog: enforced `gofmt`,
  `govet`, `ineffassign`, `unconvert`, `bodyclose`, `staticcheck` (SA bug-class)
  and `unused`; removed dead code. `errcheck` remains intentionally deferred
  (dominated by intentional fire-and-forget calls and optional request-body
  binds).

### Fixed
- Frontend `eslint` configuration repaired; 18 stale frontend tests fixed
  (full suite green).
- Security Scanning workflow no longer reports false-red (image-scan gating;
  Semgrep SARIF upload made non-blocking).
- Backup storage: removed misleading "not initialized" panic placeholders and
  added the package's first tests.
- Schema migrations recover a stale advisory lock (from a crashed holder)
  instead of deadlocking on startup.

### Security
- **Identity admin API now enforces authorization.** The `/api/v1/identity`
  routes are deny-by-default: self-service paths (`/users/me`, MFA enrollment,
  trusted browsers, risk assessment, resend-verification) remain available to
  the authenticated user, but every other identity route now requires the
  `admin`/`super_admin` role. Previously these routes were authenticated but
  not authorized.
- **Token revocation is now enforced.** `RevokeUserTokens` previously wrote a
  per-user revocation marker that was never consulted; tokens issued before a
  revocation are now rejected. Added opt-in fail-closed validation
  (`WithRevocationRequired`) for production.
- **Auth endpoints fail closed under load-shedding.** The distributed rate
  limiter now rejects auth-sensitive requests (login, token, OTP, magic-link,
  password-reset, step-up) when its Redis backend is unavailable, instead of
  silently failing open, and covers more sensitive paths.

### Known limitations (v1)
- **Single-tenant.** One organization per deployment; multi-tenant SaaS
  isolation is not implemented.
- OAuth token introspection does not yet reflect revocation; access-token
  revocation propagates within the access-token TTL (15 min).
- Several built-but-unwired features remain (flagged `TODO(unwired)` in code):
  session idle/absolute-timeout enforcement, SAML SLO session tracking,
  reverse-proxy hop-by-hop header stripping, and audit-stream SIEM config
  endpoints.

[Unreleased]: https://github.com/mhmtgngr/openidx/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mhmtgngr/openidx/releases/tag/v1.0.0
