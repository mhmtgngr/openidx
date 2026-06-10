# Changelog

All notable changes to OpenIDX are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

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
