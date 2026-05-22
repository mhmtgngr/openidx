# Changelog

All notable changes to OpenIDX are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

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
