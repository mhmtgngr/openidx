# OpenIDX Project Status

> **Last refreshed: 2026-05-20.** This document was previously badly out of
> date (it claimed "2/7 services built" and listed shipped features as TODO).
> It now reflects the actual state of the codebase. For where the project is
> headed next, see the stabilize-and-deploy roadmap referenced at the bottom.

## Snapshot

OpenIDX is an open-source Zero Trust Access Platform (IAM + ZTNA). Core
functionality is **largely built and tested** — the remaining work is
hygiene, deployability, and test depth, not missing core features.

## Backend services

All eight services under `cmd/` are HTTP-wired with real PostgreSQL
persistence and meaningful test coverage (~127 Go test files across the
tree). Build everything with `make build-services`.

| Service | Port | Status |
|---|---|---|
| Identity (`cmd/identity-service`) | 8001 | ✅ Built + tested — users, sessions, WebAuthn, push MFA, TOTP, federation, passwordless |
| Governance (`cmd/governance-service`) | 8002 | ✅ Built + tested — access reviews, policies (SoD/risk/timebound), OPA |
| Provisioning (`cmd/provisioning-service`) | 8003 | ✅ Built + tested — SCIM 2.0 users/groups |
| Audit (`cmd/audit-service`) | 8004 | ✅ Built + tested — unified audit events, streaming, compliance reports |
| Admin API (`cmd/admin-api`) | 8005 | ✅ Built + tested — aggregated admin surface |
| OAuth/OIDC (`cmd/oauth-service`) | 8006 | ✅ Built + tested — OAuth2 + OIDC provider, PKCE, JWKS (RS256) |
| Gateway (`cmd/gateway-service`) | 8088 | ✅ Built + tested — APISIX integration, proxy routes, Ziti |
| Access (`cmd/access-service`) | — | ✅ Built + tested — Ziti zero-trust, posture, **Android agent / MDM / kiosk / remote support** |

Supporting binaries: `cmd/migrate` (migrations), `cmd/backup` (backup/restore
CLI), `cmd/profiler`.

## Android unified agent (shipped)

A native Android client (`agent-android/`) delivering MDM + kiosk + remote
support over Ziti — enrollment (QR + OAuth), posture, Play Integrity
verification, kiosk lockdown, WebRTC remote control with recording
(filesystem + S3, encryption-at-rest + key rotation, retention + legal hold),
and BYOD work-profile mode. Merged in PR #59. Server side lives in
`internal/access/` (`agent_api.go`, `kiosk_api.go`, `remote_support*.go`,
`play_integrity.go`, `turn_credentials.go`, `recording_crypto.go`). See
`docs/superpowers/specs/2026-05-15-android-client-design.md`.

## Admin console (frontend)

`web/admin-console/` — React 18 + Vite + TanStack Query + Radix/Tailwind.
~85 feature pages, nearly all wired to real backend APIs (users, groups,
roles, governance, applications, Ziti, MFA, audit, analytics, agent fleet,
kiosk policies, remote support, etc.). Build with `make build-web`.

Known frontend gaps: the `/profile` page is still a placeholder; page-level
test coverage is low (~11%); lint carries accumulated warnings being burned
down incrementally.

## Infrastructure & CI

| Area | Status |
|---|---|
| Database schema + migrations | ✅ Complete (`migrations/`, `deployments/docker/init-db.sql`) |
| Docker Compose (infra) | ✅ Postgres/Redis/Elasticsearch/APISIX/OPA + healthchecks |
| CI/CD | ✅ GitHub Actions: `ci.yml` (Go), `ci-web.yml` (frontend), `ci-android.yml`, `codeql.yml`, `docker.yml`, `security-scan.yml`, `release.yml`, `docs.yml` |
| Config validation | ✅ `ValidateProduction()` blocks prod startup on insecure secrets / wildcard CORS / disabled CSRF / non-TLS DB |
| Kubernetes / Helm | ⚠️ Chart skeleton exists; values/ingress/TLS incomplete |
| Terraform (EKS) | ⚠️ Module structure exists; state bootstrap + wiring incomplete |
| Observability | ⚠️ Prometheus collectors + health checks in code; backends (Prometheus/Grafana/Jaeger) not yet in the stack |

## Running locally

```bash
make dev-infra        # Postgres, Redis, Elasticsearch, APISIX, OPA
make build-services   # build all Go services into ./bin
make build-web        # build the admin console
# run services from ./bin (see Makefile dev targets), then:
cd web/admin-console && npm run dev
```

## What's actually left (roadmap)

The near-term plan is **stabilize + make deployable**:

1. **Stabilize** — repair frontend lint, stop the false-red Security Scanning
   run, fix the `cmd/backup` CLI panic, build the `/profile` page, refresh
   docs (this file).
2. **Make deployable** — observability backends in the stack, image
   build→push→scan pipeline, complete Helm + Terraform, production runbook
   (`docs/DEPLOYMENT.md`).

Longer term: FCM push wake for agents, and iOS/Windows/macOS/Linux unified
clients (the Go agent already covers desktop today).
