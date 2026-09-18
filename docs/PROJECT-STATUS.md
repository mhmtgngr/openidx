# OpenIDX Project Status

**Last refreshed: 2026-09-18** against `main`. This file is a one-page
snapshot; the documents it points to are the authority, and if this page and
the code disagree, the code is right and this page has rotted.

| Question | Read |
|---|---|
| How do I install, verify, upgrade and operate it | [`docs/deployment/operator-guide.md`](./docs/deployment/operator-guide.md) |
| What is enforced, what is proved by CI, what is left (P-numbered programme) | [`PROJECT-READINESS-GUIDE.md`](./PROJECT-READINESS-GUIDE.md) |
| The global-scale (cell) plan and its closing table of open items | [`plans/2026-09-13-global-scale-cell-architecture-plan.md`](./plans/2026-09-13-global-scale-cell-architecture-plan.md) |
| Cutting a release | [`RELEASING.md`](./RELEASING.md) |

## Snapshot

| Area | State |
|---|---|
| Release | `VERSION` 1.35.0 (2026-09-10, signed; see `evidence/release-gate.md`). The `[Unreleased]` section of `CHANGELOG.md` holds the cell work merged since. |
| Services | Ten request-serving or worker binaries under `cmd/` plus `migrate`, `backup`, `rekey`, `openidx` (developer CLI). All on PostgreSQL with FORCE row-level security, CI-gated by `tools/orgscope`. |
| Chart | `deployments/kubernetes/helm/openidx`: installed live on kind on every chart change, in the plain shape (`kind-install`) and the cell shape (`kind-cell`: transaction pooler, local RLS, streaming replica, identity plane split, cell guard). Network policies, PDBs, HPA/KEDA, PrometheusRule, backup CronJob, edge CIDR sync. |
| Terraform | AWS root (EKS, RDS, ElastiCache, OpenZiti) and Azure root (AKS, Flexible Server, Redis, Key Vault); fmt and validate in CI, never applied from this repository. No cell module yet. |
| Observability | Prometheus collectors and OpenTelemetry in the services; 26 chart alert rules; Compose stack ships Prometheus, Grafana, Alertmanager, Loki, OTel collector. |
| Console | `web/admin-console`: 108 pages, 163 unit test files, 50 Playwright specs, English and Turkish. |
| Guards | `scripts/run-ci-guards.sh` runs 64 gating guard invocations; `tools/deadconfig`, `tools/deadservice`, `tools/testmatrix`, `tools/routereach`, `tools/contractcheck`, `scripts/check-docs-drift.sh`. |

## What is left

Four classes, each named with its evidence in the two documents above:

1. **Needs a real cell in a real cloud account**: load and failover
   measurement, the k6 game day, the live half of the chaos and DR drills,
   the Terraform cell module, per-cell key management, the first real
   release wave, the operator controls' first dated rows.
2. **Needs a product decision**: may one external account link to a user in
   two tenants (the last two tables outside the tenant belt); the per-tenant
   enrolment quota; the first public region and cell size; whether the
   event bus becomes a hard dependency.
3. **Documentation that rots**: the guard `scripts/check-docs-drift.sh`
   keeps paths honest; claims are corrected as they are found (this page
   itself was the stale one until 2026-09-18).
4. **Product shape**: NOTICE, SUPPORT and DCO files; a commercial substrate
   (plan, quota, self-signup) if one is wanted; SDKs and an admin CLI;
   connector catalogue for outbound provisioning; production code-signing
   identities for the desktop and mobile clients.
