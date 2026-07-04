# Elasticsearch security (enable auth on the compose ES + require creds in prod)

**Goal:** The docker-compose Elasticsearch currently runs with `xpack.security.enabled=false`
(open — any network-reachable client has full read/write). Turn on authentication and make the
app connect with credentials, closing the last deferred item from the prod-compose hardening
bundle.

**Verified current state (2026-07-04) — the app side is ALREADY built:**
- `internal/common/config` has `ElasticsearchUsername/Password/TLS/CACert` fields, viper defaults,
  and env bindings (`ELASTICSEARCH_USERNAME`/`ELASTICSEARCH_PASSWORD`).
- `internal/common/database.NewElasticsearchFromConfig` wires `Username`/`Password`/`CACert` into
  `elasticsearch.Config` (auth + TLS), with unit tests.
- **`cmd/audit-service/main.go:102` already calls the auth-aware constructor** passing all four
  fields. Audit is the **only** ES consumer, and ES is best-effort there ("audit works without ES").
- **No `ValidateProduction` ES check exists.** All three compose files set `xpack.security.enabled=false`.

So the remaining work is compose + one validation rule — NOT client plumbing.

## Changes

### 1. Enable ES security in prod compose (`docker-compose.prod.yml`)
- `elasticsearch` service env:
  - `xpack.security.enabled=true`
  - `ELASTIC_PASSWORD=${ELASTIC_PASSWORD:?ELASTIC_PASSWORD required}` (the official image bootstraps
    the built-in `elastic` superuser from this on first init).
  - **`xpack.security.http.ssl.enabled=false`** (see the TLS decision below — baseline is HTTP +
    basic auth over the internal `openidx-network`).
- `audit-service` env: add
  - `ELASTICSEARCH_USERNAME=${ELASTICSEARCH_USERNAME:-elastic}`
  - `ELASTICSEARCH_PASSWORD=${ELASTICSEARCH_PASSWORD:?ELASTICSEARCH_PASSWORD required}`
  (default the username to `elastic`; the operator sets `ELASTICSEARCH_PASSWORD` to the same value
  as `ELASTIC_PASSWORD`, or provisions a dedicated lower-priv role — documented).
- **Dev (`docker-compose.yml`) and `.infra.yml` keep security disabled** — no dev-auth churn
  (scoped like the prod sslmode change).
- **ES 8 note (verify at impl):** with `xpack.security.enabled=true`, ES 8 wants HTTP TLS by
  default; `xpack.security.http.ssl.enabled=false` keeps it HTTP + basic-auth (the auth win without
  cert distribution). Confirm the 8.12 image starts cleanly with security-on + ssl-off single-node
  and that a health check without creds returns 401.

### 2. `ValidateProduction` — require ES creds when ES is configured in prod
In `internal/common/config/config.go`, in the critical-issues path: **if `APP_ENV=production` AND
`ElasticsearchURL != ""`, require `ElasticsearchUsername` and `ElasticsearchPassword` to be set**
(an ES that's configured in prod must be authenticated). If `ElasticsearchURL == ""` (ES unused),
no check. This mirrors the existing VAULT_KEK / sslmode / redis-TLS critical checks. Update the 7
`cmd/*/main_test.go` production-config fixtures if they set an `ElasticsearchURL` without creds
(the Race-job gotcha).

### 3. Env files
- `.env.production`: `ELASTIC_PASSWORD=CHANGE_THIS_GENERATE_SECURE_PASSWORD`,
  `ELASTICSEARCH_USERNAME=elastic`, `ELASTICSEARCH_PASSWORD=CHANGE_THIS_GENERATE_SECURE_PASSWORD`
  (placeholders; document that ES password + the app's ES password must match).
- `.env` (gitignored): real generated values for dev use.

## ES HTTP TLS — RESOLVED: (i) baseline, no HTTP TLS
Enable security + basic auth over HTTP on the private compose network:
`xpack.security.http.ssl.enabled=false`, app uses HTTP basic auth. Closes the "open ES" gap (auth
now required); in-transit encryption relies on network isolation. `ELASTICSEARCH_TLS` stays
`false` and no cert-gen/CACert work. Self-signed ES HTTP TLS (parity with the v1.12.0 PG TLS) is a
documented follow-up, not this pass.

## Testing / verification
- **`docker compose config`** valid for all three files with the new env.
- **Live (throwaway, prod-layered):** bring up the ES service with security on; assert an unauthenticated
  `GET /_cluster/health` → **401**, and the same with `-u elastic:$ELASTIC_PASSWORD` → **200**. Confirm
  the audit-service connects (its startup ES ping succeeds with creds; a bad password → the existing
  "Elasticsearch unavailable" warn, service still boots since ES is best-effort).
- **`ValidateProduction` unit test:** `APP_ENV=production` + `ElasticsearchURL` set + no creds → error;
  with creds → ok; ES URL empty → ok. Add to `internal/common/config` tests; fix `cmd/*/main_test.go`
  fixtures.
- `go build ./...`, `go vet`, `gofmt`, CI Required Checks green.

## Out of scope
- Dedicated least-privilege ES roles / API keys (use the built-in `elastic` user; document that a
  scoped role is a follow-up).
- Dev/infra ES auth (kept open for local convenience).
- ES transport TLS (inter-node) — single-node compose, N/A.

## Sequencing
Single small PR (compose + one validation rule + env + tests). Compose/config-path — the box runs
ES? **Verify at impl** whether the box even runs Elasticsearch; if it does and this changes prod
behavior, a box deploy may apply, but this is primarily a compose-template hardening. Adversarial
review + CI green + per-PR merge go-ahead.
