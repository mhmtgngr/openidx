# Elasticsearch security — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or
> executing-plans). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Enable authentication on the compose Elasticsearch and require ES credentials in
production. Single small PR — the app side (config fields, env bindings, auth-aware client,
audit-service wiring) is already built; this is compose + one `ValidateProduction` rule.

**Spec:** `docs/superpowers/specs/2026-07-04-elasticsearch-security-design.md`
**Decision:** (i) baseline — security + HTTP basic auth, no HTTP TLS.
**Module:** `github.com/openidx/openidx`. **Branch:** `feat/elasticsearch-security` (spec committed).

---

## Task 1 — Enable ES security in prod compose

**File:** `deployments/docker/docker-compose.prod.yml`

- [ ] **Step 1:** In the `elasticsearch` service `environment:` (currently lines ~125-127), replace
  `- xpack.security.enabled=false` with:
```yaml
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=false
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD:?ELASTIC_PASSWORD required - run scripts/generate-secrets.sh}
```
  (Keep `discovery.type=single-node` and `ES_JAVA_OPTS`.)

- [ ] **Step 2:** In the `audit-service` `environment:` (after the `ELASTICSEARCH_URL=` line ~291) add:
```yaml
      - ELASTICSEARCH_USERNAME=${ELASTICSEARCH_USERNAME:-elastic}
      - ELASTICSEARCH_PASSWORD=${ELASTICSEARCH_PASSWORD:?ELASTICSEARCH_PASSWORD required - run scripts/generate-secrets.sh}
```

- [ ] **Step 3:** Leave `docker-compose.yml` and `docker-compose.infra.yml` ES blocks unchanged
  (dev stays security-disabled).

- [ ] **Step 4: Validate**
```bash
cd /home/cmit/openidx/deployments/docker
POSTGRES_PASSWORD=x REDIS_PASSWORD=x OPENIDX_APP_PASSWORD=y APISIX_ADMIN_KEY=z SMTP_USER=x SMTP_PASSWORD=x SCIM_BEARER_TOKEN=x ELASTIC_PASSWORD=espw ELASTICSEARCH_PASSWORD=espw \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml config >/dev/null && echo PROD_OK
```
  Expected `PROD_OK`; confirm the rendered elasticsearch has `xpack.security.enabled=true` and
  audit-service has `ELASTICSEARCH_USERNAME`/`ELASTICSEARCH_PASSWORD`.

- [ ] **Step 5: Commit** `feat(compose): enable Elasticsearch security in prod + wire audit-service creds`.

## Task 2 — `ValidateProduction`: require ES creds when ES is configured

**Files:** `internal/common/config/config.go`, `internal/common/config/config_test.go`

- [ ] **Step 1:** In `ValidateProduction`, in the critical-issues section (right after the Redis-TLS
  critical check, ~line 950), add:
```go
	// Critical: if Elasticsearch is configured in production, it must be authenticated
	// (the compose ES now runs with xpack.security on). No ES URL ⇒ ES unused ⇒ no check.
	if c.ElasticsearchURL != "" && (c.ElasticsearchUsername == "" || c.ElasticsearchPassword == "") {
		criticalIssues = append(criticalIssues,
			"elasticsearch_username and elasticsearch_password must be set in production when elasticsearch_url is configured")
	}
```

- [ ] **Step 2:** Unit test `TestValidateProduction_Elasticsearch` in `config_test.go`:
  - base valid prod Config (copy an existing passing-prod fixture: production env, DATABASE_URL with
    `sslmode=require`, RedisTLSEnabled, TLS.Enabled, CSRFEnabled, non-wildcard CORS, VAULT_KEK set,
    etc. — whatever the existing valid-prod test uses) with `ElasticsearchURL: ""` → `ValidateProduction()` returns nil.
  - same + `ElasticsearchURL: "http://es:9200"`, no creds → returns error mentioning elasticsearch.
  - same + ES URL + `ElasticsearchUsername: "elastic"` + `ElasticsearchPassword: "x"` → nil.
  (Reuse the existing valid-prod Config builder in config_test.go so all the OTHER critical checks
  pass; only vary the ES fields.)

- [ ] **Step 3:** `go test ./internal/common/config/ -run ValidateProduction -v` PASS.

- [ ] **Step 4: Fixture check (the Race-job gotcha).** The `cmd/*/main_test.go` prod-config
  fixtures build `&config.Config{...}` literals that do NOT set `ElasticsearchURL` (verified), so the
  new check skips them. Confirm with `go build ./...` and
  `go test ./cmd/audit-service/ ./cmd/admin-api/ ./cmd/identity-service/ ./cmd/governance-service/ ./cmd/oauth-service/ -run ValidateProduction` — all green. If any fixture sets `ElasticsearchURL`
  without creds, add creds to that fixture.

- [ ] **Step 5: Commit** `feat(config): require ES credentials in production when elasticsearch_url is set`.

## Task 3 — Env files

**Files:** `deployments/docker/.env.production`, `.env`

- [ ] **Step 1:** `.env.production` — add (match the file's placeholder convention):
```
ELASTIC_PASSWORD=CHANGE_THIS_GENERATE_SECURE_PASSWORD
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=CHANGE_THIS_GENERATE_SECURE_PASSWORD
```
  with a comment: `ELASTICSEARCH_PASSWORD` must equal `ELASTIC_PASSWORD` (the app authenticates as
  the built-in `elastic` user), or point `ELASTICSEARCH_USERNAME` at a dedicated role you provision.
- [ ] **Step 2:** `.env` (gitignored) — add real generated values (`openssl rand -base64 24`), with
  `ELASTICSEARCH_PASSWORD` == `ELASTIC_PASSWORD`. Confirm `git ls-files deployments/docker/.env` empty.
- [ ] **Step 3: Commit** `feat(compose): ELASTIC_PASSWORD + ES creds in .env.production`.

## Task 4 — Live verification + open PR

- [ ] **Step 1: Live ES-auth smoke (throwaway, may use docker/podman; dangerouslyDisableSandbox).**
  Bring up ONLY the ES service from the layered prod config on a throwaway project, and prove auth:
```bash
cd /home/cmit/openidx/deployments/docker
export POSTGRES_PASSWORD=x REDIS_PASSWORD=x OPENIDX_APP_PASSWORD=y APISIX_ADMIN_KEY=z SMTP_USER=x SMTP_PASSWORD=x SCIM_BEARER_TOKEN=x ELASTIC_PASSWORD=espw123 ELASTICSEARCH_PASSWORD=espw123
P=esz_$$
docker compose -p $P -f docker-compose.yml -f docker-compose.prod.yml up -d elasticsearch 2>&1 | tail -5
# wait for ES to be ready (security bootstrap takes ~20-40s), then:
docker compose -p $P -f docker-compose.yml -f docker-compose.prod.yml exec -T elasticsearch \
  sh -c 'curl -s -o /dev/null -w "no-auth=%{http_code}\n" http://localhost:9200/_cluster/health; curl -s -o /dev/null -w "auth=%{http_code}\n" -u elastic:$ELASTIC_PASSWORD http://localhost:9200/_cluster/health'
docker compose -p $P -f docker-compose.yml -f docker-compose.prod.yml down -v 2>&1 | tail -3
```
  PASS: `no-auth=401` and `auth=200`. If ES 8.12 refuses to start with security-on + ssl-off
  single-node, read the container log and adjust (may need `xpack.security.enrollment.enabled=false`
  or similar) — report what was needed. If live compose can't run here, at minimum `docker compose
  config` validates and note the manual step.

- [ ] **Step 2:** `go build ./...`, `go vet ./internal/common/config/`, `gofmt -l`; push
  `feat/elasticsearch-security`; `gh pr create` (summarize: enable ES security in prod, wire audit
  creds, ValidateProduction ES check; app-side auth already existed; baseline HTTP basic-auth, TLS
  deferred). Adversarial review; CI green; **stop for per-PR merge go-ahead**.

---

## Self-review notes
- Spec coverage: compose ES security (T1), audit creds (T1), ValidateProduction (T2), env (T3),
  live 401/200 verify (T4). App-side already built (not re-done).
- The ES check is conditional on `ElasticsearchURL != ""`, and prod-config fixtures leave it empty →
  no `main_test.go` fixture churn expected (T2 Step 4 confirms).
- `ELASTICSEARCH_TLS` stays false (baseline decision); no cert-gen.
- Verify-at-impl: ES 8.12 security-on + http.ssl-off single-node startup (T4 Step 1).
