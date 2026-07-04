# Prod-compose hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or
> executing-plans). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Harden the docker-compose prod deploy path in two PRs — config hardening (pool sizing,
APISIX admin key, Postgres TLS, shutdown timeout) and startup readiness probes (OPA/Ziti).

**Spec:** `docs/superpowers/specs/2026-07-04-prod-compose-hardening-design.md`
**Scope note:** graceful shutdown + sslmode prod-validation are ALREADY built (verified). This
plan does the real deltas only. Compose/config-path — **no box deploy**.

**Module path:** `github.com/openidx/openidx`. **Branch per PR from `main`.**

---

# PR A — config hardening  (branch `feat/prod-hardening-config`)

## Task A1 — DB pool sizing from env

**Files:** `internal/common/database/database.go`, `internal/common/database/database_test.go`

- [ ] **Step 1:** In `database.go`, add an env-int helper (package-level):
```go
// envInt32 reads an int32 from env var name, clamped to >= min, falling back to def
// (with a warning on unparseable input). Used for pool sizing knobs.
func envInt32(name string, def, min int32) int32 {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || int32(n) < min {
		return def
	}
	return int32(n)
}
```
Ensure `os` and `strconv` are imported.

- [ ] **Step 2:** Replace the hardcoded pool lines:
```go
	config.MaxConns = 25
	config.MinConns = 5
```
with:
```go
	config.MaxConns = envInt32("DB_MAX_CONNS", 25, 1)
	config.MinConns = envInt32("DB_MIN_CONNS", 5, 0)
```

- [ ] **Step 3:** Test `TestEnvInt32` in `database_test.go`: unset → default; valid → value; bad
  ("abc") → default; below-min → default. (Pure func, no DB needed.)

- [ ] **Step 4:** `go test ./internal/common/database/ -run TestEnvInt32` PASS; `go build ./...`.

- [ ] **Step 5:** Commit `feat(database): DB pool sizing from DB_MAX_CONNS/DB_MIN_CONNS (default 25/5)`.

## Task A2 — APISIX admin key from env + tighten allow-ip

**Files:** `deployments/docker/apisix/config.yaml`, `docker-compose.prod.yml`,
`docker-compose.infra.yml` (if it runs apisix), `.env.production`, `.env`

- [ ] **Step 1: Verify APISIX 3.8 env-var syntax.** APISIX 3.x supports env vars in config.yaml
  as `key: ${{VAR}}`. Confirm against the running image (`apache/apisix:3.8.0-debian`): grep
  APISIX docs/changelog or test that `${{APISIX_ADMIN_KEY}}` renders. If 3.8 does NOT support it,
  fall back to renaming `config.yaml` → `config.yaml.tmpl` and an entrypoint that runs
  `envsubst < config.yaml.tmpl > config.yaml` before apisix starts (document which path you took).

- [ ] **Step 2:** In `apisix/config.yaml`, replace BOTH `key: CHANGE_ME_ADMIN_KEY` with
  `key: ${{APISIX_ADMIN_KEY}}` (the `apisix.admin_key[0]` and `deployment.admin.admin_key[0]`).

- [ ] **Step 3:** Tighten `admin_allow_ip` — first find the compose network subnet:
  `docker network inspect openidx_openidx-network` (or read the `networks:` block). Keep
  `127.0.0.1` + that subnet; drop `172.16.0.0/12` and `192.168.0.0/16` if the network isn't in
  them. If unsure, keep `10.0.0.0/8` (docker default) + `127.0.0.1` and drop the other two.
  Document the final list in a comment.

- [ ] **Step 4:** Add `APISIX_ADMIN_KEY` to the `apisix` service `environment:` in
  `docker-compose.prod.yml` (and `.infra.yml` if it defines apisix) as
  `APISIX_ADMIN_KEY: ${APISIX_ADMIN_KEY:?APISIX_ADMIN_KEY required - run scripts/generate-secrets.sh}`.

- [ ] **Step 5:** `.env.production`: add `APISIX_ADMIN_KEY=CHANGE_THIS_GENERATE_SECURE_KEY`
  (placeholder). `.env` (gitignored): add a real `openssl rand -hex 24` value. Confirm
  `git ls-files deployments/docker/.env` is empty (not tracked).

- [ ] **Step 6:** `docker compose -f docker-compose.prod.yml -f docker-compose.yml config`
  (layered) renders with the env; grep the rendered apisix key resolves. Commit
  `feat(apisix): admin key from APISIX_ADMIN_KEY + tighten admin_allow_ip`.

## Task A3 — self-signed Postgres TLS + sslmode=require (prod)

**Files:** `deployments/docker/docker-compose.prod.yml`, `deployments/docker/pg-certgen.sh` (new),
`.env.production`

- [ ] **Step 1:** Create `deployments/docker/pg-certgen.sh` (mode 0755):
```sh
#!/bin/sh
# Generates a self-signed server cert/key for the compose Postgres into /certs if absent,
# with the ownership+perms Postgres requires (uid 70 = postgres in postgres:16-alpine; key
# must be 0600). Idempotent: skips if server.key already exists.
set -e
CERT_DIR=/certs
if [ -f "$CERT_DIR/server.key" ]; then
  echo "pg-certgen: cert already present, skipping"
  exit 0
fi
apk add --no-cache openssl >/dev/null 2>&1 || true
openssl req -new -x509 -days 3650 -nodes \
  -out "$CERT_DIR/server.crt" -keyout "$CERT_DIR/server.key" \
  -subj "/CN=postgres"
chown 70:70 "$CERT_DIR/server.crt" "$CERT_DIR/server.key"
chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"
echo "pg-certgen: generated self-signed cert (CN=postgres)"
```

- [ ] **Step 2:** In `docker-compose.prod.yml`, add a `pg-certgen` one-shot service + a
  `pg_certs` named volume, and wire postgres to it:
```yaml
  pg-certgen:
    image: alpine:3.20
    container_name: openidx-pg-certgen
    entrypoint: ["sh", "/certgen/pg-certgen.sh"]
    volumes:
      - ./pg-certgen.sh:/certgen/pg-certgen.sh:ro
      - pg_certs:/certs
    restart: "no"
    networks:
      - openidx-network
```
  Under the `postgres` service: add `depends_on: { pg-certgen: { condition: service_completed_successfully } }`
  (keep existing deps), mount `- pg_certs:/certs:ro`, and set
  `command: ["postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/certs/server.crt", "-c", "ssl_key_file=/certs/server.key"]`.
  Add `pg_certs:` to the top-level `volumes:` block.

- [ ] **Step 3:** In `docker-compose.prod.yml`, change all 10 DSNs' `sslmode=disable` →
  `sslmode=${DATABASE_SSL_MODE:-require}` (the 8 app DSNs + migrate + seed). `.env.production`:
  add `DATABASE_SSL_MODE=require` with a comment (operators on managed Postgres set their own).

- [ ] **Step 4 (VERIFY — the uid-70/mode-600 gotcha):** bring the prod postgres + certgen up and
  confirm TLS works:
```bash
cd /home/cmit/openidx/deployments/docker
POSTGRES_PASSWORD=x REDIS_PASSWORD=x OPENIDX_APP_PASSWORD=y APISIX_ADMIN_KEY=z \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d pg-certgen postgres
# wait healthy, then:
docker exec openidx-postgres psql "postgres://openidx:x@127.0.0.1:5432/openidx?sslmode=require" -c "SELECT ssl_is_used();" 2>&1 | tail -5
docker logs openidx-postgres 2>&1 | grep -i ssl | tail -3
docker compose -f docker-compose.yml -f docker-compose.prod.yml down
```
  Expected: connection with `sslmode=require` succeeds and `ssl_is_used()` = t (or the log shows
  SSL enabled). If Postgres refuses the key ("private key file has group or world access" /
  "could not load private key"), fix ownership/perms in pg-certgen.sh (uid 70, 0600) — this is
  the expected failure mode; iterate until it connects. If `docker compose up` is too heavy in
  the environment, at minimum run pg-certgen's cert-gen logic locally and confirm the perms, and
  `docker compose config` validates.

- [ ] **Step 5:** Commit `feat(compose): self-signed Postgres TLS + sslmode=require in prod`.

## Task A4 — configurable shutdown timeout

**Files:** `internal/common/config/config.go`, the 8 `cmd/*/main.go`, a config test

- [ ] **Step 1:** Add to the `Config` struct (near other server fields):
  `ShutdownTimeoutSeconds int `+"`mapstructure:\"shutdown_timeout_seconds\"`"
- [ ] **Step 2:** `setDefaults`: `v.SetDefault("shutdown_timeout_seconds", 30)`. `bindEnvVars`
  `envMappings`: add `"shutdown_timeout_seconds": "SHUTDOWN_TIMEOUT_SECONDS"`.
- [ ] **Step 3:** In each of the 8 mains, replace `ShutdownTimeout: 30 * time.Second` (9
  occurrences — gateway has 2) with
  `ShutdownTimeout: time.Duration(cfg.ShutdownTimeoutSeconds) * time.Second`. Verify `cfg` is in
  scope at each site (it is — the server is built after config load). Guard against a 0 default
  slipping through (if `cfg.ShutdownTimeoutSeconds == 0`, the viper default of 30 applies; but
  add a belt: `if cfg.ShutdownTimeoutSeconds <= 0 { cfg.ShutdownTimeoutSeconds = 30 }` right
  after config load in each main, OR clamp in config validation — pick one, note it).
- [ ] **Step 4:** Test `TestShutdownTimeoutDefault` in config test: default load → 30; with
  `SHUTDOWN_TIMEOUT_SECONDS=10` → 10.
- [ ] **Step 5:** `go build ./...`; `go test ./internal/common/config/`. Commit
  `feat(config): SHUTDOWN_TIMEOUT_SECONDS (default 30) replaces hardcoded 30s in all mains`.

## Task A5 — open PR A, review, CI, merge (with go-ahead)
- [ ] Push `feat/prod-hardening-config`; `gh pr create` (summarize A1–A4; note the scope
  correction — graceful shutdown was already wired, this only makes the timeout configurable);
  adversarial review; CI green; **stop for per-PR merge go-ahead**.

---

# PR B — startup readiness probes  (branch `feat/prod-hardening-readiness`, from `main` after PR A)

## Task B1 — bounded-retry dependency helper + OPA checker

**Files:** `internal/common/health/wait.go` (new), `internal/common/health/wait_test.go`

- [ ] **Step 1:** Create `WaitForDependency`:
```go
package health

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// WaitForDependency probes `probe` up to `attempts` times, `interval` apart, returning nil on
// the first success and the last error if all attempts fail. Logs each retry. Respects ctx.
func WaitForDependency(ctx context.Context, log *zap.Logger, name string, attempts int, interval time.Duration, probe func(context.Context) error) error {
	var last error
	for i := 1; i <= attempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = probe(ctx)
		if last == nil {
			if i > 1 {
				log.Info("dependency ready", zap.String("dependency", name), zap.Int("attempt", i))
			}
			return nil
		}
		log.Warn("dependency not ready, retrying", zap.String("dependency", name), zap.Int("attempt", i), zap.Int("max", attempts), zap.Error(last))
		if i < attempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
	}
	return last
}
```
- [ ] **Step 2:** Test `TestWaitForDependency`: probe fails N-1 then succeeds → nil; always fails
  → returns last error after `attempts`; ctx cancel → returns ctx err. Use a short interval
  (e.g. 1ms) and a counter closure.
- [ ] **Step 3:** `go test ./internal/common/health/ -run TestWaitForDependency` PASS.
- [ ] **Step 4:** Commit `feat(health): WaitForDependency bounded-retry probe helper`.

## Task B2 — OPA boot probe in HTTP services

**Files:** the HTTP `cmd/*/main.go` that use OPA (identity, governance, provisioning, audit,
admin-api, oauth, access, gateway — confirm each references `cfg.OPAURL`/OPA middleware), plus a
tiny OPA probe.

- [ ] **Step 1:** Add an OPA probe helper (in `internal/common/health/wait.go` or an `opa`
  helper): `func ProbeOPA(url string) func(context.Context) error` that does
  `GET {url}/health` and returns error on non-200/transport error (short per-attempt timeout via
  the passed ctx + an `http.Client{Timeout: ...}`).
- [ ] **Step 2:** In each OPA-using main, AFTER config load + logger, BEFORE building/serving the
  router, add:
```go
	if cfg.OPAURL != "" {
		octx, ocancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := health.WaitForDependency(octx, log, "opa", 10, 3*time.Second, health.ProbeOPA(cfg.OPAURL)); err != nil {
			if cfg.Environment == "production" {
				log.Fatal("OPA not reachable at startup", zap.Error(err))
			}
			log.Warn("OPA not reachable at startup; continuing (dev)", zap.Error(err))
		}
		ocancel()
	}
```
  (Confirm the config field name for OPA URL and environment — `cfg.OPAURL` / `cfg.Environment`;
  adjust to actual names. Do it in a shared spot if the mains share a bootstrap, else per-main.)
- [ ] **Step 3:** `go build ./...`. Manual check (one service): point `OPA_URL` at a dead port
  with `APP_ENV=production` → `log.Fatal`; with `APP_ENV=development` → warns + continues.
- [ ] **Step 4:** Commit `feat(startup): OPA readiness probe at boot (fail-fast in prod, warn in dev)`.

## Task B3 — Ziti boot readiness (access service, prod fail-fast)

**Files:** `cmd/access-service/main.go` and/or `internal/access/ziti_fabric.go`

- [ ] **Step 1:** Read the current Ziti bootstrap (`ziti_fabric.go` `ziti.NewContext` init +
  `initialized` flag; it's best-effort with reconnect). Determine where boot init happens and
  whether Ziti is enabled (`cfg.ZitiEnabled`).
- [ ] **Step 2:** When `cfg.ZitiEnabled` and `APP_ENV=production`, wrap the initial context dial
  in `WaitForDependency` (bounded retry) and `log.Fatal` if it never comes up; in dev keep the
  existing best-effort warn+reconnect. Do NOT change the reconnect path. If Ziti init is
  asynchronous/backgrounded today, add the bounded boot check before marking startup complete —
  keep it minimal and preserve the existing reconnect behavior.
- [ ] **Step 3:** `go build ./...`; `go test ./internal/access/ -run Ziti` if such tests exist.
  Commit `feat(startup): Ziti boot readiness fail-fast in prod (access)`.

## Task B4 — APISIX probe decision + open PR B
- [ ] **Step 1:** Read the route-programming path (whichever service programs APISIX routes). If
  it already tolerates/self-heals APISIX being late, make the APISIX boot probe **warn-only**
  (don't fail-fast); if a missing APISIX hard-breaks route setup, fail-fast in prod like OPA.
  Implement accordingly (reuse `WaitForDependency` + an APISIX admin probe). Document the choice.
- [ ] **Step 2:** Push `feat/prod-hardening-readiness`; `gh pr create`; adversarial review; CI
  green; **stop for per-PR merge go-ahead**.

---

## Self-review notes
- Spec coverage: A1 pool sizing, A2 APISIX key+allow-ip, A3 Postgres TLS+sslmode, A4 shutdown
  timeout, B1 helper, B2 OPA, B3 Ziti, B4 APISIX — all mapped. sslmode prod-validation already
  exists (not re-done). Graceful-shutdown wiring already exists (only A4 timeout delta).
- Verify-at-impl flags: APISIX 3.8 `${{}}` env syntax (A2-1), the uid-70/mode-600 Postgres TLS
  gotcha (A3-4), exact config field names for OPA URL/environment (B2), Ziti boot structure (B3),
  APISIX self-heal behavior (B4). Each task says to confirm before asserting.
- No `ValidateProduction` rule changes (A4 is a plain config field) → the 7 `cmd/*/main_test.go`
  fixtures shouldn't need updating; verify the Race job stays green.
