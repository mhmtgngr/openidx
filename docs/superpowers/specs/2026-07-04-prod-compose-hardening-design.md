# Prod-compose hardening (config quick-wins + graceful shutdown + startup health checks)

**Goal:** Close the self-hosted production-readiness gaps in the docker-compose deploy
path, in three independently-shippable PRs. Scope was chosen by the user; **Elasticsearch
xpack.security is explicitly OUT** (deferred back to backlog — it needs ES-client auth
wiring).

**Verified current state (2026-07-04):**
- prod compose **hardcodes `sslmode=disable`** on all 10 DSNs (dev uses `${DATABASE_SSL_MODE:-disable}`).
- DB pool is **hardcoded** `MaxConns=25/MinConns=5` in `internal/common/database/database.go`.
- APISIX admin key is `CHANGE_ME_ADMIN_KEY` in `deployments/docker/apisix/config.yaml`, **not env-driven**; `admin_allow_ip` is broad (`127.0.0.1`, `10/8`, `172.16/12`, `192.168/16`); the admin port is already bound to `127.0.0.1` on the host in prod ✓.
- Only **1 of 13** service mains (`admin-api`) uses the graceful-shutdown helper `internal/server` (`server.New(server.Config{…}).Start()`); the rest do a bare `go tlsutil.ListenAndServe(...)`.
- `ValidateProduction` (`config.go:874`) already asserts VAULT_KEK + OPA devMode-off in prod; there is a `DatabaseSSLMode` config field. `internal/common/health` has readiness handlers.

---

## PR A — config quick-wins

Three low-risk, mostly-config changes.

### A1. DB pool sizing from env
`internal/common/database/database.go` — replace the hardcoded `config.MaxConns = 25` /
`config.MinConns = 5` with env-driven values, defaults unchanged:
- `DB_MAX_CONNS` (default 25), `DB_MIN_CONNS` (default 5), read via a small
  `envInt(name string, def int32)` helper (parse, clamp ≥1, warn+default on bad input).
- Keep `MaxConnLifetime`/`MaxConnIdleTime`/`HealthCheckPeriod` as-is (out of scope).
- No caller signature change (read env inside `NewPostgres`), so all services pick it up.
- Test: `TestPoolSizingFromEnv` — set envs, assert the parsed `pgxpool.Config` reflects them; bad value → default + no panic.

### A2. APISIX admin key from env + tighten allow-ip
`deployments/docker/apisix/config.yaml` — replace both `key: CHANGE_ME_ADMIN_KEY`
occurrences with APISIX's env-var syntax `key: ${{APISIX_ADMIN_KEY}}` (**verify the exact
APISIX 3.8 syntax at impl** — 3.x supports `${{VAR}}`/`${{VAR:=default}}` in config.yaml;
if unsupported on 3.8, fall back to an entrypoint `envsubst` over a `config.yaml.tmpl`).
- Pass `APISIX_ADMIN_KEY` into the `apisix` service `environment:` in `docker-compose.prod.yml`
  (and `.infra.yml` if it runs apisix) from `${APISIX_ADMIN_KEY:?…}`.
- Add `APISIX_ADMIN_KEY=CHANGE_THIS_GENERATE_SECURE_KEY` to `.env.production` (placeholder)
  and a real generated value to `.env` (gitignored).
- Tighten `admin_allow_ip`: drop the broad `172.16/12`+`192.168/16` unless needed; keep
  `127.0.0.1` + the compose network CIDR (`10.0.0.0/8` is docker's default bridge range —
  confirm the actual `openidx-network` subnet and scope to it). **Decision to confirm at
  review:** how tight to make this without breaking inter-container admin calls.

### A3. sslmode=require in prod, with self-signed Postgres TLS (A3-i, chosen)
Make the prod Postgres speak TLS and default the app DSNs to `require`, so a fresh prod
`up` encrypts in transit out of the box.

- **`pg-certgen` one-shot service** (tiny `alpine`+`openssl` image) that, if the cert isn't
  already present, generates a self-signed `server.crt`/`server.key` into a named volume
  `pg_certs` and — **the two gotchas that make Postgres reject the key otherwise** —
  `chown 70:70` (the `postgres` uid in `postgres:16-alpine` is **70**, not 999) and
  `chmod 600 server.key`. Idempotent (skip if files exist); `restart: "no"`.
- **postgres service:** `depends_on: { pg-certgen: { condition: service_completed_successfully } }`,
  mount `pg_certs` at `/certs:ro`, and
  `command: ["postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/certs/server.crt", "-c", "ssl_key_file=/certs/server.key"]`.
- **DSNs:** all 10 in `docker-compose.prod.yml` → `sslmode=${DATABASE_SSL_MODE:-require}`.
  `require` = **encrypt without cert verification**, which self-signed satisfies with **no CA
  distribution** to clients. (`verify-ca`/`verify-full` would need the CA cert mounted into
  every service — deliberately out of scope; `require` is the pragmatic in-transit-encryption
  win.)
- **`.env.production`:** document `DATABASE_SSL_MODE` (default `require`; operators with an
  external managed Postgres set their own mode/certs).
- **`ValidateProduction`:** warn (not hard-fail) if `APP_ENV=production` and the effective
  sslmode resolves to `disable`, so a misconfigured prod is loud.
- Scope: **prod compose only.** `docker-compose.yml`/`.infra.yml` (dev) keep
  `${DATABASE_SSL_MODE:-disable}` — no dev TLS churn.
- **Verify at impl:** bring the prod postgres up with TLS and confirm a client connects with
  `sslmode=require` (`psql "...sslmode=require"` succeeds; server log shows `SSL on`). The
  uid-70/mode-600 combination is the single most likely failure — test it explicitly.

---

### A4. Configurable shutdown timeout (graceful shutdown is ALREADY wired — verified)

**Correction to the initial survey:** all 8 HTTP mains already run through the
`internal/server` graceful helper (`server.New(server.Config{…}).Start()` with DB/Redis/tracer
`Shutdownable`s) — graceful shutdown is DONE. The only gap is that every main hardcodes
`ShutdownTimeout: 30 * time.Second` (9 occurrences across the 8 mains; gateway has 2).

Delta (fold into PR A — it's a config quick-win):
- Add `ShutdownTimeoutSeconds` config (default 30) via viper `setDefaults` + `bindEnvVars`
  (env `SHUTDOWN_TIMEOUT_SECONDS`).
- Replace the 9 hardcoded `30 * time.Second` with
  `time.Duration(cfg.ShutdownTimeoutSeconds) * time.Second`.
- Test: `TestShutdownTimeoutConfig` — default is 30, env override applies.

---

## PR B — startup health checks (OPA / APISIX / Ziti)

Services should verify their hard dependencies are reachable at boot with a **bounded retry**,
and **fail-fast in production** (`APP_ENV=production`) / **warn in dev**, instead of returning
500s on the first request.

- Add a small helper `internal/common/health.WaitForDependency(ctx, name, probe func(context.Context) error, opts{retries, interval})` (or extend the existing health package) that
  logs attempts and returns an error after N bounded retries.
- **OPA** (all services using OPA): probe `GET $OPA_URL/health` at boot. Fail-fast in prod;
  warn in dev. (This complements the existing `ValidateProduction` OPA devMode check.)
- **Ziti** (access-service only): the controller/SDK bootstrap already exists in
  `internal/access/ziti_fabric.go` (`ziti.NewContext`); wrap its initial dial in the bounded
  retry + a clear prod fail-fast, rather than the current best-effort init.
- **APISIX** (access/gateway, whichever manages routes): probe the APISIX admin endpoint at
  boot if the service programs routes; warn-only (route programming already tolerates APISIX
  coming up later — confirm at impl, don't fail-fast if it self-heals).
- **Gate:** the fail-fast must be prod-only and behind a short overall deadline so a dev
  `docker compose up` where OPA lags a few seconds retries rather than crash-loops.

Verification: unit test the retry helper (probe fails N-1 times then succeeds → returns nil;
fails all → error). Manual: start a service with OPA down in prod mode → fails fast with a clear
message; in dev → warns and continues.

---

## Sequencing & risk

**Two PRs** (the initial three collapsed once verification showed graceful shutdown + sslmode
prod-validation are already built):
- **PR A — config hardening:** A1 pool sizing env, A2 APISIX key from env + allow-ip, A3
  Postgres TLS + `sslmode=require`, A4 shutdown timeout configurable. Mostly compose/config + a
  small `database.go`/config-plumbing change.
- **PR B — startup readiness probes:** OPA boot probe (all services) + Ziti prod fail-fast
  (access) + the bounded-retry helper. The main Go change.

A → B (independent, but A is lower-risk; land it first). Each is its own branch/PR with
adversarial review + CI green + per-PR merge go-ahead (branch-protected `main`). All
compose/config-path — **no box deploy** (box runs systemd; these harden the compose deploy
path). If any change touches `ValidateProduction`, update all 7 `cmd/*/main_test.go` fixtures
(the Race job runs `cmd/`) — the known CI gotcha. (A4 adds a config field only, not a
ValidateProduction rule, so it shouldn't trip the fixtures — verify.)

## Out of scope (deferred back to backlog)
- Elasticsearch xpack.security + ES-client auth wiring.
- Bounded graceful-shutdown for non-HTTP workers beyond pool/tracer close.
- Rotating any real secret (the leaked APISIX key is external ops; here we only make the key env-driven).

## Open questions (resolve during implementation, non-blocking)
1. **A3 sslmode:** RESOLVED — A3-i (self-signed Postgres TLS, default `require`).
2. **A2 admin_allow_ip:** RESOLVED — kept `127.0.0.1` + `10.0.0.0/8` + `172.16.0.0/12`,
   dropped only `192.168.0.0/16`. Review caught that rootless podman/netavark uses `10.89.x`
   (within `10/8`), so removing `10/8` would 403 the documented `load-production-routes.sh`
   host→`:9188` workflow. Host port-binding to `127.0.0.1` remains the primary protection.
3. **PR B APISIX probe:** RESOLVED — **no boot probe added.** The `APISIXReconciler`
   (`internal/access/apisix_reconciler.go:58`) already tolerates APISIX being down —
   "PUT route failed (will retry next reconcile)" — so APISIX is NOT a hard boot
   dependency; it self-heals on the next reconcile cycle. A fail-fast probe would wrongly
   crash a service that recovers on its own, and a warn-only probe duplicates the
   reconciler's existing warning. APISIX also sits in FRONT of the services (it calls
   them, not vice-versa at boot), so it isn't a startup dependency.
