# OpenIDX Production Hardening Checklist

This is the production-readiness checklist for OpenIDX deployments. It is
**grounded in the code** — every required item below corresponds to a
check in `Config.ValidateProduction()`
(`internal/common/config/config.go`), which runs as a blocking startup
gate. If a knob is misset, the service refuses to start. If a knob is in
the "should-set" section, the service starts but emits a warning in
the logs.

You can use this file in two ways:

1. As a deployment checklist for a production install (single- or
   multi-tenant; the tenant boundary itself is covered by
   [SECURITY-TENANCY.md](./SECURITY-TENANCY.md)).
2. As a reference for what the validator already enforces, so you don't
   have to re-derive it from the source.

For the threat model and the boundaries this list assumes, see
[SECURITY-TENANCY.md](./SECURITY-TENANCY.md).

---

## Hard requirements (validator refuses to start otherwise)

Set `OPENIDX_ENVIRONMENT=production` (or `APP_ENV=production`) to
activate the gate. Every item below is a critical issue the validator
returns as an error — you cannot bring the service up in production
without satisfying it.

### Secrets

| Knob | Required value | Notes |
|---|---|---|
| `ACCESS_SESSION_SECRET` | random ≥ 32 bytes; must not match `change-me` | Used by the access-service for session cookies. |
| `ENCRYPTION_KEY` | random ≥ 32 bytes; must not contain "change" (case-insensitive) | Encrypts sensitive at-rest fields — SMTP credentials, identity-provider client secrets, **and the OAuth signing key**. Losing it costs every outstanding token. |

The validator does **not** check rotation cadence — that's an
operational policy. We recommend 90-day rotation for JWT-signing keys.

### TLS / transport encryption

| Knob | Required value | What goes plaintext if you skip it |
|---|---|---|
| `DATABASE_SSL_MODE` | `require`, `verify-ca`, or `verify-full` (not `disable`) | The entire PostgreSQL wire protocol — including password hashes, MFA secrets, audit events. |
| `REDIS_TLS_ENABLED` | `true` | Session IDs, OAuth login_session bridges, MFA challenge tokens. |
| `TLS_ENABLED` | `true` | Inter-service HTTP between identity / oauth / governance / etc. |
| `REDIS_TLS_SKIP_VERIFY` | **must be `false`** | Setting this to `true` disables Redis server-cert validation, which silently undoes `REDIS_TLS_ENABLED`. Closed in v1.4.0. |
| `ZITI_INSECURE_SKIP_VERIFY` | **must be `false`** | Setting this to `true` disables Ziti controller TLS validation. Closed in v1.4.0. |

Both skip-verify flags exist as dev-loop escape hatches against
self-signed certs in a local docker stack. In production they erase the
trust chain on the link they cover, which is why the validator hard-
refuses them.

### CSRF + CORS + audit stream

| Knob | Required value | Notes |
|---|---|---|
| `CSRF_ENABLED` | `true` | Defaults to `true` since v1.4.0; was `false` before. |
| `CORS_ALLOWED_ORIGINS` | not `*` | Must enumerate the admin-console + first-party SPA origins. |
| `AUDIT_STREAM_ALLOWED_ORIGINS` | not empty, not `*` | WebSocket origin allow-list for the audit-stream endpoint. |

### Debug knobs

| Knob | Required value | Notes |
|---|---|---|
| `DEBUG_OTP_IN_RESPONSE` | `false` | Setting this to `true` returns OTP codes in API responses; **never** acceptable in production. |

### Seeded default admin (DB-backed startup gate, not a config knob)

The v10 seed migration creates `admin@openidx.local` with the published
default password `Admin@123`. `ValidateProduction()` cannot see database
state, so this one is enforced by a separate startup gate:
`identity.EnsureDefaultAdminRotated`
(`internal/identity/default_admin_gate.go`), called from the
identity-service and oauth-service mains after migrations. In production
both services **refuse to start** while an enabled account still
authenticates with that password (a *disabled* seeded admin only warns).
Rotate it via the console (**Users → admin → Set password**) or
`POST /api/v1/identity/users/:id/set-password`.

---

## Soft requirements (validator warns but allows startup)

The same code path also emits warnings for the following. The service
still starts, but every warning should be triaged before declaring an
install production-ready.

- Default values for any of the three secrets above (caught as critical
  if explicitly default; warned if structurally suspicious).
- `cors_allowed_origins is wildcard` (also a critical issue).
- `tls.enabled is false` (also a critical issue).

There is no item below that is "warn-only" — the v1.3.0 / v1.4.0
sweeps promoted everything material to a critical issue.

---

## Hardening that lives outside the config validator

The validator only catches what is expressible as a config flag. The
items below are operational; the project does not check them at
startup.

### Database

- Run PostgreSQL with `log_statement = 'ddl'` so schema changes leave
  a trail.
- Migrations land through `cmd/migrate up`, not auto-migrated by
  application services — this is enforced by the entry-point design;
  no service binary calls `Migrate()` directly.
- Apply pg_hba rules so OpenIDX service accounts can only connect from
  the application subnet, not from the operator workstations.
- Take encrypted backups via the same `internal/backup` path the
  v1.1.0 release wired up (see [disaster-recovery.md](./disaster-recovery.md)).
- Size connection pools against `max_connections`. Each service opens up
  to `DB_MAX_CONNS` (default 10) application connections plus, when
  `DATABASE_BYPASS_URL` is set, up to 8 bypass connections. Before an
  internet-facing pilot raise identity, oauth and access to
  `DB_MAX_CONNS=25` (they carry the sign-in path) and raise Postgres
  `max_connections` to match: 3×25 + 4×10 + 7×8 + headroom ≈ 190, so
  `max_connections=200`. On the reference box `scripts/box-deploy.sh
  preflight` prints the budget and warns when it does not fit.

### Redis

- Pin the Redis version (do not track `:latest`). The session-cleanup
  flake the v1.1.0 / v1.2.0 cycle hit was sensitive to a Redis client
  behavior change.
- Bind Redis to `127.0.0.1` unless remote access is genuinely
  required. See `docs/host-firewall-baseline.md`.
- Use a non-default `REQUIREPASS`. Do not skip this on the assumption
  that the wire is TLS-protected: that assumption fails the moment
  Redis is published on a non-loopback address, and Redis holds
  session and rate-limit state. A leaked DSN is far more dangerous
  when the password is empty.
- Consider Redis Sentinel if a single-node failure would page someone;
  the project already supports it (see the `redis_sentinel_*`
  config fields).

### Rate limiting per account

- Set `RATE_LIMIT_PER_USER=true` on any deployment reachable from the
  internet. The limiter then keys authenticated requests on the user
  instead of the client IP, and additionally counts the credential
  endpoints `/oauth/login` and `/eam/*` against the **submitted username**
  (from the JSON or form body, or `username`/`login_hint` in the query),
  in its own bucket at the `RATE_LIMIT_AUTH_REQUESTS` limit. A password
  spray that rotates source IPs therefore still stops at that limit for
  any one account. The per-IP bucket keeps applying on top.
- The username is normalised (trimmed, lower case) and hashed before it
  becomes a Redis key, so the key never carries it in clear. The bucket
  is only enforced while Redis answers; during an outage the per-IP auth
  tier's fail-closed behaviour applies as before.
- A user who is the target of a spray can be locked out of sign-in for the
  rest of the window. That is the intended trade: account lockout via
  `failed_login_count` still applies separately, and the window is short
  (`RATE_LIMIT_AUTH_WINDOW`, default 60 s).

### Container / runtime

- Run all services as non-root. The Docker images already drop to a
  non-root user; if you re-roll images, preserve this.
- Use read-only root filesystems where possible.
- Set CPU + memory limits — the rate-limit middleware fails closed on
  Redis disconnect (as of PR #82), but an OOM-killed pod still drops
  in-flight requests.

### Networking

- Put the API gateway (APISIX or an equivalent) in front of all
  external traffic. Direct exposure of any service binary is a
  misconfiguration.
- Apply Kubernetes NetworkPolicies (or VPC security groups) to
  restrict service-to-service traffic to known peers.

### Admin console

- The console keeps its access and refresh tokens in `localStorage`.
  The nginx configurations this repository ships send a
  Content-Security-Policy on the console's documents and files that
  allows no inline script and no `eval`, so injected markup cannot run
  and read them (`scripts/check-console-csp.sh` fails CI if one stops).
- If your own web server or CDN serves the built console, send the same
  policy, from `deployments/docker/nginx/admin-console.conf`, on the
  console's documents and files, and only there: the API, OAuth, SAML
  and Guacamole paths answer with pages the console's policy would
  break.

### Observability

- Forward audit events out of the database to a SIEM. The audit table
  is durable but not append-only; assume you'll want offsite copies.
- Set alerts on the brute-force / impossible-travel events the risk
  engine emits.
- Track the JWT key-rotation cadence with a dashboard or a calendar
  reminder; nothing in the code reminds you.

---

## When this file is wrong

The validator is the source of truth. If you add or remove a critical
issue in `Config.ValidateProduction()`, update the corresponding row in
the "Hard requirements" table above in the same PR.

If you discover an item that **should** be enforced at startup but
isn't, the policy is: harden the validator first (defense in depth at
launch), then update this file. Doc-only hardening leaves the next
operator one config-typo away from a regression.
