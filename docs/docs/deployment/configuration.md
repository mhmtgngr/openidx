# Configuration Reference

Every environment variable on this page is bound by
`internal/common/config.bindEnvVars` or read directly by a service, and
`tools/deadconfig` fails the build if this page names one that is not. That gate
exists because this page once listed 63 settings the product had no binding for
— `PASSWORD_MIN_LENGTH`, the four `OAUTH_*_TTL`, `RATE_LIMIT_RPS`,
`MAX_SESSIONS_PER_USER` and the rest — so an operator could set them, see
nothing change, and have no way to tell. One was even misspelled
(`MFA_WEBARUTHN_ENABLED`), which is the clearest possible evidence that nobody
had ever tried it.

Settings that are real but are **not** environment variables are listed under
[Where the other settings live](#where-the-other-settings-live) rather than
omitted, because "it isn't here" is what sent people looking for an environment
variable in the first place.

## How configuration is loaded

1. **Defaults** compiled into `internal/common/config`.
2. **A YAML file** named `config.yaml`, looked for in `.`, `./configs` and
   `/etc/openidx`. Optional; there is no `--config` flag.
3. **Environment variables**, which win over both. Every key also has an
   automatic `OPENIDX_`-prefixed spelling: `push_mfa.enabled` is
   `OPENIDX_PUSH_MFA_ENABLED`.

A setting this codebase once accepted and no longer reads is reported at startup
in every environment, with what to set instead — see
`internal/common/config/retired.go`.

## Environment variables

### Core

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `APP_ENV` | string | `development` | `development`, `staging` or `production`. Production turns on `ValidateProduction`, which refuses to start on an insecure setting. |
| `LOG_LEVEL` | string | `info` | `debug`, `info`, `warn`, `error`. Also settable as `log_level` in the config file. |
| `PORT` | int | per service | Listening port. |
| `SERVICE_BIND_ADDR` | string | `0.0.0.0` | Address to bind. Refused for a service under a `DARK_MODE_*` tier, which must be reachable only over the overlay. |
| `SHUTDOWN_TIMEOUT_SECONDS` | int | `30` | Graceful-drain window on SIGTERM. |
| `PUBLIC_BASE_URL` | url | - | Externally reachable base URL, used to build links in email and push. |

The log format is not configurable: JSON in production, human-readable
elsewhere. There is no `SERVICE_NAME` — each binary passes its own.

### Database

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_URL` | string | - | PostgreSQL DSN (required). |
| `DATABASE_READ_URL` | string | - | Optional read-replica DSN for read-heavy queries. |
| `DATABASE_SSL_MODE` | string | `disable` | `disable`, `require`, `verify-ca`, `verify-full`. Production refuses anything below `require`. |
| `DATABASE_SSL_ROOT_CERT` | path | - | CA bundle for `verify-ca` / `verify-full`. |
| `DATABASE_SSL_CERT` | path | - | Client certificate for mTLS to PostgreSQL. |
| `DATABASE_SSL_KEY` | path | - | Client key for mTLS to PostgreSQL. |

Pool sizing is part of the DSN, not a separate variable — pgx reads
`pool_max_conns`, `pool_min_conns` and `pool_max_conn_lifetime` from the query
string:

```
postgres://user:password@host:5432/openidx?sslmode=verify-full&pool_max_conns=25&pool_min_conns=5
```

### Redis

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `REDIS_URL` | string | - | Redis URL (required). Carries the password and database number: `redis://:password@host:6379/0`. |
| `REDIS_TLS_ENABLED` | bool | `false` | Connect with TLS. Production warns when this is off. |
| `REDIS_TLS_CA_CERT` | path | - | CA bundle for the Redis TLS connection. |
| `REDIS_TLS_CERT` | path | - | Client certificate for mTLS to Redis. |
| `REDIS_TLS_KEY` | path | - | Client key for mTLS to Redis. |
| `REDIS_TLS_SKIP_VERIFY` | bool | `false` | Never in production. |
| `REDIS_SENTINEL_ENABLED` | bool | `false` | Resolve the master through Sentinel. |
| `REDIS_SENTINEL_ADDRESSES` | strings | - | Comma-separated Sentinel addresses. |
| `REDIS_SENTINEL_MASTER_NAME` | string | `mymaster` | Sentinel master name. |
| `REDIS_SENTINEL_PASSWORD` | string | - | Sentinel password, if the Sentinels require one. |

### Elasticsearch (audit search)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ELASTICSEARCH_URL` | string | - | Elasticsearch URL. Audit search is disabled when empty; the audit trail itself is in PostgreSQL and does not depend on it. |
| `ELASTICSEARCH_USERNAME` | string | - | Basic-auth user. |
| `ELASTICSEARCH_PASSWORD` | string | - | Basic-auth password. |
| `ELASTICSEARCH_TLS` | bool | `false` | Connect with TLS. |
| `ELASTICSEARCH_CA_CERT` | path | - | CA bundle for the Elasticsearch connection. |

### OAuth / OIDC

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OAUTH_ISSUER` | url | - | Token issuer, and the base of the discovery document. |
| `OAUTH_JWKS_URL` | url | `<OAUTH_ISSUER>/.well-known/jwks.json` | Where other services fetch the signing keys. |
| `OAUTH_LOGIN_URL` | url | `<OAUTH_ISSUER>/login` | Where `/oauth/authorize` sends a browser to sign in. Set it when the console is served from a different origin than the issuer; the reference compose stack is exactly that case. Must be absolute. |
| `DCR_ALLOW_OPEN_REGISTRATION` | bool | `false` | Allow unauthenticated dynamic client registration. |
| `DCR_INITIAL_ACCESS_TOKEN` | string | - | Bearer required for dynamic client registration when open registration is off. |
| `SSF_RECEIVER_ISSUER` | string | - | Expected issuer for inbound SSF/CAEP events. |
| `SSF_RECEIVER_JWKS_URL` | url | - | JWKS for verifying inbound SSF/CAEP events. |

**Token lifetimes are per client, not per deployment.** Access, refresh and ID
token lifetimes are properties of the OAuth client, set on the application in
the admin console (Applications → the app → Token settings). There is no
`OAUTH_ACCESS_TOKEN_TTL`.

**The signing key is not an environment variable either.** OpenIDX signs every
token RS256 with a rotatable key stored in `oauth_signing_keys`, encrypted at
rest with `ENCRYPTION_KEY`, and published through JWKS. The shared middleware
refuses any other algorithm by name, so there is no HMAC secret to set. Rotate
with `POST /api/v1/admin/oauth/signing-keys/rotate`.

### Encryption and secrets

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ENCRYPTION_KEY` | string | - | 32-byte key protecting encrypted-at-rest fields: the OAuth signing key, identity-provider client secrets, SMTP credentials. Required in production. Losing it costs every outstanding token. |
| `ENCRYPTION_KEYS` | string | - | Comma-separated `id:key` pairs for staged rotation. |
| `ENCRYPTION_ACTIVE_KEK_ID` | string | - | Which key in `ENCRYPTION_KEYS` new writes use. |
| `ACCESS_SESSION_SECRET` | string | - | Signs the access proxy's session cookies. Required in production. |
| `AUDIT_CHAIN_SECRET` | string | - | HMAC key the audit hash chain seals events with. Deliberately separate from every other secret: whoever can write the audit database must not hold the key that would let them re-seal a doctored trail. Required in production. |
| `AUDIT_CHAIN_INTERVAL` | duration | `1m` | How often the sealer sweeps for unsealed rows. |
| `VAULT_KEK` | string | - | Key-encryption key for the PAM credential vault. Governance, admin-api and access-service refuse to start without a vault keyring, by design. |
| `VAULT_KEKS` | string | - | Comma-separated `id:key` pairs for vault KEK rotation. |
| `VAULT_ACTIVE_KEK_ID` | string | - | Which vault KEK new writes use. |
| `VAULT_REVEAL_LEASE_TTL_SECONDS` | int | `300` | How long a revealed credential stays checked out. |
| `BAO_ADDR` | url | - | OpenBao / Vault address, when the KEK is held externally. |
| `BAO_TOKEN` | string | - | Token for that server. |
| `BAO_KEK_PATH` | string | - | Path to the KEK secret. |
| `BAO_CACERT` | path | - | CA bundle for that server. |
| `INTERNAL_SERVICE_TOKEN` | string | - | Shared bearer for service-to-service calls that do not carry a user token. |

### Network security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | strings | `*` | Comma-separated origins. Production refuses `*`. Methods and headers are fixed by the middleware and are not configurable. |
| `AUDIT_STREAM_ALLOWED_ORIGINS` | strings | localhost | Origins allowed to open the audit-event WebSocket. Guards against cross-site WebSocket hijacking; production requires an explicit list. |
| `CSRF_ENABLED` | bool | `false` | Enable CSRF protection. Production requires `true`. There is no separate CSRF secret — the token is derived. |
| `CSRF_TRUSTED_DOMAIN` | string | - | Parent domain trusted for CSRF when the console and API differ by subdomain. |
| `OIDX_TRUSTED_PROXIES` | strings | - | Proxies whose `X-Forwarded-For` is believed. Empty means trust none, so the client IP is the peer address. |
| `TLS_ENABLED` | bool | `false` | Serve HTTPS directly rather than behind a terminating proxy. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` / `TLS_CA_FILE` | path | - | Certificate, key and CA for that listener. |

### Rate limiting

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ENABLE_RATE_LIMIT` | bool | `true` | Mount the distributed rate limiter. |
| `RATE_LIMIT_REQUESTS` | int | `100` | Requests allowed per window on ordinary routes. |
| `RATE_LIMIT_WINDOW` | int | `60` | Window in seconds. |
| `RATE_LIMIT_AUTH_REQUESTS` | int | `20` | Requests allowed per window on authentication routes, which fail **closed** when Redis is unreachable. |
| `RATE_LIMIT_AUTH_WINDOW` | int | `60` | Window in seconds for authentication routes. |
| `RATE_LIMIT_PER_USER` | bool | `false` | Key the limiter on the authenticated user rather than the client IP. |

### Enforcement gates

Each of these decides whether a control that is *displayed* is also *enforced*.
`ValidateProduction` reports the ones still in report mode at startup, and the
ops cockpit shows them, so a GA install cannot pass the production gate without
seeing which gates are open.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ACCESS_ASSIGNMENT_ENFORCE` | bool | `false` | Deny an unassigned user at `/oauth/authorize` and at the access proxy, rather than logging the decision. |
| `ABAC_ENFORCE` | string | `off` | `off`, `observe` or `enforce` for attribute-based policies at the same two enforcement points. |
| `ENABLE_OPA_AUTHZ` | bool | `false` | Put OPA in the request path. Fail-closed in production. |
| `PAM_SESSION_RISK_GATE` | string | `off` | `off`, `observe` or `enforce` for the PAM session risk score. |
| `PAM_SESSION_RISK_THRESHOLD` | int | `70` | Score at or above which the gate bites. |
| `PAM_SSH_REQUIRE_HOST_KEY` | bool | `false` | Refuse an SSH session to a host whose key is not pinned. |
| `PAM_REQUIRE_ZTNA` | string | `off` | `off`, `observe` or `enforce` for whether a privileged session may reach its target off the overlay. In `enforce`, a launch is refused unless the entry's `reach_mode` is `ziti`, and a website entry — which returns a raw URL and brokers nothing — is refused outright. `observe` refuses nothing and audits every launch that `enforce` would refuse, so the affected entries can be counted first. **`enforce` also refuses to start** unless `GUACAMOLE_ZITI_PUBLIC_URL` is set and differs from `GUACAMOLE_PUBLIC_URL`: the broker&rarr;target leg is this service's decision, but the user&rarr;broker leg is closed by the overlay broker being published at an overlay address and nowhere else, and that is the configuration it needs. The mode is reported to the launcher as `require_ztna` on `GET /pam/broker/status`, so the console disables Connect on an entry `enforce` would refuse instead of firing a request that returns `403`; what is reported is what the service will do, so an unrecognised value reads `off` there too. |
| `POSTURE_DEVICE_TRUST_GATE` | string | `off` | `off`, `observe` or `enforce` for the device-trust posture check. |
| `STEPUP_GATE` | string | `off` | `off`, `observe` or `enforce` for MFA freshness. In `enforce`, a PAM launch or credential reveal, and any write made with admin authority, is refused with `step_up_required` when the session's last verified second factor is older than the window. Reads are never gated; API keys, service accounts and client-credentials tokens are never gated. |
| `STEPUP_MAX_AGE` | duration | `15m` | The freshness window `STEPUP_GATE` applies. The console's Security &rarr; re-authentication interval (`security.reauth_interval`, in seconds) overrides it when set above zero. |
| `SHOW_ALL_APPS_WHEN_UNASSIGNED` | bool | `false` | Show every application to a user with no assignments. A convenience for a fresh install; it is not an authorization decision. |
| `DEV_ADMIN_BYPASS` | bool | `false` | Development-only administrator bypass. Production refuses to start with it on. |
| `ACCESS_API_REQUIRE_AUTH` | bool | `false` | Require authentication on the access API. `false` yields soft auth in development. |
| `ADMIN_API_REQUIRE_AUTH` | bool | `false` | Require authentication on the admin API. `false` yields soft auth in development. |
| `DEBUG_OTP_IN_RESPONSE` | bool | `false` | Return OTP codes in API responses. Development only, and production refuses to start with it on. |

### OPA

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OPA_URL` | string | - | OPA server URL. The decision path is fixed at `/v1/data/openidx/authz`. |
| `OPA_DECISION_CACHE_TTL_SECONDS` | int | `5` | How long a decision is cached. `0` disables caching. |

There is no `OPA_DEV_MODE`. When OPA is unreachable the middleware fails closed
in production and open elsewhere, which is a property of `APP_ENV` rather than a
switch of its own.

### Multi-factor authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `WEBAUTHN_RP_ID` | string | `localhost` | WebAuthn relying-party ID. Must be the registrable domain, or browsers refuse registration. |
| `WEBAUTHN_RP_ORIGINS` | strings | localhost | Origins allowed to complete a WebAuthn ceremony. |
| `WEBAUTHN_IOS_APP_ID` | string | - | Apple app id, for `/.well-known/apple-app-site-association`. |
| `WEBAUTHN_ANDROID_PACKAGE` | string | - | Android package name, for `/.well-known/assetlinks.json`. |
| `WEBAUTHN_ANDROID_SHA256` | string | - | Android signing-certificate fingerprint for the same file. |
| `PUSH_MFA_ENABLED` | bool | `true` | Push MFA. Off refuses enrolment and refuses to raise a challenge. |
| `PUSH_MFA_CHALLENGE_TIMEOUT` | int | `60` | Seconds a push challenge stays answerable. |
| `PUSH_MFA_FCM_CREDENTIALS_FILE` | path | - | Firebase service-account JSON for FCM HTTP v1 (Android and web push). |
| `PUSH_MFA_FCM_PROJECT_ID` | string | - | Firebase project. Defaults to the `project_id` in the credentials file. |
| `PUSH_MFA_APNS_KEY_ID` / `PUSH_MFA_APNS_TEAM_ID` / `PUSH_MFA_APNS_KEY_PATH` / `PUSH_MFA_APNS_BUNDLE_ID` | string | - | APNs token authentication for iOS push. |
| `PUSH_MFA_APNS_PRODUCTION` | bool | `false` | Use the production APNs host rather than the sandbox. |
| `NTFY_BASE_URL` | url | - | Self-hosted ntfy server for push, the transport the OpenIDX mobile client uses. |
| `NTFY_TOKEN` | string | - | Bearer for that server. |
| `NTFY_TOPIC_SECRET` | string | - | Secret from which per-device topics are derived. |
| `ADAPTIVE_MFA_ENABLED` | bool | `true` | Step up based on the login risk score. |
| `SMS_ENABLED` | bool | `false` | Offer the SMS OTP factor. |
| `SMS_PROVIDER` | string | `mock` | `twilio`, `aws_sns`, `netgsm`, `ileti_merkezi`, `verimor`, `turkcell`, `vodafone`, `turk_telekom`, `mutlucell`, `webhook`, or `mock`. **`mock` counts as not configured**: the factor refuses rather than reporting a code it never sent, and production refuses to start with `SMS_ENABLED=true` and `SMS_PROVIDER=mock`. |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_FROM_NUMBER` | string | - | Twilio credentials. |
| `SMS_WEBHOOK_URL` / `SMS_WEBHOOK_API_KEY` | string | - | Generic webhook provider. |
| `AWS_REGION` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | string | - | SNS credentials; omitted, the SDK's own chain applies. |

The Turkish gateways take `NETGSM_*`, `ILETIMERKEZI_*`, `VERIMOR_*`,
`TURKCELL_SMS_*`, `VODAFONE_SMS_*`, `TURKTELEKOM_SMS_*` and `MUTLUCELL_*`
credentials; see `internal/common/config/config.go` for the exact names.

TOTP parameters are fixed at the RFC 6238 defaults an authenticator app expects
— 6 digits, a 30-second period, SHA-1 — and are not configurable.

### Email

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMTP_HOST` | string | - | SMTP server. Email is disabled when empty. |
| `SMTP_PORT` | int | `587` | SMTP port. |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | string | - | SMTP credentials; the password is encrypted at rest when stored through the console. |
| `SMTP_FROM` | string | - | From address. |

TLS verification is not optional and there is no from-name override; the display
name comes from the email template.

### Observability

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `TRACING_ENABLED` | bool | `false` | Emit OpenTelemetry traces. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | string | - | OTLP collector. Standard OpenTelemetry variable, read by the SDK. |
| `OTEL_SERVICE_NAME` | string | per service | Service name on the spans. |
| `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG` | string | - | Sampler and its argument, e.g. `traceidratio` and `0.1`. |
| `OTEL_RESOURCE_ATTRIBUTES` | string | - | Extra resource attributes. |

Prometheus metrics are always served at `/metrics` and health at `/health`;
neither has a switch, so there is nothing to turn off by accident.

### Audit forwarding

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AUDIT_SIEM_ENABLED` | bool | `false` | Forward audit events to a SIEM. |
| `AUDIT_SIEM_ENDPOINT` | string | - | Syslog or HTTP endpoint. |
| `AUDIT_SIEM_FORMAT` | string | `json` | Wire format. |
| `AUDIT_SIEM_TOKEN` | string | - | Bearer for an HTTP collector. |
| `AUDIT_SIEM_TLS` | bool | `false` | Connect with TLS. |
| `AUDIT_SIEM_INSECURE_SKIP_VERIFY` | bool | `false` | Never in production. |
| `AUDIT_SIEM_BATCH_SIZE` | int | `100` | Events per batch. |
| `AUDIT_SIEM_POLL_SECONDS` | int | `10` | How often the forwarder sweeps. |
| `AUDIT_SIEM_HOSTNAME` | string | - | Hostname stamped on forwarded events. |

Retention and archival are configured in the admin console under Audit →
Archival, not here: they are per organization.

### Backups

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `BACKUP_DIR` | path | - | Where `cmd/backup` writes dumps. |
| `BACKUP_RETENTION_COUNT` | int | `7` | How many dumps to keep. |
| `BACKUP_ENCRYPTION_KEY` | string | - | Encrypts the dump at rest. |
| `BACKUP_S3_BUCKET` / `BACKUP_S3_ENDPOINT` / `BACKUP_S3_REGION` / `BACKUP_S3_ACCESS_KEY` / `BACKUP_S3_SECRET_KEY` | string | - | Object storage for off-host copies. |

### Networking overlay (OpenZiti, BrowZer, APISIX)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ZITI_ENABLED` | bool | `false` | Manage an OpenZiti overlay. |
| `ZITI_CTRL_URL` / `ZITI_CTRL_URLS` | url | - | Controller address, or a comma-separated set for HA. |
| `ZITI_ADMIN_USER` / `ZITI_ADMIN_PASSWORD` | string | - | Controller credentials. |
| `ZITI_IDENTITY_DIR` | path | `/ziti` | Where enrolled identities are written. |
| `ZITI_INSECURE_SKIP_VERIFY` | bool | `false` | Never in production. |
| `ZITI_PER_ORG_ATTRIBUTES` | bool | `false` | Scope overlay attributes per organization. |
| `APISIX_ADMIN_URL` | string | `http://localhost:9180` | APISIX admin API. |
| `APISIX_ADMIN_KEY` | string | - | APISIX admin key. |
| `APISIX_EDGE_ENABLED` | bool | `false` | Reconcile edge routes into APISIX. |
| `APISIX_CONFIG_PATH` | path | - | APISIX config file the bootstrapper writes. |
| `BROWZER_ENABLED` | bool | `false` | Manage a BrowZer bootstrapper for clientless access. |
| `BROWZER_CLIENT_ID` | string | `browzer-client` | OAuth client BrowZer uses. |

`ZITI_*`, `BROWZER_*` and `GUACAMOLE_*` have more variables than are useful to
list here; `internal/common/config/config.go` carries the complete set with a
comment apiece.

### Multi-tenancy

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DEFAULT_ORG_ID` | uuid | - | Organization a request with no tenant signal belongs to. |
| `DEFAULT_ORG_FALLBACK` | bool | `false` | Use it, rather than refusing a request with no tenant signal. |
| `TENANT_BASE_DOMAIN` | string | - | Base domain from which a subdomain identifies the tenant. |

### Access Requests

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ACCESS_REQUEST_MAX_DURATION_HOURS` | int | `2160` (90 days) | Longest window a time-bound access request may elevate somebody for |

A request over the ceiling is **refused**, with the maximum named in the error,
and never silently shortened — an approver reading "30 days" must not be
approving something else.

The default is the longest window the product documents (`90d`), so it rejects
nothing the console can produce: the request form offers 4h, 8h, 1d, 3d, 7d,
30d and 90d, and nothing longer. It exists for the API, which previously
accepted any value at all — including one large enough to overflow and land in
the past.

Set it lower where standing access should be shorter:

```bash
# Nothing longer than a working day.
export ACCESS_REQUEST_MAX_DURATION_HOURS=8
```

Whether a vault credential, a role and an application assignment should have
*different* ceilings is an open product decision; today one bound applies to
all three.

### Endpoint Agent Downloads

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AGENT_DOWNLOADS_DIR` | string | `deployments/downloads` | Directory of per-OS agent installers served at `/downloads/<file>` |

`GET /downloads/agent-manifest.json` lists what that directory actually holds,
one entry per platform with a URL and a SHA-256. The end-user **Add a device**
wizard reads it: a platform with an entry gets a download button, a platform
without one is told the installer comes from its administrator. Nothing is
advertised that is not on disk.

The extension decides the platform — `.msi`/`.exe` → Windows, `.pkg`/`.dmg` →
macOS, `.deb`/`.rpm` → Linux, `.apk` → Android — so populating it is a copy:

```bash
# Every artifact from an agent release, into the directory the service serves.
TAG=agent-v1.2.0
mkdir -p /var/lib/openidx/downloads
gh release download "$TAG" --repo <owner>/<repo> \
  --pattern 'OpenIDX-*.msi' --pattern '*.deb' --pattern '*.rpm' \
  --dir /var/lib/openidx/downloads

# Point access-service at it.
export AGENT_DOWNLOADS_DIR=/var/lib/openidx/downloads
```

The `agent-v*` release publishes the Windows MSI plus `.deb` and `.rpm` for
amd64 and arm64. There is no macOS or iOS client to download; the wizard says
so rather than sending users to ask for one.


## Where the other settings live

These are real settings. They are not environment variables, and this section
exists because looking for one and not finding it is what made the previous
version of this page grow rows the product never had.

| Setting | Where it lives |
|---|---|
| Password policy — minimum length, character classes, history, expiry | Admin console → Settings → Security. Stored per organization and enforced by `POST /api/v1/admin/validate-password`. |
| Session idle timeout, absolute timeout, concurrent-session limit | Admin console → Settings → Security. Read by the session policy on every refresh, and by the console's idle-timeout dialog. |
| Access, refresh and ID token lifetimes | Per OAuth client, on the application in Applications → the app. |
| OTP code length, lifetime, attempt ceiling | Admin console → Settings → SMS. Applied without a restart by the identity service's config watcher. |
| Certification campaign duration and reminders | Per campaign, when the campaign is created. |
| Directory sync interval and scope | Per directory, in Directories → the directory. |
| Audit retention and archival | Admin console → Audit → Archival. Per organization. |
| Database pool sizing | The `DATABASE_URL` query string (`pool_max_conns`, `pool_min_conns`, `pool_max_conn_lifetime`). |
| Redis password and database number | The `REDIS_URL` itself. |
| OAuth signing key | Generated on first start into `oauth_signing_keys`, encrypted with `ENCRYPTION_KEY`. Rotate with `POST /api/v1/admin/oauth/signing-keys/rotate`. |

## Configuration file

The same keys can be set in `config.yaml`, found in `.`, `./configs` or
`/etc/openidx`. Nested keys use their dotted form. Environment variables win
over the file.

```yaml
environment: production
log_level: info
database_url: postgres://openidx:password@localhost:5432/openidx?sslmode=verify-full
redis_url: redis://:password@localhost:6379/0

oauth_issuer: https://openidx.example.com
cors_allowed_origins: https://app.example.com,https://admin.example.com
csrf_enabled: true

enable_rate_limit: true
rate_limit_requests: 100
rate_limit_window: 60

access_assignment_enforce: true
abac_enforce: enforce

webauthn:
  rp_id: example.com
  rp_origins: https://app.example.com

push_mfa:
  enabled: true
  fcm_credentials_file: /etc/openidx/firebase-service-account.json
```

There is no interpolation: `${SOMETHING}` in a config file is the literal
string, not the environment variable. Use environment variables directly for
anything that varies per deployment.

## Secrets management

### HashiCorp Vault / OpenBao

```bash
export VAULT_ADDR="https://vault.example.com"
vault login -method=oidc

vault kv put secret/openidx/database url="postgres://..."
vault kv put secret/openidx/encryption key="$(openssl rand -hex 16)"

export DATABASE_URL=$(vault kv get -field=url secret/openidx/database)
export ENCRYPTION_KEY=$(vault kv get -field=key secret/openidx/encryption)
```

The vault KEK can also be held in OpenBao directly rather than passed as
`VAULT_KEK` — set `BAO_ADDR`, `BAO_TOKEN` and `BAO_KEK_PATH`.

### Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: openidx-secrets
type: Opaque
stringData:
  DATABASE_URL: postgres://openidx:password@postgres:5432/openidx?sslmode=require
  REDIS_URL: redis://:password@redis:6379/0
  ENCRYPTION_KEY: <32 bytes>
  ACCESS_SESSION_SECRET: <32 bytes>
  AUDIT_CHAIN_SECRET: <32 bytes>
  VAULT_KEK: <32 bytes>
```

The Helm chart mounts the whole secret with `envFrom`, so every key in it
reaches every service.

## Startup validation

`APP_ENV=production` turns on `ValidateProduction`, which **refuses to start**
on any of:

- a missing or placeholder `ENCRYPTION_KEY`, `ACCESS_SESSION_SECRET`,
  `AUDIT_CHAIN_SECRET` or `VAULT_KEK`;
- `CORS_ALLOWED_ORIGINS=*`;
- `CSRF_ENABLED=false`;
- `DATABASE_SSL_MODE=disable`;
- the default administrator password still in place;
- `DEV_ADMIN_BYPASS=true` or `DEBUG_OTP_IN_RESPONSE=true`;
- `SMS_ENABLED=true` with `SMS_PROVIDER=mock`.

It also **reports** every enforcement gate still in report mode, so the gap
between what the console displays and what the product enforces is visible at
startup rather than discovered later.

## Production checklist

- [ ] `APP_ENV=production`
- [ ] Secrets generated with `scripts/generate-secrets.sh`, not by hand
- [ ] `DATABASE_SSL_MODE=verify-full` and `REDIS_TLS_ENABLED=true`
- [ ] `CORS_ALLOWED_ORIGINS` and `AUDIT_STREAM_ALLOWED_ORIGINS` explicit, not `*`
- [ ] `CSRF_ENABLED=true`
- [ ] `ENABLE_RATE_LIMIT=true`
- [ ] The enforcement gates moved off `off` — in `observe` first, then `enforce`
- [ ] `OIDX_TRUSTED_PROXIES` set to the real proxies, so the client IP in the audit trail is the client's
- [ ] Tracing and audit forwarding pointed somewhere that is read
- [ ] `ENCRYPTION_KEY` backed up somewhere that survives the database
- [ ] Backups scheduled and a restore rehearsed

## Environment examples

### Development

```env
APP_ENV=development
LOG_LEVEL=debug
DATABASE_URL=postgres://openidx:devpassword@localhost:5432/openidx
REDIS_URL=redis://localhost:6379/0
ENCRYPTION_KEY=0123456789abcdef0123456789abcdef
```

### Production

```env
APP_ENV=production
LOG_LEVEL=info
DATABASE_URL=postgres://openidx:CHANGE_ME@prod-db.example.com:5432/openidx?sslmode=verify-full
DATABASE_SSL_MODE=verify-full
REDIS_URL=rediss://:CHANGE_ME@prod-redis.example.com:6380/0
REDIS_TLS_ENABLED=true
CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
AUDIT_STREAM_ALLOWED_ORIGINS=https://admin.example.com
CSRF_ENABLED=true
ENABLE_RATE_LIMIT=true
ACCESS_ASSIGNMENT_ENFORCE=true
ABAC_ENFORCE=enforce
ENCRYPTION_KEY=CHANGE_ME
ACCESS_SESSION_SECRET=CHANGE_ME
AUDIT_CHAIN_SECRET=CHANGE_ME
VAULT_KEK=CHANGE_ME
```
