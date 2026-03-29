# Configuration Reference

Complete reference for all OpenIDX configuration options.

## Environment Variables

OpenIDX uses environment variables for configuration. All variables can be set in a `.env` file or directly in the environment.

### Core Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `APP_ENV` | string | `development` | Environment: `development`, `staging`, `production` |
| `LOG_LEVEL` | string | `info` | Logging level: `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | string | `json` | Log format: `json`, `text` |
| `SERVICE_NAME` | string | - | Service identifier (required) |
| `PORT` | int | varies | Service port (defaults per service) |

### Database Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_URL` | string | - | PostgreSQL connection string (required) |
| `DATABASE_MAX_OPEN_CONNS` | int | `25` | Maximum open connections |
| `DATABASE_MAX_IDLE_CONNS` | int | `5` | Maximum idle connections |
| `DATABASE_CONN_MAX_LIFETIME` | duration | `5m` | Maximum connection lifetime |
| `DATABASE_POOL_MIN` | int | `5` | Minimum pool size (pgx) |
| `DATABASE_POOL_MAX` | int | `20` | Maximum pool size (pgx) |

**Connection String Format:**

```
postgres://user:password@host:port/database?sslmode=require
```

### Redis Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `REDIS_URL` | string | - | Redis connection string (required) |
| `REDIS_PASSWORD` | string | - | Redis password (if set) |
| `REDIS_DB` | int | `0` | Redis database number |
| `REDIS_POOL_SIZE` | int | `10` | Connection pool size |
| `REDIS_MIN_IDLE_CONNS` | int | `2` | Minimum idle connections |

**Connection String Format:**

```
redis://[:password@]host:port[/db]
```

### Elasticsearch Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ELASTICSEARCH_URL` | string | - | Elasticsearch URL (required for audit service) |
| `ELASTICSEARCH_INDEX` | string | `audit-*` | Index pattern for audit events |
| `ELASTICSEARCH_VERSION` | string | `8` | Elasticsearch major version |

### OAuth Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OAUTH_ISSUER` | string | - | Token issuer URL |
| `OAUTH_ACCESS_TOKEN_TTL` | duration | `1h` | Access token lifetime |
| `OAUTH_REFRESH_TOKEN_TTL` | duration | `720h` | Refresh token lifetime (30 days) |
| `OAUTH_AUTH_CODE_TTL` | duration | `10m` | Authorization code lifetime |
| `OAUTH_ID_TOKEN_TTL` | duration | `1h` | ID token lifetime |
| `JWT_SIGNING_METHOD` | string | `RS256` | JWT signing algorithm |
| `JWT_PRIVATE_KEY` | path | - | Path to JWT private key |
| `JWT_PUBLIC_KEY` | path | - | Path to JWT public key |
| `JWT_SIGNING_KEY` | string | - | HMAC signing key (if using HS256) |

### Encryption Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ENCRYPTION_KEY` | string | - | 32-byte encryption key (hex) |
| `ENCRYPTION_KEY_PATH` | path | - | Path to encryption key file |

### Security Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | strings | `*` | CORS allowed origins |
| `CORS_ALLOWED_METHODS` | strings | `GET,POST,PUT,DELETE,OPTIONS` | CORS allowed methods |
| `CORS_ALLOWED_HEADERS` | strings | - | CORS allowed headers |
| `CSRF_SECRET` | string | - | CSRF protection secret |
| `RATE_LIMIT_ENABLED` | bool | `true` | Enable rate limiting |
| `RATE_LIMIT_RPS` | int | `100` | Requests per second per IP |
| `RATE_LIMIT_BURST` | int | `200` | Burst size |

### OPA Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OPA_URL` | string | - | OPA server URL |
| `OPA_POLICY_PATH` | string | `/v1/data/openidx/authz` | OPA policy decision path |
| `OPA_TIMEOUT` | duration | `5s` | OPA query timeout |
| `OPA_DEV_MODE` | bool | `false` | Allow requests if OPA unreachable |

### APISIX Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `APISIX_ADMIN_URL` | string | `http://localhost:9180` | APISIX admin API URL |
| `APISIX_ADMIN_KEY` | string | - | APISIX admin key |
| `APISIX_BASE_URL` | string | `http://localhost:8088` | APISIX proxy URL |

### Keycloak Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KEYCLOAK_URL` | string | - | Keycloak base URL |
| `KEYCLOAK_REALM` | string | `master` | Keycloak realm |
| `KEYCLOAK_CLIENT_ID` | string | - | Keycloak client ID |
| `KEYCLOAK_CLIENT_SECRET` | string | - | Keycloak client secret |

### MFA Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MFA_TOTP_ISSUER` | string | `OpenIDX` | TOTP issuer name |
| `MFA_TOTP_PERIOD` | int | `30` | TOTP time period (seconds) |
| `MFA_TOTP_DIGITS` | int | `6` | TOTP code length |
| `MFA_TOTP_ALGORITHM` | string | `SHA1` | TOTP algorithm |
| `MFA_PUSH_ENABLED` | bool | `false` | Enable push MFA |
| `MFA_PUSH_TIMEOUT` | duration | `2m` | Push MFA timeout |
| `MFA_WEBARUTHN_ENABLED` | bool | `true` | Enable WebAuthn/FIDO2 |

### Email Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMTP_HOST` | string | - | SMTP server host |
| `SMTP_PORT` | int | `587` | SMTP server port |
| `SMTP_USERNAME` | string | - | SMTP username |
| `SMTP_PASSWORD` | string | - | SMTP password |
| `SMTP_FROM` | string | - | Default from address |
| `SMTP_FROM_NAME` | string | `OpenIDX` | Default from name |
| `SMTP_SKIP_VERIFY` | bool | `false` | Skip TLS verification |

### SMS Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMS_PROVIDER` | string | - | SMS provider: `twilio`, `sns`, `log` |
| `TWILIO_ACCOUNT_SID` | string | - | Twilio account SID |
| `TWILIO_AUTH_TOKEN` | string | - | Twilio auth token |
| `TWILIO_FROM_NUMBER` | string | - | Twilio from number |
| `SMS_TEMPLATE_LOGIN` | string | - | SMS login code template |

### Observability Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `METRICS_ENABLED` | bool | `true` | Enable Prometheus metrics |
| `METRICS_PATH` | string | `/metrics` | Metrics endpoint path |
| `TRACING_ENABLED` | bool | `false` | Enable distributed tracing |
| `TRACING_SAMPLER` | float | `0.1` | Trace sampling rate |
| `TRACING_ENDPOINT` | string | - | Jaeger endpoint |
| `HEALTH_CHECK_ENABLED` | bool | `true` | Enable health checks |

## Configuration File Format

OpenIDX also supports configuration via YAML files placed in `/etc/openidx/` or specified with `--config` flag.

**Example `/etc/openidx/identity-service.yaml`:**

```yaml
service:
  name: identity-service
  port: 8001

database:
  url: postgres://openidx:password@localhost:5432/openidx
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 5m

redis:
  url: redis://localhost:6379/0
  pool_size: 10

log:
  level: info
  format: json

oauth:
  issuer: https://openidx.example.com
  access_token_ttl: 1h
  refresh_token_ttl: 720h

security:
  cors_allowed_origins:
    - https://app.example.com
    - https://admin.example.com
  rate_limit_rps: 100

opa:
  url: http://localhost:8281
  policy_path: /v1/data/openidx/authz
  dev_mode: false

mfa:
  totp_issuer: OpenIDX
  webauthn_enabled: true

metrics:
  enabled: true
  path: /metrics
```

## Service-Specific Configuration

### Identity Service

Additional variables for the Identity Service:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `PASSWORD_MIN_LENGTH` | int | `8` | Minimum password length |
| `PASSWORD_REQUIRE_UPPERCASE` | bool | `true` | Require uppercase letters |
| `PASSWORD_REQUIRE_LOWERCASE` | bool | `true` | Require lowercase letters |
| `PASSWORD_REQUIRE_NUMBERS` | bool | `true` | Require numbers |
| `PASSWORD_REQUIRE_SYMBOLS` | bool | `true` | Require special characters |
| `SESSION_TTL` | duration | `24h` | Session lifetime |
| `MAX_SESSIONS_PER_USER` | int | `10` | Maximum concurrent sessions |

### Governance Service

Additional variables for the Governance Service:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `REVIEW_DEFAULT_DURATION` | duration | `720h` | Default review duration |
| `REVIEW_REMINDER_INTERVAL` | duration | `168h` | Review reminder frequency |
| `POLICY_EVALUATION_CACHE_TTL` | duration | `5m` | Policy cache duration |

### Audit Service

Additional variables for the Audit Service:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AUDIT_RETENTION_DAYS` | int | `90` | Event retention period |
| `AUDIT_EXPORT_BATCH_SIZE` | int | `1000` | Export batch size |
| `AUDIT_ASYNC_WRITE` | bool | `true` | Async event writing |

### Provisioning Service

Additional variables for the Provisioning Service:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SCIM_BULK_MAX_OPERATIONS` | int | `100` | Max SCIM bulk operations |
| `SCIM_SYNC_INTERVAL` | duration | `15m` | Directory sync interval |
| `LDAP_SYNC_ENABLED` | bool | `false` | Enable LDAP sync |

## Secrets Management

### Using Vault (Recommended)

For production, use HashiCorp Vault for secrets:

```bash
export VAULT_ADDR="https://vault.example.com"
vault login -method=oidc

# Store database credentials
vault kv put secret/openidx/database \
  url="postgres://openidx:$(vault generate -format=base64)@db:5432/openidx"

# Store JWT keys
vault kv put secret/openidx/jwt \
  private_key="$(vault generate -type=rsa-4096)" \
  public_key="..."

# Inject secrets into environment
export DATABASE_URL=$(vault kv get -field=url secret/openidx/database)
```

### Using Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: openidx-secrets
type: Opaque
stringData:
  database-url: postgres://openidx:password@postgres:5432/openidx
  redis-url: redis://redis:6379/0
  jwt-signing-key: <base64-encoded-key>
  encryption-key: <hex-encoded-key>
```

### Using AWS Secrets Manager

```bash
# Store secret
aws secretsmanager create-secret \
  --name openidx/prod/database \
  --secret-string '{"url":"postgres://..."}'

# Retrieve in application
export DATABASE_URL=$(aws secretsmanager get-secret-value \
  --secret-id openidx/prod/database \
  --query SecretString --output text | jq -r '.url')
```

## Configuration Validation

OpenIDX validates configuration at startup. Common errors:

### Missing Required Variables

```
Error: required environment variable "DATABASE_URL" is not set
```

### Invalid Connection String

```
Error: invalid database URL: missing host in connection string
```

### Invalid Encryption Key

```
Error: encryption key must be 32 bytes (64 hex characters)
```

## Production Checklist

Before deploying to production, ensure:

- [ ] Set `APP_ENV=production`
- [ ] Use strong, randomly generated secrets
- [ ] Enable TLS for all database connections (`sslmode=require`)
- [ ] Configure proper CORS origins (not `*`)
- [ ] Enable rate limiting
- [ ] Set appropriate log level (`info` or `warn`)
- [ ] Configure metrics and tracing
- [ ] Set up log aggregation
- [ ] Configure backup for PostgreSQL
- [ ] Use secure key storage (Vault, KMS, etc.)
- [ ] Set up monitoring and alerting
- [ ] Configure OPA in non-dev mode
- [ ] Enable security headers
- [ ] Set up regular security scans

## Environment-Specific Configs

### Development (.env.development)

```env
APP_ENV=development
LOG_LEVEL=debug
DATABASE_URL=postgres://openidx:devpassword@localhost:5432/openidx
REDIS_URL=redis://localhost:6379/0
OPA_DEV_MODE=true
RATE_LIMIT_ENABLED=false
```

### Staging (.env.staging)

```env
APP_ENV=staging
LOG_LEVEL=info
DATABASE_URL=postgres://openidx:CHANGE_ME@staging-db:5432/openidx
REDIS_URL=redis://staging-redis:6379/0
OPA_DEV_MODE=false
RATE_LIMIT_ENABLED=true
RATE_LIMIT_RPS=200
```

### Production (.env.production)

```env
APP_ENV=production
LOG_LEVEL=warn
DATABASE_URL=postgres://openidx:CHANGE_ME@prod-db.example.com:5432/openidx?sslmode=require
REDIS_URL=redis://:CHANGE_ME@prod-redis.example.com:6380/0
OPA_DEV_MODE=false
RATE_LIMIT_ENABLED=true
RATE_LIMIT_RPS=100
CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
```
