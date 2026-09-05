# Configuration

OpenIDX services are configured via environment variables. All services share a common configuration loaded through `internal/common/config`.

## Environment Variables

### Core

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_ENV` | Environment: `development` or `production` | `development` |
| `LOG_LEVEL` | Logging level: `debug`, `info`, `warn`, `error` | `info` |

### Database & Cache

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | — |
| `POSTGRES_PASSWORD` | PostgreSQL password (used by containers) | — |
| `REDIS_URL` | Redis connection string | — |
| `REDIS_PASSWORD` | Redis password (used by containers) | — |
| `ELASTICSEARCH_URL` | Elasticsearch URL (audit service only) | `http://localhost:9200` |

### Authentication

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | Secret for JWT signing (min 32 chars) | — |
| `ENCRYPTION_KEY` | AES-256 key (exactly 32 bytes) | — |

### OAuth / OIDC

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH_ISSUER` | OAuth issuer URL | `http://localhost:8006` |
| `OAUTH_LOGIN_URL` | Absolute URL of the login page `/oauth/authorize` redirects to. Set it when the console is not on the issuer's origin. | `<OAUTH_ISSUER>/login` |
| `OAUTH_JWKS_URL` | JWKS endpoint URL | — |

### External Services

| Variable | Description | Default |
|----------|-------------|---------|
| `OPA_URL` | Open Policy Agent URL | `http://localhost:8281` |

### Frontend

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_URL` | API gateway URL for frontend | `http://localhost:8088` |
| `VITE_OAUTH_URL` | OAuth service URL for frontend | `http://localhost:8006` |
| `VITE_OAUTH_CLIENT_ID` | OAuth client ID for admin console | `admin-console` |

### Observability

| Variable | Description | Default |
|----------|-------------|---------|
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin password | `admin` |

### SMTP (Optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `SMTP_HOST` | SMTP server hostname | — |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USERNAME` | SMTP username | — |
| `SMTP_PASSWORD` | SMTP password | — |
| `SMTP_FROM` | From email address | `noreply@openidx.io` |

## Secret Management

### Local Development

Use the secret generation script:

```bash
./scripts/generate-secrets.sh
```

This creates a `.env` file with cryptographically random secrets. The file is git-ignored.

### Kubernetes

Use the Helm chart's secrets configuration:

```yaml
# values.yaml
secrets:
  postgresPassword: "..."
  redisPassword: "..."
  jwtSecret: "..."
  encryptionKey: "..."
```

Or use External Secrets Operator for production:

```yaml
externalSecrets:
  enabled: true
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  remoteKeyPrefix: "openidx"
```

### Service Ports

Each service listens on a fixed port determined by the service type:

| Service | Port |
|---------|------|
| Identity Service | 8001 |
| Governance Service | 8002 |
| Provisioning Service | 8003 |
| Audit Service | 8004 |
| Admin API | 8005 |
| OAuth Service | 8006 |
| Gateway Service | 8080 |
