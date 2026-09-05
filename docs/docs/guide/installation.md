# Installation

Install OpenIDX on your system or infrastructure.

## System Requirements

### Minimum Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 8 GB | 10+ GB |
| Disk | 20 GB | 50+ GB SSD |
| OS | Linux (Ubuntu 22.04+, RHEL 9+) | Linux |

### Software Requirements

- **Go**: 1.25+ (for development)
- **Node.js**: 18+ (for Admin Console)
- **Docker**: 24.0+ (for containerized deployment)
- **PostgreSQL**: 16+
- **Redis**: 7+

## Installation Methods

### Docker Compose (Recommended)

The easiest way to run OpenIDX:

```bash
# Clone the repository
git clone https://github.com/mhmtgngr/openidx.git
cd openidx

# Generate secrets
./scripts/generate-secrets.sh

# Start all services
docker compose -f deployments/docker/docker-compose.yml up -d
```

### Kubernetes (Helm)

For production deployments. Each tagged release publishes the chart to
GHCR as a cosign-signed OCI artifact (chart version = release version —
pick one from the [releases page](https://github.com/mhmtgngr/openidx/releases)):

```bash
helm install openidx oci://ghcr.io/mhmtgngr/openidx/charts/openidx \
  --version <X.Y.Z> \
  --namespace openidx \
  --create-namespace \
  --set postgresql.enabled=true \
  --set redis.enabled=true
```

See [Kubernetes Deployment](../deployment/kubernetes.md) for detailed configuration.

### Binary Installation

Each release attaches one Linux binary per service
(`<service>-linux-amd64`) plus a cosign-signed `SHA256SUMS` file — see
[RELEASING.md](https://github.com/mhmtgngr/openidx/blob/main/docs/RELEASING.md)
for signature verification:

```bash
# Download a service binary and the signed checksums
wget https://github.com/mhmtgngr/openidx/releases/latest/download/identity-service-linux-amd64
wget https://github.com/mhmtgngr/openidx/releases/latest/download/SHA256SUMS

# Verify and install
sha256sum --ignore-missing -c SHA256SUMS
sudo install -m 0755 identity-service-linux-amd64 /usr/local/bin/identity-service
```

### Build from Source

For development or custom builds:

```bash
# Clone the repository
git clone https://github.com/mhmtgngr/openidx.git
cd openidx

# Build all services
make build

# Or build individual services
go build -o bin/identity-service ./cmd/identity-service
go build -o bin/oauth-service ./cmd/oauth-service
# ... etc.
```

## Database Setup

### PostgreSQL

OpenIDX requires PostgreSQL 16+.

```bash
# Using Docker
docker run -d \
  --name openidx-postgres \
  -e POSTGRES_USER=openidx \
  -e POSTGRES_PASSWORD=your-password \
  -e POSTGRES_DB=openidx \
  -p 5432:5432 \
  postgres:16-alpine

# Run migrations
go run ./cmd/migrate up
```

### Database Schema

The schema is versioned and managed via migrations (the `migrate` CLI
reads the standard `DB_*`/`DATABASE_URL` environment):

```bash
# Run all migrations
go run ./cmd/migrate up

# Rollback one migration
go run ./cmd/migrate down

# View migration status
go run ./cmd/migrate status
```

## Redis Setup

```bash
# Using Docker
docker run -d \
  --name openidx-redis \
  -p 6379:6379 \
  redis:7-alpine
```

## Elasticsearch Setup (Optional)

Required for audit log search:

```bash
# Using Docker
docker run -d \
  --name openidx-elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0
```

## Configuration

Create a configuration file at `/etc/openidx/config.yaml` or set environment variables:

```yaml
database:
  url: "postgres://openidx:password@localhost:5432/openidx?sslmode=disable"

redis:
  url: "redis://localhost:6379/0"

elasticsearch:
  url: "http://localhost:9200"

oauth:
  issuer: "https://your-domain.com"
  jwks_url: "https://your-domain.com/.well-known/jwks.json"

logging:
  level: "info"
  format: "json"
```

## Verification

After installation, verify all services are running:

```bash
# Check health endpoints
curl http://localhost:8001/health  # Identity Service
curl http://localhost:8006/health  # OAuth Service

# Check OIDC discovery
curl http://localhost:8006/.well-known/openid-configuration
```

## Upgrading

```bash
# Pull latest images
docker compose -f deployments/docker/docker-compose.yml pull

# Restart services
docker compose -f deployments/docker/docker-compose.yml up -d

# Run any pending migrations
go run ./cmd/migrate up
```

## Troubleshooting

See [Troubleshooting](../troubleshooting.md) for common issues.

### Service fails to start

1. Check logs: `docker compose logs -f [service-name]`
2. Verify database connectivity: `psql -h localhost -U openidx -d openidx`
3. Check port availability: `netstat -tlnp | grep -E '8001|8006'`

### Migration errors

1. Verify database version: `psql --version`
2. Check migration status: `go run ./cmd/migrate status`
3. Review the migration output — the `migrate` CLI logs to stdout
