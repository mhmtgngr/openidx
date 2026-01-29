# Docker Compose Deployment

Run the full OpenIDX stack using Docker Compose.

## Prerequisites

- Docker Engine 24+
- Docker Compose v2
- 8 GB RAM minimum

## Quick Start

```bash
# Generate secrets
./scripts/generate-secrets.sh

# Start everything
docker compose -f deployments/docker/docker-compose.yml up -d
```

## Infrastructure Only

To start only infrastructure services (database, cache, etc.) for local service development:

```bash
docker compose -f deployments/docker/docker-compose.infra.yml up -d
```

This starts:

- **PostgreSQL 16** — port 5432
- **Redis 7** — port 6379
- **Elasticsearch 8.12** — port 9200
- **Keycloak 23** — port 8180
- **APISIX 3.8** — ports 8088 (HTTP), 8443 (HTTPS)
- **etcd 3.5** — internal only
- **OPA 0.61** — port 8181
- **Prometheus** — port 9090
- **Grafana** — port 3001

## Full Stack

The main `docker-compose.yml` includes infrastructure plus all OpenIDX services:

```bash
docker compose -f deployments/docker/docker-compose.yml up -d
```

This adds:

- **Identity Service** — port 8001
- **Governance Service** — port 8002
- **Provisioning Service** — port 8003
- **Audit Service** — port 8004
- **Admin API** — port 8005
- **OAuth Service** — port 8006
- **Admin Console** — port 3000

## Environment Variables

Copy `.env.example` to `.env` and update values, or use the secret generator:

```bash
cp .env.example .env
# Edit .env with your values

# Or generate random secrets:
./scripts/generate-secrets.sh
```

## Verify

```bash
# Check container status
docker compose -f deployments/docker/docker-compose.yml ps

# Check service health
curl http://localhost:8001/health
curl http://localhost:8006/.well-known/openid-configuration

# View logs
docker compose -f deployments/docker/docker-compose.yml logs -f identity-service
```

## Monitoring

- **Prometheus**: [http://localhost:9090](http://localhost:9090) — metrics and alerting
- **Grafana**: [http://localhost:3001](http://localhost:3001) — pre-configured dashboards
    - Username: `admin`
    - Password: value of `GRAFANA_ADMIN_PASSWORD` from `.env`

Two dashboards are provisioned automatically:

1. **OpenIDX Overview** — request rates, error rates, latency percentiles, in-flight requests
2. **OpenIDX Auth Metrics** — authentication attempts, token operations, session counts

## Stopping

```bash
docker compose -f deployments/docker/docker-compose.yml down

# To also remove volumes (destroys data):
docker compose -f deployments/docker/docker-compose.yml down -v
```

## Building Images

```bash
make docker-build
```

Or build individual services:

```bash
docker build -t openidx/identity-service -f deployments/docker/Dockerfile.identity-service .
```
