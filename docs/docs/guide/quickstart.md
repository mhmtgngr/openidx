# Quick Start

Get OpenIDX running locally in a few steps.

## Prerequisites

- [Go 1.22+](https://go.dev/dl/)
- [Node.js 18+](https://nodejs.org/)
- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- [Make](https://www.gnu.org/software/make/)

## 1. Clone & Generate Secrets

```bash
git clone https://github.com/openidx/openidx.git
cd openidx

# Generate a .env file with random secrets
./scripts/generate-secrets.sh
```

This creates a `.env` file with cryptographically random passwords for PostgreSQL, Redis, Keycloak, JWT signing, and encryption.

## 2. Start Infrastructure

```bash
make dev-infra
```

This starts PostgreSQL, Redis, Elasticsearch, Keycloak, APISIX, etcd, OPA, Prometheus, and Grafana via Docker Compose.

Wait for all containers to become healthy:

```bash
docker compose -f deployments/docker/docker-compose.infra.yml ps
```

## 3. Start Services

```bash
make dev
```

This builds and starts all 7 backend services. Alternatively, start services individually:

```bash
go run ./cmd/identity-service
go run ./cmd/oauth-service
go run ./cmd/admin-api
# ... etc.
```

## 4. Start the Admin Console

```bash
cd web/admin-console
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## 5. Verify

Check that services are healthy:

```bash
# Identity Service
curl http://localhost:8001/health

# OAuth Service
curl http://localhost:8006/health

# OIDC Discovery
curl http://localhost:8006/.well-known/openid-configuration
```

## Available Ports

| Service | URL |
|---------|-----|
| Admin Console | [http://localhost:3000](http://localhost:3000) |
| Identity Service | [http://localhost:8001](http://localhost:8001) |
| Governance Service | [http://localhost:8002](http://localhost:8002) |
| Provisioning Service | [http://localhost:8003](http://localhost:8003) |
| Audit Service | [http://localhost:8004](http://localhost:8004) |
| Admin API | [http://localhost:8005](http://localhost:8005) |
| OAuth Service | [http://localhost:8006](http://localhost:8006) |
| API Gateway (APISIX) | [http://localhost:8088](http://localhost:8088) |
| Keycloak | [http://localhost:8180](http://localhost:8180) |
| Prometheus | [http://localhost:9090](http://localhost:9090) |
| Grafana | [http://localhost:3001](http://localhost:3001) |

## Next Steps

- [Architecture Overview](architecture.md) — understand how the services fit together
- [Configuration Reference](configuration.md) — customize settings via environment variables
- [Docker Deployment](../deployment/docker.md) — run the full stack with Docker Compose
- [API Reference](../api/overview.md) — explore all API endpoints
