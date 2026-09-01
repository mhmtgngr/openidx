# Quick Start

Get OpenIDX running locally in a few steps.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- [Go 1.25+](https://go.dev/dl/) and [Node.js 20+](https://nodejs.org/) — only for building from source
- [Make](https://www.gnu.org/software/make/)
- **Hardware floor**: the full stack is ~39 containers — plan on ≥ 8–10 GB RAM

## 1. Clone & Generate Secrets

```bash
git clone https://github.com/mhmtgngr/openidx.git
cd openidx

# Generate a .env file with random secrets — compose refuses to start without them
./scripts/generate-secrets.sh
```

This creates a `.env` file with cryptographically random passwords for PostgreSQL, Redis, Grafana, JWT signing, and encryption.

## 2. Start Infrastructure

```bash
make dev-infra
```

This starts PostgreSQL, Redis, Elasticsearch, APISIX, etcd, and OPA via Docker Compose.

## 3. Start Services

```bash
make dev
```

This starts the full stack from `deployments/docker/docker-compose.yml`, including all 8 backend services. Alternatively, build from source and start services individually:

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

## 5. First Login

Sign in with the seeded admin — this is the authoritative first-login
credential:

| Field | Value |
|---|---|
| Username | `admin` (email `admin@openidx.local`) |
| Password | `Admin@123` |

**Rotate this password immediately** (Console: **Users → admin → Set
password**). This is not optional for production: the identity and oauth
services refuse to start with `APP_ENV=production` while the seeded
default password still authenticates.

## 6. Verify

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
| Prometheus | [http://localhost:9090](http://localhost:9090) |
| Grafana | [http://localhost:3001](http://localhost:3001) (admin / `$GRAFANA_ADMIN_PASSWORD` from your `.env`) |

## Next Steps

- [Concepts](concepts.md) — one product, four pillars: the mental model
- [Architecture Overview](architecture.md) — understand how the services fit together
- [Privileged Access](privileged-access.md) and [Zero Trust Network](network-access.md) — the PAM and ZTNA pillars
- [Configuration Reference](configuration.md) — customize settings via environment variables
- [Docker Deployment](../deployment/docker.md) — run the full stack with Docker Compose
- [API Reference](../api/overview.md) — explore all API endpoints
