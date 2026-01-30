# CLAUDE.md - OpenIDX Development Guide

## Project Overview

OpenIDX is an open-source Zero Trust Access Platform (ZTAP) that provides enterprise-grade Identity and Access Management. It competes with commercial solutions like Microsoft Entra ID, Okta, and Duo while offering 70-80% cost savings.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     API Gateway (APISIX)                        │
└─────────────────────────────────────────────────────────────────┘
                                │
    ┌───────────────────────────┼───────────────────────┐
    │                           │                       │
┌───▼───┐  ┌───────▼───────┐  ┌───▼───┐  ┌───────▼─────┐
│Identity│  │  Governance  │  │Provis-│  │    Audit   │
│Service │  │   Service    │  │ioning │  │   Service  │
└────────┘  └──────────────┘  └───────┘  └────────────┘
    │               │              │             │
    └───────────────┼──────────────┴─────────────┘
                    │
         ┌──────────▼──────────┐
         │  Policy Engine (OPA)│
         └─────────────────────┘
                    │
    ┌───────────────┼───────────────┐
    │               │               │
┌───▼───┐     ┌─────▼─────┐   ┌─────▼─────┐
│Postgres│    │   Redis   │   │Elasticsearch│
└────────┘    └───────────┘   └────────────┘
```

## Tech Stack

### Backend (Go 1.22+)
- **Framework**: Gin (HTTP router)
- **Database**: PostgreSQL with pgx driver
- **Cache**: Redis with go-redis
- **Logging**: Zap
- **Config**: Viper
- **JWT**: golang-jwt/v5

### Frontend (React 18+)
- **Framework**: React with TypeScript
- **Build**: Vite
- **Styling**: Tailwind CSS
- **State**: Zustand + React Query
- **UI**: Radix UI primitives
- **Auth**: keycloak-js

### Infrastructure
- **Identity Provider**: Keycloak
- **API Gateway**: Apache APISIX
- **Policy Engine**: Open Policy Agent (OPA)
- **Container**: Docker + Kubernetes
- **IaC**: Terraform (AWS EKS)

## Directory Structure

```
openidx/
├── cmd/                    # Service entry points
│   ├── identity-service/
│   ├── governance-service/
│   ├── provisioning-service/
│   ├── audit-service/
│   └── admin-api/
├── internal/               # Private application code
│   ├── identity/          # Identity service logic
│   ├── governance/        # Access reviews, policies
│   ├── provisioning/      # SCIM 2.0, user lifecycle
│   ├── audit/             # Audit logging, compliance
│   ├── admin/             # Admin API handlers
│   └── common/            # Shared packages
│       ├── config/
│       ├── database/
│       ├── logger/
│       └── middleware/
├── pkg/                   # Public libraries
├── api/                   # API definitions
├── web/admin-console/     # React frontend
├── deployments/           # Deployment configs
│   ├── docker/
│   ├── kubernetes/helm/
│   └── terraform/
└── configs/               # Configuration files
```

## Development Commands

```bash
# Start local development
make dev-infra    # Start PostgreSQL, Redis, Elasticsearch
make dev          # Start all services

# Build
make build        # Build all services
make build-web    # Build frontend

# Test
make test         # Run unit tests
make test-integration  # Run integration tests

# Lint
make lint         # Run Go linters
make lint-web     # Run frontend linters

# Docker
make docker-build # Build Docker images
make docker-push  # Push to registry

# Kubernetes
make helm-install # Deploy via Helm
```

## Key Development Tasks

### Adding a New API Endpoint

1. Define route in service's `RegisterRoutes` function
2. Implement handler method on Service struct
3. Add business logic
4. Update OpenAPI spec in `api/openapi/`
5. Add tests

### Adding a New Service

1. Create directory in `cmd/<service-name>/`
2. Copy main.go template from existing service
3. Create internal package in `internal/<service>/`
4. Add to Docker Compose and Kubernetes configs
5. Update Makefile targets

### Frontend Component Pattern

```tsx
// Use Radix UI primitives + Tailwind
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'

// API calls with React Query
const { data, isLoading } = useQuery({
  queryKey: ['users'],
  queryFn: () => api.get('/api/v1/identity/users'),
})
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://...` |
| `REDIS_URL` | Redis connection string | `redis://...` |
| `KEYCLOAK_URL` | Keycloak base URL | `http://localhost:8180` |
| `OPA_URL` | OPA base URL | `http://localhost:8281` |
| `LOG_LEVEL` | Logging level | `info` |
| `APP_ENV` | Environment (dev/prod) | `development` |

## Code Style Guidelines

### Go
- Use standard Go project layout
- Keep handlers thin, business logic in service methods
- Use context for cancellation and timeouts
- Structured logging with zap
- Return errors, don't panic

### TypeScript/React
- Functional components with hooks
- Use TypeScript strictly (no `any`)
- Colocate tests with components
- Use Radix UI for accessibility

## Testing

```bash
# Go unit tests
go test -v ./...

# Integration tests (requires infra)
go test -v -tags=integration ./test/integration/...

# Frontend tests
cd web/admin-console && npm test
```

## Common Tasks for Claude Code

### "Add user provisioning feature"
1. Check `internal/provisioning/service.go` for existing SCIM implementation
2. Extend with new endpoints as needed
3. Update frontend in `web/admin-console/src/pages/users.tsx`

### "Fix authentication issue"
1. Check `internal/common/middleware/middleware.go` for Auth middleware
2. Verify Keycloak config in `deployments/docker/keycloak/`
3. Check APISIX routes in `deployments/docker/apisix/`

### "Add new compliance report"
1. Extend `internal/audit/service.go` - `GenerateComplianceReport`
2. Add report type to `ReportType` enum
3. Create frontend page for report viewing

### "Improve API performance"
1. Check Redis caching in service implementations
2. Review database queries for N+1 problems
3. Consider adding pagination if missing

## API Endpoints Reference

### Identity Service (8001)
- `GET/POST /api/v1/identity/users` - List/create users
- `GET/PUT/DELETE /api/v1/identity/users/:id` - User CRUD
- `GET /api/v1/identity/users/:id/sessions` - User sessions

### Governance Service (8002)
- `GET/POST /api/v1/governance/reviews` - Access reviews
- `POST /api/v1/governance/reviews/:id/items/:itemId/decision` - Submit decision
- `GET/POST /api/v1/governance/policies` - Manage policies

### Provisioning Service (8003)
- `GET/POST /scim/v2/Users` - SCIM user management
- `GET/POST /scim/v2/Groups` - SCIM group management
- `GET /scim/v2/ServiceProviderConfig` - SCIM discovery

### Audit Service (8004)
- `GET /api/v1/audit/events` - Query audit logs
- `POST /api/v1/audit/reports` - Generate compliance report
- `GET /api/v1/audit/statistics` - Get statistics

### Admin API (8005)
- `GET /api/v1/dashboard` - Dashboard stats
- `GET/PUT /api/v1/settings` - System settings
- `GET/POST /api/v1/applications` - Application management
