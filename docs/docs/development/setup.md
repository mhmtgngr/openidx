# Development Environment Setup

This guide covers setting up a full development environment for OpenIDX, including all dependencies, tools, and workflows.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.22+ | Backend development |
| Node.js | 18+ | Frontend development |
| npm | 9+ | Package management |
| Docker | 24+ | Container runtime |
| Docker Compose | 2.20+ | Local infrastructure |
| Make | 4.0+ | Build automation |
| Git | 2.40+ | Version control |
| PostgreSQL Client | 16+ | Direct DB access (optional) |
| Redis CLI | 7+ | Direct cache access (optional) |

### Installing Prerequisites

**Ubuntu/Debian:**

```bash
# Go
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Other tools
sudo apt-get install -y make git postgresql-client redis-tools
```

**macOS (Homebrew):**

```bash
brew install go node docker-compose make git
```

**Windows (WSL2):**

```bash
# Install WSL2 with Ubuntu, then run:
sudo apt update
sudo apt install -y build-essential
# Follow Ubuntu instructions above
```

## Repository Setup

### 1. Clone and Configure

```bash
# Clone the repository
git clone https://github.com/openidx/openidx.git
cd openidx

# Verify Go installation
go version

# Verify Node.js installation
node --version
npm --version
```

### 2. Generate Secrets

```bash
./scripts/generate-secrets.sh
```

This creates a `.env` file in the project root with secure random values for:

- PostgreSQL passwords
- Redis passwords
- JWT signing keys
- Encryption keys
- OAuth client secrets
- API secrets

**Do not commit the `.env` file.** It is already in `.gitignore`.

### 3. Pre-commit Hooks (Optional)

```bash
# Install pre-commit hooks for Go
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install pre-commit hooks for frontend
cd web/admin-console
npm install -g husky
npm install -g lint-staged
cd ../..
```

## Infrastructure Setup

### Start Development Infrastructure

```bash
make dev-infra
```

This starts the following services via Docker Compose:

| Service | Container Name | Port | Description |
|---------|---------------|------|-------------|
| PostgreSQL | openidx-postgres | 5432 | Primary database |
| PostgreSQL Replica | openidx-postgres-replica | 5433 | Read replica |
| Redis | openidx-redis | 6379 | Cache layer |
| Elasticsearch | openidx-elasticsearch | 9200 | Audit log storage |
| Keycloak | openidx-keycloak | 8180 | External IdP |
| APISIX | openidx-apisix | 8088 | API Gateway |
| etcd | openidx-etcd | 2379 | Service discovery |
| OPA | openidx-opa | 8281 | Policy engine |
| Prometheus | openidx-prometheus | 9090 | Metrics |
| Grafana | openidx-grafana | 3001 | Dashboards |
| Jaeger | openidx-jaeger | 16686 | Tracing UI |

### Verify Infrastructure

```bash
# Check all containers are running
docker compose -f deployments/docker/docker-compose.infra.yml ps

# Check PostgreSQL
docker exec -it openidx-postgres pg_isready

# Check Redis
docker exec -it openidx-redis redis-cli ping

# Check Elasticsearch
curl http://localhost:9200/_cluster/health
```

### Create Databases

```bash
# The init scripts in docker-compose.infra.yml automatically create:
# - openidx (main database)
# - openidx_test (test database)

# Run migrations
make migrate-up
```

## Backend Development Setup

### 1. Install Go Dependencies

```bash
# Download all Go modules
go mod download

# Verify dependencies
go mod verify

# Tidy up (if needed)
go mod tidy
```

### 2. Install Development Tools

```bash
# Go tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/golang/mock/mockgen@latest
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/swaggo/swag/cmd/swag@latest

# Verify installations
golangci-lint --version
mockgen --version
```

### 3. Build and Run Services

**Option A: Run all services with Make**

```bash
# Run all services in background
make dev

# Or run with logs
make dev-logs
```

**Option B: Run services individually**

```bash
# Terminal 1: Identity Service
go run ./cmd/identity-service

# Terminal 2: OAuth Service
go run ./cmd/oauth-service

# Terminal 3: Admin API
go run ./cmd/admin-api

# Terminal 4: Governance Service
go run ./cmd/governance-service

# Terminal 5: Provisioning Service
go run ./cmd/provisioning-service

# Terminal 6: Audit Service
go run ./cmd/audit-service

# Terminal 7: Gateway Service
go run ./cmd/gateway-service
```

### 4. Verify Services

```bash
# Health checks
curl http://localhost:8001/health  # Identity
curl http://localhost:8006/health  # OAuth
curl http://localhost:8005/health  # Admin
curl http://localhost:8002/health  # Governance
curl http://localhost:8003/health  # Provisioning
curl http://localhost:8004/health  # Audit
```

## Frontend Development Setup

### 1. Install Dependencies

```bash
cd web/admin-console

# Install npm dependencies
npm install

# Verify installation
npm list --depth=0
```

### 2. Development Server

```bash
# Start Vite dev server
npm run dev

# The console will be available at http://localhost:3000
```

### 3. Build for Production

```bash
# Build optimized bundle
npm run build

# Preview production build
npm run preview
```

### 4. Frontend Tools

```bash
# Type checking
npm run type-check

# Linting
npm run lint

# Format code
npm run format

# Run tests
npm test
```

## IDE Setup

### Visual Studio Code

Recommended extensions:

```json
{
  "recommendations": [
    "golang.go",
    "bradlc.vscode-tailwindcss",
    "dbaeumer.vscode-eslint",
    "esbenp.prettier-vscode",
    "ms-vscode.makefile-tools",
    "redhat.vscode-yaml",
    "ms-azuretools.vscode-docker",
    "eamodio.gitlens"
  ]
}
```

Workspace settings (`.vscode/settings.json`):

```json
{
  "go.useLanguageServer": true,
  "go.lintOnSave": "workspace",
  "go.lintTool": "golangci-lint",
  "go.formatOnSave": true,
  "typescript.preferences.importModuleSpecifier": "relative",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  }
}
```

### GoLand / IntelliJ IDEA

1. Open the project directory
2. Go to Settings → Go → GOROOT → Select Go 1.22+
3. Enable "Go Modules integration"
4. Settings → Editor → Code Style → Go → Import "Run goimports on save"

### Neovim / Vim

Install these plugins:

- `folke/tokyonight.nvim` - Theme
- `neovim/nvim-lspconfig` - LSP
- `williamboman/mason.nvim` - LSP installer
- `nvim-treesitter/nvim-treesitter` - Syntax highlighting
- `hrsh7th/nvim-cmp` - Completion
- `ray-x/go.nvim` - Go development

## Testing Setup

### Unit Tests

```bash
# Run all Go tests
go test -v ./...

# Run tests for a specific package
go test -v ./internal/identity/...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Integration Tests

```bash
# Requires infrastructure to be running
make dev-infra

# Run integration tests
go test -v -tags=integration ./test/integration/...
```

### Frontend Tests

```bash
cd web/admin-console

# Run unit tests
npm test

# Run with coverage
npm run test:coverage

# Run E2E tests (Playwright)
npm run test:e2e
```

## Database Management

### Connect to PostgreSQL

```bash
# Using psql
docker exec -it openidx-postgres psql -U openidx -d openidx

# Using pgAdmin (web UI)
open http://localhost:5050  # if configured
```

### Run Migrations

```bash
# Apply all pending migrations
make migrate-up

# Rollback last migration
make migrate-down

# Create new migration
make migrate-new NAME=create_users_table
```

### Reset Database

```bash
# Drop and recreate all tables
make migrate-reset

# Seed with test data
make seed
```

## Debugging

### Backend Debugging with Delve

```bash
# Install Delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug a service
dlv debug ./cmd/identity-service --headless --listen=:2345 --api-version=2

# Or with VS Code, create .vscode/launch.json:
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch Identity Service",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${workspaceFolder}/cmd/identity-service",
      "env": {
        "DATABASE_URL": "postgres://openidx:password@localhost:5432/openidx",
        "REDIS_URL": "redis://localhost:6379"
      }
    }
  ]
}
```

### Frontend Debugging

The Vite dev server includes source maps and hot module replacement. Open Chrome DevTools and navigate to Sources to set breakpoints.

## Performance Profiling

```bash
# Enable pprof endpoints (set in .env)
ENABLE_PPROF=true

# Get CPU profile
go tool pprof http://localhost:8001/debug/pprof/profile

# Get heap profile
go tool pprof http://localhost:8001/debug/pprof/heap

# Interactive profiling
go tool pprof -http=:8080 http://localhost:8001/debug/pprof/profile
```

## Troubleshooting

### Port Conflicts

If ports are already in use:

```bash
# Find process using port
lsof -i :8001

# Kill the process
kill -9 <PID>

# Or change ports in .env
IDENTITY_SERVICE_PORT=8101
```

### Database Connection Issues

```bash
# Restart PostgreSQL container
docker compose -f deployments/docker/docker-compose.infra.yml restart postgres

# Check logs
docker logs openidx-postgres
```

### Frontend Build Errors

```bash
# Clear node_modules and reinstall
rm -rf web/admin-console/node_modules
cd web/admin-console
npm install

# Clear Vite cache
npm run clean
```

### Go Module Issues

```bash
# Clear module cache
go clean -modcache

# Re-download dependencies
go mod download

# Verify dependencies
go mod verify
```

## Next Steps

- Read the [Testing Guide](testing.md) for comprehensive testing information
- Review the [Contributing Guide](contributing.md) for workflow guidelines
- Check [Observability](observability.md) for monitoring and debugging tips
