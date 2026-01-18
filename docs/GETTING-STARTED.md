# Getting Started with OpenIDX

## 🚀 Quick Start (5 Minutes)

### Prerequisites

- Go 1.22+
- Node.js 18+
- Docker & Docker Compose
- PostgreSQL 16 (or use Docker)
- Make (optional, for convenience)

### 1. Clone and Setup

```bash
git clone https://github.com/mhmtgngr/openidx.git
cd openidx

# Install dependencies
make deps
# OR manually:
go mod download
cd web/admin-console && npm install
```

### 2. Start Infrastructure

```bash
# Option A: Using Docker Compose (Recommended)
cd deployments/docker
docker-compose up -d postgres redis elasticsearch keycloak

# Option B: Local PostgreSQL
# Make sure PostgreSQL is running on localhost:5432
createdb openidx
```

### 3. Initialize Database

```bash
# Connect to PostgreSQL
psql postgresql://openidx:openidx_secret@localhost:5432/openidx

# Run the schema (will be provided in migrations)
\i migrations/001_create_tables.sql
```

### 4. Build Services

```bash
# Build all services at once
make build-services

# OR build individually
go build -o bin/identity-service ./cmd/identity-service
go build -o bin/governance-service ./cmd/governance-service
go build -o bin/provisioning-service ./cmd/provisioning-service
go build -o bin/oauth-service ./cmd/oauth-service
go build -o bin/audit-service ./cmd/audit-service
go build -o bin/admin-api ./cmd/admin-api
```

### 5. Start Services

```bash
# Terminal 1: Identity Service
export DATABASE_URL="postgresql://openidx:openidx_secret@localhost:5432/openidx?sslmode=disable"
export REDIS_URL="redis://:redis_secret@localhost:6379"
./bin/identity-service

# Terminal 2: OAuth Service
export DATABASE_URL="postgresql://openidx:openidx_secret@localhost:5432/openidx?sslmode=disable"
export REDIS_URL="redis://:redis_secret@localhost:6379"
./bin/oauth-service

# Terminal 3: Governance Service
export DATABASE_URL="postgresql://openidx:openidx_secret@localhost:5432/openidx?sslmode=disable"
export REDIS_URL="redis://:redis_secret@localhost:6379"
./bin/governance-service

# Terminal 4: Provisioning Service (SCIM)
export DATABASE_URL="postgresql://openidx:openidx_secret@localhost:5432/openidx?sslmode=disable"
export REDIS_URL="redis://:redis_secret@localhost:6379"
./bin/provisioning-service
```

### 6. Start Frontend

```bash
cd web/admin-console
npm run dev
```

### 7. Access the System

Open your browser:
- **Admin Console:** http://localhost:3000
- **OAuth Provider:** http://localhost:8006
- **Identity API:** http://localhost:8001
- **Governance API:** http://localhost:8002
- **SCIM API:** http://localhost:8003

---

## 🐳 Docker Compose (Full Stack)

### Start Everything

```bash
cd deployments/docker

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

### Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| Admin Console | http://localhost:3000 | - |
| API Gateway | http://localhost:8088 | - |
| Keycloak | http://localhost:8180 | admin/admin |
| PostgreSQL | localhost:5432 | openidx/openidx_secret |
| Redis | localhost:6379 | redis_secret |
| Elasticsearch | http://localhost:9200 | - |
| OPA | http://localhost:8181 | - |

### Stop Everything

```bash
# Stop services (keep data)
docker-compose down

# Stop and remove all data
docker-compose down -v
```

---

## 📝 First-Time Setup Tasks

### 1. Create First Admin User

```bash
curl -X POST http://localhost:8001/api/v1/identity/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@openidx.local",
    "first_name": "Admin",
    "last_name": "User",
    "enabled": true,
    "email_verified": true
  }'
```

### 2. Register OAuth Client for Admin Console

```bash
curl -X POST http://localhost:8006/api/v1/oauth/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Admin Console",
    "description": "OpenIDX Administration Console",
    "type": "web",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scopes": ["openid", "profile", "email", "offline_access"],
    "pkce_required": true,
    "allow_refresh_token": true,
    "access_token_lifetime": 3600,
    "refresh_token_lifetime": 86400
  }'
```

Save the `client_id` and `client_secret` from the response.

### 3. Create First Access Review (Optional)

```bash
curl -X POST http://localhost:8002/api/v1/governance/reviews \
  -H "Content-Type: application/json" \
  -d '{
    "id": "review-001",
    "name": "Q1 2026 User Access Review",
    "description": "Quarterly review of all user access rights",
    "type": "user_access",
    "reviewer_id": "admin-user-id",
    "start_date": "2026-01-20T00:00:00Z",
    "end_date": "2026-01-31T23:59:59Z"
  }'
```

---

## 🔧 Development Workflow

### Frontend Development

```bash
cd web/admin-console

# Start dev server with hot reload
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Run linter
npm run lint

# Type check
npm run type-check
```

### Backend Development

```bash
# Run with hot reload (install air first)
go install github.com/cosmtrek/air@latest

# In service directory
cd cmd/identity-service
air

# Run tests
go test ./...

# Run specific test
go test -v ./internal/identity -run TestCreateUser

# Run with race detector
go test -race ./...

# Generate mocks (if using gomock)
go generate ./...
```

### Database Migrations

```bash
# Install golang-migrate
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Create new migration
migrate create -ext sql -dir migrations -seq create_users_table

# Run migrations
migrate -path migrations -database "postgresql://openidx:openidx_secret@localhost:5432/openidx?sslmode=disable" up

# Rollback
migrate -path migrations -database "postgresql://openidx:openidx_secret@localhost:5432/openidx?sslmode=disable" down 1

# Check version
migrate -path migrations -database "postgresql://openidx:openidx_secret@localhost:5432/openidx?sslmode=disable" version
```

---

## 🧪 Testing

### Backend Tests

```bash
# Unit tests
make test

# Integration tests (requires running infrastructure)
make test-integration

# Coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Frontend Tests

```bash
cd web/admin-console

# Unit tests
npm test

# E2E tests (if configured)
npm run test:e2e

# Coverage
npm run test:coverage
```

### API Testing

```bash
# Test OAuth flow
curl http://localhost:8006/.well-known/openid-configuration

# Test SCIM
curl http://localhost:8003/scim/v2/ServiceProviderConfig

# Test user creation
curl -X POST http://localhost:8001/api/v1/identity/users \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "email": "test@example.com"}'
```

---

## 🐛 Troubleshooting

### Services Won't Start

**Problem:** Port already in use
```bash
# Find process using port
lsof -i :8001
# Kill process
kill -9 <PID>
```

**Problem:** Database connection refused
```bash
# Check PostgreSQL is running
docker-compose ps postgres
# Check logs
docker-compose logs postgres
# Restart
docker-compose restart postgres
```

### Frontend Issues

**Problem:** API calls fail with CORS error
```bash
# Ensure services allow CORS (already configured in OAuth service)
# Check browser console for exact error
```

**Problem:** Build fails with TypeScript errors
```bash
cd web/admin-console
rm -rf node_modules package-lock.json
npm install
npm run build
```

### Docker Issues

**Problem:** Services crash immediately
```bash
# Check logs
docker-compose logs <service-name>

# Recreate containers
docker-compose down
docker-compose up -d --force-recreate
```

**Problem:** Out of disk space
```bash
# Clean up Docker
docker system prune -a --volumes
```

---

## 📚 Common Tasks

### Add a New User

**Via API:**
```bash
curl -X POST http://localhost:8001/api/v1/identity/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john.doe@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "enabled": true
  }'
```

**Via Admin Console:**
1. Go to http://localhost:3000
2. Navigate to Users
3. Click "Add User"
4. Fill in details
5. Click "Create User"

### Register an OAuth Client

**Via API:**
```bash
curl -X POST http://localhost:8006/api/v1/oauth/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "type": "web",
    "redirect_uris": ["https://myapp.com/callback"],
    "scopes": ["openid", "profile", "email"]
  }'
```

**Via Admin Console:**
1. Go to Applications
2. Click "Register Application"
3. Fill in details
4. Copy Client ID and Secret

### Configure SCIM for Okta

1. **In OpenIDX:**
   - Register OAuth client (type: service)
   - Note Client ID and Secret

2. **In Okta:**
   - Go to Applications → Your App → Provisioning
   - SCIM Base URL: `http://your-openidx-url:8003/scim/v2`
   - OAuth Token: Use client credentials to get token
   - Test Connection

3. **Test:**
   - Create user in Okta
   - Check OpenIDX Users page - user should appear!

---

## 🔐 Security Best Practices

### Development

- ✅ Use `.env` files for secrets (don't commit)
- ✅ Change default passwords immediately
- ✅ Use HTTPS in production
- ✅ Enable CORS carefully (whitelist domains)
- ✅ Use strong JWT signing keys
- ✅ Rotate secrets regularly

### Production

- ✅ Use secrets management (Vault, AWS Secrets Manager)
- ✅ Enable TLS for all services
- ✅ Use network policies in Kubernetes
- ✅ Enable audit logging
- ✅ Set up monitoring and alerting
- ✅ Regular security audits

---

## 📊 Monitoring

### Health Checks

```bash
# Check all services
curl http://localhost:8001/health  # Identity
curl http://localhost:8002/health  # Governance
curl http://localhost:8003/health  # Provisioning
curl http://localhost:8004/health  # Audit
curl http://localhost:8005/health  # Admin API
curl http://localhost:8006/health  # OAuth
```

### Logs

```bash
# Docker Compose
docker-compose logs -f [service-name]

# Individual service
tail -f logs/identity-service.log

# Search logs
docker-compose logs | grep "ERROR"
```

### Metrics (If Prometheus configured)

```bash
curl http://localhost:8001/metrics
```

---

## 🆘 Getting Help

- **Documentation:** `/docs` folder
- **Issues:** https://github.com/mhmtgngr/openidx/issues
- **Architecture:** See `docs/ARCHITECTURE.md` (to be created)
- **API Reference:** See `docs/API-REFERENCE.md` (to be created)

---

## 🎯 Next Steps

After getting the system running:

1. **Explore the Admin Console** - Create users, groups, applications
2. **Try OAuth Flow** - Register a test app and authenticate
3. **Test SCIM** - Connect with Okta or Azure AD
4. **Create Access Review** - Test governance features
5. **Read Documentation** - Understand the architecture

---

**Happy Coding!** 🚀
