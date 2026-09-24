# Getting Started with OpenIDX

> **Just want to run OpenIDX?** Use the **[Quick Start in the repository
> README](https://github.com/mhmtgngr/openidx/blob/main/README.md#quick-start)**:
> `./scripts/lite-up.sh`. The [Lite install](#lite-install) section below
> has what it runs, its memory budget and its optional components. The rest
> of this document is for **developers building from source**, and for the
> first-time setup tasks, which apply to every path.
>
> **Planning a production deploy?** The developer setup below brings up
> a development stack with insecure defaults. Before going to
> production, walk through
> [docs/SECURITY-HARDENING.md](./SECURITY-HARDENING.md), which lists
> the knobs the in-process `ValidateProduction()` gate refuses to
> start without. Also read
> [docs/SECURITY-TENANCY.md](./SECURITY-TENANCY.md) — OpenIDX is
> multi-tenant, enforced at the database with FORCE row-level
> security; that document defines the trust boundary.

## 🛠 Developer Setup (from source)

### Prerequisites

- Go 1.26+
- Node.js 20+
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
./scripts/generate-secrets.sh          # writes .env with random secrets
docker compose -f deployments/docker/docker-compose.yml up -d postgres redis elasticsearch

# Option B: Local PostgreSQL
# Make sure PostgreSQL is running on localhost:5432
createdb openidx
```

### 3. Initialize Database

Migrations are tracked under `internal/migrations` and applied by the
dedicated `cmd/migrate` binary. Do not run them by hand and do not
let the service binaries auto-migrate — `cmd/migrate up` is the
single supported entry point.

```bash
# Build the migrator
go build -o bin/migrate ./cmd/migrate

# Apply all pending migrations
export DATABASE_URL="postgresql://openidx:openidx_secret@localhost:5432/openidx?sslmode=disable"
./bin/migrate up

# Verify
./bin/migrate status
```

`migrate up` is idempotent — re-running it is safe. The lock table
prevents concurrent migrators from racing, and the loser of that race
now waits up to 30 s for the winner to finish (see PR #130).

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

## Lite install

`./scripts/lite-up.sh` runs `deployments/docker/docker-compose.lite.yml`:
the quick start in the README. It is sized for one machine with **4 GB of RAM
and 2 CPUs** (Linux, x86-64, Docker Engine with Compose 2.20 or later).

**What runs.** PostgreSQL, the three Redis roles (session, rate limit,
revocation), and the seven services the console calls: identity, governance,
provisioning, audit, admin-api, oauth and access. The console's own nginx is
the edge: it serves the SPA and sends each API prefix to its service
(`deployments/docker/nginx/admin-console.lite.conf`), so the browser talks to
one origin. There is no APISIX, etcd, OPA, mailpit or gateway-service; the
console calls none of them.

**What the script does.** It writes `.env` with random secrets when there is
none (mode 600; `scripts/generate-secrets.sh`, its output hidden), starts the
stack, waits until every service is healthy, and the first time gives the
seeded `admin` account a random password, printed once and stored nowhere.
A second run changes nothing it was not asked to change. Lost the password?
`./scripts/lite-up.sh --reset-admin-password`.

**Images.** The published ones, `ghcr.io/mhmtgngr/openidx/<service>`, all at
one release: `OPENIDX_VERSION`, default `v1.37.0`. v1.37.0 is the first
release whose console image calls its own origin. To try an unreleased
`main`, set `OPENIDX_VERSION` in `.env` to the full commit SHA of a `main`
commit (docker.yml tags every image with it).

**Memory.** Every container has a limit; the core's add up to 2080 MiB,
which leaves about 2 GiB of a 4 GB machine for the kernel, Docker and the
page cache.

| Container | Limit (MiB) | Container | Limit (MiB) |
|---|---|---|---|
| postgres | 512 | oauth-service | 256 |
| redis / redis-ratelimit / redis-revocation | 128 / 64 / 64 | admin-api | 192 |
| identity-service | 192 | access-service | 192 |
| audit-service | 160 | governance-service | 128 |
| provisioning-service | 128 | admin-console (nginx) | 64 |

`migrate` (256) and `seed` (64) finish before the services start. Measured
with the seven services running as processes against PostgreSQL 16 and
Redis 7 (not in containers): 30–51 MiB resident each when idle, 32–55 MiB
after 50 sign-ins and 750 API calls, except oauth-service, which peaked at
133 MiB because each password check holds 19 MiB for Argon2id. What the
containers use on the CI runner is printed by the `lite-install` job.

**Optional components.** One command each; each one needs the extra memory
shown, so add them one at a time and watch `docker stats`:

| Command | Adds | Extra limit (MiB) |
|---|---|---|
| `./scripts/lite-up.sh --with elasticsearch` | full-text audit search | 1024 |
| `./scripts/lite-up.sh --with guacamole` | brokered SSH/RDP/VNC for PAM, at `/guacamole/` on the console | 768 |
| `./scripts/lite-up.sh --with ziti` | the OpenZiti controller and one router; access-service connects to them | 384 |
| `./scripts/lite-up.sh --with observability` | Prometheus, Alertmanager, Grafana (127.0.0.1:3001), Loki, Promtail, Jaeger (127.0.0.1:16686), and tracing on | 1216 |

`--without <component>` takes one out. The choice is kept in `.env`
(`COMPOSE_PROFILES`), so plain `docker compose -f
deployments/docker/docker-compose.lite.yml ps|logs|down` sees the same
components. Guacamole's `guacadmin` gets the generated
`GUACAMOLE_ADMIN_PASSWORD`, not the schema's default. The Ziti profile
advertises `*.localtest.me`, which resolves to 127.0.0.1, so clients on other
machines cannot join it, and BrowZer is not included. Promtail reads the
Docker socket, which is root-equivalent on the host. Alertmanager shows alerts
(127.0.0.1:9093, and in Grafana) but delivers none: to send them somewhere,
add a receiver to `deployments/docker/alertmanager/alertmanager.lite.yml`.

**Reaching it from another machine.** The admin-console OAuth client accepts
only the console URLs it has registered, and `http://localhost:3000` is the
one registered by default. Either tunnel (`ssh -L 3000:localhost:3000
you@host`, then open http://localhost:3000), or run `./scripts/lite-up.sh
--url http://<host>:3000`: that registers the URL and makes it the token
issuer. Browsers must then use exactly that URL. Over plain HTTP on an
address other than localhost the browser has no Web Crypto, so the console
falls back to PKCE `plain`; the lite install runs in development mode, which
allows it. Put TLS in front for anything but a trial.

**Ports.** Only the console (`OPENIDX_CONSOLE_PORT`, default 3000) listens
beyond 127.0.0.1. PostgreSQL (5432), the session Redis (6379) and the
services (8001–8007) are published on 127.0.0.1 for debugging.

**What it is not.** It runs `APP_ENV=development` with no TLS and rate
limiting off. `ADMIN_API_REQUIRE_AUTH` and `ACCESS_API_REQUIRE_AUTH` are on,
so the admin and access APIs refuse anonymous callers even so. For
production use the Helm chart (`docs/DEPLOYMENT.md`).

**Check it.** `OPENIDX_ADMIN_PASSWORD_FILE=<file with the password>
scripts/lite-smoke.sh` signs in the way the console does and checks the
claims above; CI runs it on every change that touches the install.

---

## 🐳 Docker Compose (Full Stack)

The full stack is the advanced path in the **[README Quick
Start](https://github.com/mhmtgngr/openidx/blob/main/README.md#quick-start)** — clone, run
`./scripts/generate-secrets.sh` (compose refuses to start without the
generated `.env`), then `docker compose -f
deployments/docker/docker-compose.yml up -d`. It needs 8–10 GB of RAM. It
is not duplicated here so the instructions can never diverge. Infrastructure credentials
(PostgreSQL, Redis, Grafana, …) are the random values in your generated
`.env`, not fixed defaults.

Day-to-day commands once it's up:

```bash
# View logs / status
docker compose -f deployments/docker/docker-compose.yml logs -f
docker compose -f deployments/docker/docker-compose.yml ps

# Stop (keep data) / stop and remove all data
docker compose -f deployments/docker/docker-compose.yml down
docker compose -f deployments/docker/docker-compose.yml down -v
```

The admin console is at http://localhost:3000 (sign-in:
[First Login](#1-first-login)); the API gateway at http://localhost:8088.

---

## 📝 First-Time Setup Tasks

### 1. First Login

You do not create the first admin — the seed migration (v10) already did.

**Lite install:** `./scripts/lite-up.sh` replaces the seeded password with a
random one on its first run and prints it once; sign in as `admin` with
that. The seeded password below never works there.

**Full stack and developer setup:** this is the **authoritative**
first-login credential; if another document disagrees, this one is right:

| Field | Value |
|---|---|
| Username | `admin` (email `admin@openidx.local`) |
| Password | `Admin@123` |

Sign in at http://localhost:3000 and **rotate this password immediately**
(Console: **Users → admin → Set password**, or
`POST /api/v1/identity/users/00000000-0000-0000-0000-000000000001/set-password`).

This is not optional for production: the identity and oauth services
**refuse to start** with `APP_ENV=production` while the seeded default
password still authenticates
(`identity.EnsureDefaultAdminRotated`, called from both service mains).
Rotate it while still in development and the gate never bothers you.

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

### 3. Configure SSO with an External Provider

You can configure OpenIDX to use external identity providers like Google, Okta, or any other OIDC-compliant provider for Single Sign-On.

**1. Create an Identity Provider:**

Use the following API call to register an external provider. Replace the `issuer_url`, `client_id`, and `client_secret` with the values from your provider.

```bash
curl -X POST http://localhost:8001/api/v1/identity/providers \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Google",
    "provider_type": "oidc",
    "issuer_url": "https://accounts.google.com",
    "client_id": "your-google-client-id.apps.googleusercontent.com",
    "client_secret": "your-google-client-secret",
    "scopes": ["openid", "profile", "email"],
    "enabled": true
  }'
```

**2. Test the SSO Flow:**

- Go to the Admin Console login page (`http://localhost:3000`).
- You should now see a "Sign in with Google" button (or the name you provided).
- Clicking this button will redirect you to Google for authentication.
- After successful authentication, you will be redirected back and logged into the Admin Console.

### 4. Create First Access Review (Optional)

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
- **Architecture:** [Architecture](https://github.com/mhmtgngr/openidx/blob/main/docs/docs/guide/architecture.md) on the docs site
- **API Reference:** the OpenAPI specs in `api/openapi/`, browsable in the
  console under **Developer → API Docs**

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
