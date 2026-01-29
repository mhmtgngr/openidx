# Contributing

See the full [CONTRIBUTING.md](https://github.com/openidx/openidx/blob/main/CONTRIBUTING.md) in the repository root.

## Development Setup

```bash
# Clone
git clone https://github.com/openidx/openidx.git
cd openidx

# Generate secrets
./scripts/generate-secrets.sh

# Start infrastructure
make dev-infra

# Run services
make dev

# Run frontend
cd web/admin-console
npm install
npm run dev
```

## Project Structure

```
openidx/
├── cmd/                    # Service entry points (main.go per service)
├── internal/               # Private application code
│   ├── identity/           # Identity service
│   ├── governance/         # Governance service
│   ├── provisioning/       # Provisioning service
│   ├── audit/              # Audit service
│   ├── admin/              # Admin API
│   ├── oauth/              # OAuth/OIDC service
│   └── common/             # Shared packages
│       ├── config/         # Configuration loading
│       ├── database/       # Database clients
│       ├── logger/         # Structured logging
│       └── middleware/     # HTTP middleware
├── pkg/                    # Public libraries
├── api/openapi/            # OpenAPI 3.0 specifications
├── web/admin-console/      # React frontend
├── deployments/            # Docker, Kubernetes, Terraform
├── docs/                   # MkDocs documentation (this site)
├── scripts/                # Utility scripts
└── test/integration/       # Integration tests
```

## Workflow

1. Fork the repository
2. Create a feature branch from `dev`
3. Make your changes
4. Run tests: `make test` and `cd web/admin-console && npm test`
5. Run linters: `make lint`
6. Submit a pull request to `dev`

## Code Style

### Go

- Standard Go project layout
- Thin handlers, business logic in service methods
- Structured logging with `zap`
- Return errors, don't panic

### TypeScript / React

- Functional components with hooks
- Strict TypeScript (no `any`)
- Radix UI primitives for accessibility
- Tailwind CSS for styling
