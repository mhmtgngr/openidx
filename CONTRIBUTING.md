# Contributing to OpenIDX

Thank you for your interest in contributing to OpenIDX. This guide explains how to get started.

## Prerequisites

- Go 1.22+
- Node.js 20+
- Docker and Docker Compose
- Make

## Local Development Setup

```bash
# Clone the repository
git clone https://github.com/openidx/openidx.git
cd openidx

# Install dependencies
make deps

# Start infrastructure (PostgreSQL, Redis, Elasticsearch, Keycloak, etc.)
make dev-infra

# Start all services
make dev

# Access the admin console at http://localhost:3000
# Default credentials: admin@openidx.local / Admin@123
```

## Project Structure

```
cmd/                    # Service entry points
internal/               # Private application code
  identity/             # Identity service (users, groups, MFA)
  governance/           # Access reviews, policies
  provisioning/         # SCIM 2.0, directory sync
  audit/                # Audit logging, compliance
  admin/                # Admin API, dashboard
  oauth/                # OAuth 2.0, OIDC, SAML
  common/               # Shared packages (config, middleware, database)
web/admin-console/      # React frontend
deployments/            # Docker, Kubernetes, Terraform configs
migrations/             # Database migration files
```

## Development Workflow

1. **Fork** the repository and create a branch from `dev`
2. **Name your branch** descriptively: `feat/add-user-export`, `fix/session-timeout`, `docs/api-reference`
3. **Write code** following the style guidelines below
4. **Add tests** for new functionality
5. **Run checks** before pushing:
   ```bash
   make lint        # Go linting
   make lint-web    # Frontend linting
   make test        # Unit tests
   ```
6. **Open a Pull Request** against the `dev` branch

## Branching Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable releases |
| `dev` | Active development, PR target |
| `feat/*` | New features |
| `fix/*` | Bug fixes |
| `docs/*` | Documentation |

## Commit Message Convention

Use conventional commits:

```
feat: add SCIM group provisioning
fix: resolve session timeout on token refresh
docs: update API endpoint reference
refactor: extract validation into shared package
test: add governance service unit tests
chore: update Go dependencies
```

## Code Style

### Go

- Follow standard Go project layout
- Keep HTTP handlers thin; put business logic in service methods
- Use `context.Context` for cancellation and timeouts
- Use structured logging via zap (`internal/common/logger/`)
- Return errors, don't panic
- Run `make lint` before committing

### TypeScript / React

- Functional components with hooks
- Use TypeScript strictly (no `any`)
- Use Radix UI primitives for accessible components
- Style with Tailwind CSS utility classes
- Fetch data with React Query (`useQuery` / `useMutation`)

## Testing

```bash
# Go unit tests
make test

# Go tests with coverage report
make test-coverage

# Integration tests (requires running infrastructure)
make test-integration

# Frontend tests
cd web/admin-console && npm test
```

When adding a new feature, include tests that cover:
- Happy path
- Error / edge cases
- Input validation

## Adding a New API Endpoint

1. Define the route in the service's `RegisterRoutes` function
2. Implement the handler method on the Service struct
3. Add business logic in the service layer
4. Add tests
5. Update the OpenAPI spec in `api/openapi/`

## Reporting Issues

Use [GitHub Issues](https://github.com/openidx/openidx/issues) with the provided templates:
- **Bug Report** for defects
- **Feature Request** for new functionality

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
