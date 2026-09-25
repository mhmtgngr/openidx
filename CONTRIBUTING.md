# Contributing to OpenIDX

Thank you for your interest in contributing to OpenIDX. This guide explains how to get started.

## Prerequisites

- Go 1.26. `go.mod` declares `go 1.26.0` and pins `toolchain go1.26.8`; with
  the default `GOTOOLCHAIN=auto`, the `go` command downloads that toolchain.
  The endpoint agent in `agent/` is a separate module on Go 1.25
  (`agent/go.mod`).
- Node.js 20, the version CI uses
- Docker and Docker Compose
- Make

## Local Development Setup

```bash
# Clone the repository
git clone https://github.com/mhmtgngr/openidx.git
cd openidx

# Install dependencies
make deps

# Start infrastructure (PostgreSQL, Redis, Elasticsearch, APISIX, OPA,
# and the observability stack) — OpenIDX is its own IdP, so there is no
# Keycloak to start
make dev-infra

# Start all services
make dev

# Access the admin console at http://localhost:3000
```

The seeded admin is `admin` / `Admin@123`, and
[docs/GETTING-STARTED.md § First Login](docs/GETTING-STARTED.md#1-first-login)
is the authoritative source for it — rotate the password before you do
anything else, because production refuses to start while the default still
authenticates.

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
  access/               # ZTNA, PAM broker, kill switch
  migrations/           # Database migrations
  common/               # Shared packages (config, middleware, database)
web/admin-console/      # React frontend
client/                 # Flutter app (mobile and desktop)
agent/                  # Go endpoint agent, its own module
deployments/            # Docker, Kubernetes, Terraform configs
```

## Development Workflow

1. **Fork** the repository and create a branch from `main`
2. **Name your branch** descriptively: `feat/add-user-export`, `fix/session-timeout`, `docs/api-reference`
3. **Write code** following the style guidelines below
4. **Add tests** for new functionality
5. **Run checks** before pushing:
   ```bash
   make lint        # Go linting
   make lint-web    # Frontend linting
   make test        # Unit tests
   make guards      # Every shell guard CI runs (~40s)
   ```
   `make guards` reads the guard list out of `.github/workflows`, so it runs
   what CI runs rather than a copy that can drift from it. It prints the few
   invocations it cannot run locally — the ones CI computes an argument for —
   instead of counting them as passes.
6. **Open a Pull Request** against `main`. It can merge once the
   [required checks](#required-checks) pass.

## Branching Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Every pull request targets it. Releases are tags on `main` ([docs/RELEASING.md](docs/RELEASING.md)) |
| `feat/*` | New features |
| `fix/*` | Bug fixes |
| `docs/*` | Documentation |

## Required checks

The **Required Checks** job (`status-check` in `.github/workflows/ci.yml`) is
the merge gate. It passes only when every job below passed or was skipped. A
job is skipped, which counts as a pass, when the pull request does not touch
what it checks: the Go jobs run when a `.go`, `go.mod` or `go.sum` file
changed, and the web jobs when something under `web/` changed. The list is the
`needs:` of that job, and `scripts/check-required-checks.sh` fails the build
if a job in `ci.yml` is in neither `needs:` nor the informational register. If
this table and `ci.yml` disagree, `ci.yml` is right.

| Check | Job | Runs on | What it checks |
|---|---|---|---|
| detect-changes | `detect-changes` | every change | Decides which of the jobs below the change needs |
| Every commit is signed off | `dco` | pull requests | Every commit the pull request adds has a `Signed-off-by` line |
| No internal topology | `no-internal-topology` | every change | The changed lines add no site-specific internal addresses |
| No prose running as shell | `shell-prose` | every change | Shell scripts run no stray prose; no document cites a missing path (`scripts/check-docs-drift.sh`); a detached database call names its tenant |
| GitHub config is runnable | `github-config` | every change | Workflows parse, CODEOWNERS names real owners, every CI job is required or declared informational, versions match `VERSION`, and the release and OpenAPI guards hold |
| Retries can still go red | `ci-resilience-guards` | every change | CI retries keep failures visible, `setup-go` installs the pinned toolchain, Windows-only tests have a job, and the mobile clients keep their secrets out of backups |
| UI safety guards | `ui-safety-guards` | every change | Console rules: every query shows its error, destructive actions ask for confirmation, controls are named and reachable by keyboard, and `web/admin-console/e2e/suite.txt` lists every spec |
| The documented first run works | `first-run` | every change | The README quick start writes the secrets compose needs, and the compose file resolves |
| The OPA policy parses and its tests pass | `opa-policy` | every change | `opa check --strict` on the policy and the chart's copy, then `opa test` |
| Tenant isolation (RLS_MODE=session and local) | `rls-isolation` | every change | Tenant isolation and other database-backed suites, against PostgreSQL as a role that cannot bypass RLS |
| Self-heal loop tests | `selfheal` | every change | The self-heal scripts' safety checks, with fake probes |
| Pipeline reacts correctly to every failure | `fault-matrix` | every change | The CI-over-overlay pipeline step handles each origin failure (`deployments/ci/faulttest`) |
| Field fixes still hold | `field-fix-scoreboard` | every change | The field-fix scoreboard (`scripts/field-fix-score.sh`) is at target |
| Build (Go 1.26) | `build-matrix` | Go changes | The services build, and the integration tests compile |
| Lint | `lint` | Go changes | `gofmt` and `golangci-lint` |
| Unit Tests (…) | `test-unit` | Go changes | `go test` for each package group, with coverage |
| Race Detector | `test-race` | Go changes | `go test -race ./...` |
| Integration Tests | `test-integration` | Go changes | `go test -tags=integration` on `./test/integration/...` and `./cmd/rekey/...`, against PostgreSQL, Redis and the running services |
| Vulnerability Check | `vulnerability-check` | Go changes | `govulncheck` on the root module and the agent module |
| Every tested package has a job | `testmatrix` | Go changes | Every package with tests is in the unit-test matrix |
| Org-scope lint | `orgscope` | Go changes | Every query on a tenant table names its organization |
| Unread-config lint | `deadconfig` | Go changes | Every setting is read by something, and every documented setting is bound |
| Unreachable-service lint | `deadservice` | Go changes | Every service type can be reached from a binary |
| Inert-test lint | `inerttests` | Go changes | No test passes without calling the code it tests |
| Inert-switch lint | `inertswitch` | Go changes | No boolean an API accepts is stored without something deciding on it |
| Route-reachability lint | `routereach` | Go changes | Every handler is mounted, and reads only the parameters its routes declare |
| Unwritten-table lint | `tablewriters` | Go changes | Every table the migrations create has a writer, or is registered as having none |
| Posture-coverage lint | `posturevocab` | Go changes | Each posture check covers every operating system that reports it |
| Zero-answer lint | `zeroanswer` | Go changes | No one-row aggregate query drops its scan error |
| The stack answers end to end | `smoke` | Go or web changes | The services and the console, built from source, pass `make smoke-test` and the contract check |
| The console's journeys work in a browser | `e2e` | Go or web changes | The Playwright specs marked `run` in `web/admin-console/e2e/suite.txt`, against a running stack |
| Frontend Tests | `test-frontend` | web changes | Console lint, type check and unit tests |

Other workflows run on pull requests that touch their paths: Frontend CI,
Documentation (`mkdocs build --strict`), Helm Chart, Docker Build, Security
Scanning, CodeQL Analysis, Terraform, Android CI and the client builds. The
Required Checks job does not include them, so read their results too.

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

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by` line. It certifies the
[Developer Certificate of Origin](https://developercertificate.org/): that you
wrote the change, or otherwise have the right to submit it under the project's
Apache-2.0 licence. Git adds the line for you:

```bash
git commit -s
```

Forgot one? `git commit --amend -s` fixes the last commit and
`git rebase --signoff main` fixes a branch. CI checks it: the
`Every commit is signed off` job (`scripts/check-dco.sh`) walks every non-merge
commit a pull request adds and fails on the first one without a sign-off. Merge
commits need none. The sign-off is a statement, not a signature; no GPG key is
involved.

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

Use [GitHub Issues](https://github.com/mhmtgngr/openidx/issues) with the provided templates:
- **Bug Report** for defects
- **Feature Request** for new functionality

[SUPPORT.md](SUPPORT.md) says what to expect once an issue is open.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
