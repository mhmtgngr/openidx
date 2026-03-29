# OpenIDX CLI

The unified developer CLI tool for OpenIDX provides a convenient interface for common development tasks.

## Installation

### Build from source

```bash
go build -o bin/openidx ./cmd/openidx
```

### Install to PATH

```bash
make install-cli
# or
go install github.com/openidx/openidx/cmd/openidx@latest
```

### Shell Completion

Enable shell completion for a better experience:

**Bash:**
```bash
openidx completion bash > /etc/bash_completion.d/openidx
source ~/.bashrc
```

**Zsh:**
```bash
openidx completion zsh > ~/.zsh/completions/_openidx
exec zsh
```

**Fish:**
```bash
openidx completion fish > ~/.config/fish/completions/openidx.fish
```

**PowerShell:**
```bash
openidx completion powershell > openidx.ps1
# Add to your PowerShell profile
```

Or simply run:
```bash
openidx install-completion
```

## Quick Start

```bash
# Start the development environment
openidx dev

# View service status
openidx status

# View logs
openidx logs identity

# Run tests
openidx test

# Stop services
openidx dev-stop
```

## Commands

### Development

| Command | Description |
|---------|-------------|
| `openidx dev` | Start development environment |
| `openidx dev --infra` | Start only infrastructure services |
| `openidx dev -b` | Start services in background |
| `openidx dev-stop` | Stop development environment |
| `openidx status` | Show service status |
| `openidx status -w` | Watch mode - refresh status periodically |

### Build

| Command | Description |
|---------|-------------|
| `openidx build` | Build all services and web apps |
| `openidx build -s` | Build Go services only |
| `openidx build -w` | Build web applications only |
| `openidx build -o identity-service` | Build specific service |
| `openidx clean` | Clean build artifacts |
| `openidx clean -a` | Also clean Docker resources |

### Test

| Command | Description |
|---------|-------------|
| `openidx test` | Run all tests |
| `openidx test-unit` | Run unit tests only |
| `openidx test-integration` | Run integration tests |
| `openidx test-e2e` | Run end-to-end tests |
| `openidx test -c` | Run tests with coverage |
| `openidx test -v` | Verbose output |
| `openidx bench` | Run benchmarks |

### Database

| Command | Description |
|---------|-------------|
| `openidx migrate up` | Run all pending migrations |
| `openidx migrate down` | Rollback last migration |
| `openidx migrate status` | Show migration status |
| `openidx migrate version` | Show current migration version |
| `openidx migrate create <name>` | Create a new migration |
| `openidx seed` | Seed database with test data |
| `openidx db reset` | Reset database |

### Logs

| Command | Description |
|---------|-------------|
| `openidx logs` | View logs from all services |
| `openidx logs identity` | View logs for specific service |
| `openidx logs -f` | Follow log output |
| `openidx logs -n 50` | Show last 50 lines |
| `openidx logs-filter --level error` | Filter logs by level |
| `openidx logs-errors` | Show only error logs |

### Environment

| Command | Description |
|---------|-------------|
| `openidx doctor` | Check environment and dependencies |
| `openidx fix` | Attempt to fix common issues |
| `openidx paths` | Show important paths |
| `openidx config` | Show configuration |

### Docker

| Command | Description |
|---------|-------------|
| `openidx docker build` | Build Docker images |
| `openidx docker push` | Push images to registry |

### Cleanup

| Command | Description |
|---------|-------------|
| `openidx cleanup` | Stop and clean up development environment |
| `openidx cleanup -v` | Also remove data volumes |
| `openidx purge` | Completely remove OpenIDX (all data) |
| `openidx prune` | Prune unused Docker resources |

### Other

| Command | Description |
|---------|-------------|
| `openidx version` | Show version information |
| `openidx info` | Show project information |
| `openidx services` | List available services |
| `openidx lint` | Run linters |
| `openidx lint --fix` | Fix lint issues |
| `openidx generate` | Generate code |
| `openidx install` | Install dependencies |
| `openidx update` | Update OpenIDX to latest version |

## Global Flags

| Flag | Description |
|------|-------------|
| `-d, --dir <path>` | Project root directory |
| `-v, --verbose` | Verbose output |
| `--no-color` | Disable colored output |

## Examples

### Start development with background mode

```bash
openidx dev -b
```

### View and follow logs

```bash
openidx logs -f governance
```

### Run tests with coverage

```bash
openidx test -c
open coverage.html
```

### Reset and reseed database

```bash
openidx db reset
openidx seed
```

### Check environment health

```bash
openidx doctor
```

### Monitor service status

```bash
openidx status -w -i 5
```

## Exit Codes

- `0` - Success
- `1` - Error or failed health check

## Configuration

The CLI reads configuration from:

1. Environment variables (e.g., `DATABASE_URL`, `REDIS_URL`)
2. `.env` file in the project root
3. Command-line flags

## Contributing

When adding new commands:

1. Create a new function in `cmd/openidx/commands/`
2. Follow the naming convention: `New*Command()`
3. Use `CommandContext` for shared functionality
4. Add colored output using `GetColors()`
5. Register the command in `main.go`

## Troubleshooting

### Command not found

Make sure the CLI is built and in your PATH:

```bash
make build-cli
export PATH=$PATH:$(pwd)/bin
```

### Docker errors

Ensure Docker is running:

```bash
docker info
```

### Port conflicts

Check what's using the ports:

```bash
openidx doctor
```
