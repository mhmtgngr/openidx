# Testing

## Go Tests

### Unit Tests

```bash
# Run all unit tests
make test

# Run with verbose output
go test -v ./...

# Run with race detector
go test -race ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Integration Tests

Integration tests require running infrastructure (PostgreSQL, Redis):

```bash
# Start infrastructure first
make dev-infra

# Run integration tests
make test-integration

# Or directly
go test -v -tags=integration ./test/integration/...
```

### Test Structure

Tests follow the existing pattern in `internal/identity/service_test.go`:

- Model serialization tests — verify struct fields and JSON tags
- Type constant tests — verify enum values are correct
- Handler tests — verify HTTP error handling for invalid input
- Business logic tests — verify calculations and validations

## Frontend Tests

### Running Tests

```bash
cd web/admin-console

# Run all tests
npm test

# Run in watch mode
npx vitest

# Run with coverage
npx vitest --coverage
```

### Test Setup

- **Framework**: Vitest + React Testing Library
- **DOM**: jsdom
- **Setup file**: `src/test/setup.ts` (mocks for IntersectionObserver, matchMedia, crypto)

### Test Files

Tests are colocated with their source files:

```
src/
├── lib/
│   ├── utils.ts
│   └── utils.test.ts
└── components/ui/
    ├── button.tsx
    ├── button.test.tsx
    ├── card.tsx
    ├── card.test.tsx
    ├── badge.tsx
    ├── badge.test.tsx
    ├── input.tsx
    └── input.test.tsx
```

### Writing Tests

```tsx
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Button } from './button'

describe('Button', () => {
  it('handles click events', async () => {
    const onClick = vi.fn()
    render(<Button onClick={onClick}>Click me</Button>)
    await userEvent.click(screen.getByRole('button'))
    expect(onClick).toHaveBeenCalledOnce()
  })
})
```

## CI/CD

Tests run automatically in GitHub Actions:

- **Go CI** (`.github/workflows/ci.yml`) — build, lint, test with race detector + coverage, govulncheck
- **Frontend CI** (`.github/workflows/ci-web.yml`) — lint, type check, build, test
- **CodeQL** (`.github/workflows/codeql.yml`) — static security analysis for Go and TypeScript
