# OpenIDX Testing Guide

This guide explains how to write, run, and maintain tests for the OpenIDX project.

---

## Table of Contents

1. [Test Structure](#test-structure)
2. [Running Tests](#running-tests)
3. [Unit Tests](#unit-tests)
4. [Integration Tests](#integration-tests)
5. [End-to-End Tests](#end-to-end-tests)
6. [Test Coverage](#test-coverage)
7. [Best Practices](#best-practices)
8. [Mock Examples](#mock-examples)

---

## Test Structure

```
openidx/
├── internal/
│   ├── identity/
│   │   ├── service.go
│   │   └── service_test.go         # Unit tests
│   ├── governance/
│   │   ├── service.go
│   │   └── service_test.go
│   └── ...
├── test/
│   ├── integration/                # Integration tests
│   │   ├── identity_test.go
│   │   ├── governance_test.go
│   │   └── setup_test.go
│   └── e2e/                        # End-to-end tests
│       ├── user_flow_test.go
│       └── admin_flow_test.go
└── coverage.html                   # Coverage report
```

---

## Running Tests

### All Tests
```bash
# Run all unit tests
make test

# Or directly with go
go test -v ./...
```

### Specific Package
```bash
# Test identity service only
go test -v ./internal/identity/

# Test with verbose output
go test -v ./internal/identity/ -run TestGetUser
```

### With Coverage
```bash
# Generate coverage report
make test-coverage

# View coverage in browser
open coverage.html

# Or generate inline
go test -v -cover ./...
```

### Integration Tests
```bash
# Requires running infrastructure (DB, Redis, etc.)
make dev-infra

# Run integration tests
make test-integration

# Or directly
go test -v -tags=integration ./test/integration/...
```

### Watch Mode (for development)
```bash
# Install entr for file watching
# On macOS: brew install entr
# On Linux: apt-get install entr

# Auto-run tests on file change
find . -name "*.go" | entr -c go test -v ./internal/identity/
```

---

## Unit Tests

### Test File Naming
- Test files must end with `_test.go`
- Place test files in the same package as code being tested
- Example: `service.go` → `service_test.go`

### Basic Test Structure

```go
package identity

import (
    "context"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestGetUser tests the GetUser method
func TestGetUser(t *testing.T) {
    // Arrange - setup test data
    ctx := context.Background()
    userID := "user-123"

    // Act - execute the function
    user, err := service.GetUser(ctx, userID)

    // Assert - verify results
    assert.NoError(t, err)
    assert.NotNil(t, user)
    assert.Equal(t, userID, user.ID)
}
```

### Table-Driven Tests (Recommended)

```go
func TestCreateUser(t *testing.T) {
    tests := []struct {
        name          string
        input         *User
        expectedError bool
        errorMessage  string
    }{
        {
            name: "Valid user",
            input: &User{
                Username: "john.doe",
                Email:    "john@example.com",
            },
            expectedError: false,
        },
        {
            name: "Missing email",
            input: &User{
                Username: "john.doe",
            },
            expectedError: true,
            errorMessage:  "email is required",
        },
        {
            name: "Invalid email format",
            input: &User{
                Username: "john.doe",
                Email:    "not-an-email",
            },
            expectedError: true,
            errorMessage:  "invalid email format",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := service.CreateUser(context.Background(), tt.input)

            if tt.expectedError {
                assert.Error(t, err)
                if tt.errorMessage != "" {
                    assert.Contains(t, err.Error(), tt.errorMessage)
                }
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

### Testing with Mocks

```go
// Create mock interface
type MockDatabase struct {
    mock.Mock
}

func (m *MockDatabase) GetUser(ctx context.Context, id string) (*User, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*User), args.Error(1)
}

// Use in test
func TestGetUserWithMock(t *testing.T) {
    mockDB := new(MockDatabase)

    // Setup expectations
    expectedUser := &User{ID: "user-123", Username: "john"}
    mockDB.On("GetUser", mock.Anything, "user-123").Return(expectedUser, nil)

    // Test
    user, err := mockDB.GetUser(context.Background(), "user-123")

    // Verify
    assert.NoError(t, err)
    assert.Equal(t, expectedUser, user)
    mockDB.AssertExpectations(t)
}
```

---

## Integration Tests

Integration tests require running infrastructure (database, Redis, etc.).

### Setup Integration Test

```go
// +build integration

package integration

import (
    "context"
    "testing"

    "github.com/openidx/openidx/internal/common/database"
    "github.com/openidx/openidx/internal/identity"
)

var (
    testDB    *database.PostgresDB
    testRedis *database.RedisClient
)

// TestMain runs before all tests
func TestMain(m *testing.M) {
    // Setup
    var err error
    testDB, err = database.NewPostgres("postgres://openidx:openidx_secret@localhost:5432/openidx_test")
    if err != nil {
        panic(err)
    }

    testRedis, err = database.NewRedis("redis://:redis_secret@localhost:6379/1")
    if err != nil {
        panic(err)
    }

    // Run tests
    code := m.Run()

    // Cleanup
    testDB.Close()
    testRedis.Close()

    os.Exit(code)
}

func TestIdentityServiceIntegration(t *testing.T) {
    ctx := context.Background()

    // Create service with real DB
    svc := identity.NewService(testDB, testRedis, cfg, logger)

    // Test create user
    user := &identity.User{
        ID:       "test-user-001",
        Username: "integration.test",
        Email:    "integration@test.com",
    }

    err := svc.CreateUser(ctx, user)
    assert.NoError(t, err)

    // Test retrieve user
    retrieved, err := svc.GetUser(ctx, user.ID)
    assert.NoError(t, err)
    assert.Equal(t, user.Username, retrieved.Username)

    // Cleanup
    err = svc.DeleteUser(ctx, user.ID)
    assert.NoError(t, err)
}
```

### Running Integration Tests

```bash
# Start test infrastructure
docker-compose -f deployments/docker/docker-compose.yml up -d postgres redis

# Run integration tests
go test -v -tags=integration ./test/integration/

# Cleanup
docker-compose -f deployments/docker/docker-compose.yml down
```

---

## End-to-End Tests

E2E tests verify complete user flows through the API.

### API Test Example

```go
func TestUserCRUDFlow(t *testing.T) {
    baseURL := "http://localhost:8001"

    // Create user
    createReq := map[string]interface{}{
        "id":       "e2e-user-001",
        "username": "e2e.test",
        "email":    "e2e@test.com",
    }

    resp, err := http.Post(
        baseURL+"/api/v1/identity/users",
        "application/json",
        jsonBody(createReq),
    )
    assert.NoError(t, err)
    assert.Equal(t, http.StatusCreated, resp.StatusCode)

    // Get user
    resp, err = http.Get(baseURL + "/api/v1/identity/users/e2e-user-001")
    assert.NoError(t, err)
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var user map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&user)
    assert.Equal(t, "e2e.test", user["username"])

    // Delete user
    req, _ := http.NewRequest("DELETE", baseURL+"/api/v1/identity/users/e2e-user-001", nil)
    resp, err = http.DefaultClient.Do(req)
    assert.NoError(t, err)
    assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}
```

---

## Test Coverage

### Generate Coverage Report

```bash
# Run tests with coverage
go test -v -coverprofile=coverage.out ./...

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html

# Open in browser
open coverage.html
```

### Coverage by Package

```bash
# Show coverage per package
go test -cover ./...

# Example output:
# ok      github.com/openidx/openidx/internal/identity    0.123s  coverage: 75.2% of statements
# ok      github.com/openidx/openidx/internal/governance  0.089s  coverage: 68.5% of statements
```

### Coverage Goals
- **Target**: 80% overall coverage
- **Minimum**: 70% per package
- **Critical paths**: 90%+ coverage (auth, security, data validation)

---

## Best Practices

### 1. Test Naming
```go
// Good: Clear, descriptive names
func TestGetUser_WithValidID_ReturnsUser(t *testing.T)
func TestCreateUser_WithMissingEmail_ReturnsError(t *testing.T)

// Bad: Vague names
func TestGetUser1(t *testing.T)
func TestFunction(t *testing.T)
```

### 2. Use Subtests
```go
func TestUserOperations(t *testing.T) {
    t.Run("Create", func(t *testing.T) {
        // Test create
    })

    t.Run("Update", func(t *testing.T) {
        // Test update
    })

    t.Run("Delete", func(t *testing.T) {
        // Test delete
    })
}
```

### 3. Test Setup and Cleanup
```go
func TestWithCleanup(t *testing.T) {
    // Setup
    user := createTestUser(t)

    // Cleanup - runs even if test fails
    t.Cleanup(func() {
        deleteTestUser(t, user.ID)
    })

    // Test logic
    // ...
}
```

### 4. Parallel Tests
```go
func TestParallel(t *testing.T) {
    t.Parallel() // Run in parallel with other tests

    // Test logic
}
```

### 5. Test Helpers
```go
// helper.go
func createTestUser(t *testing.T, username string) *User {
    t.Helper() // Mark as helper

    user := &User{Username: username}
    // ... create user
    return user
}
```

### 6. Assert vs Require
```go
// Use assert when test can continue after failure
assert.Equal(t, expected, actual) // Continue running

// Use require when test must stop after failure
require.NoError(t, err) // Stop if error
require.NotNil(t, user) // Stop if nil
```

### 7. Table-Driven Tests
```go
// Preferred: Easy to add new cases
tests := []struct {
    name     string
    input    string
    expected string
}{
    {"case1", "input1", "output1"},
    {"case2", "input2", "output2"},
}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        result := function(tt.input)
        assert.Equal(t, tt.expected, result)
    })
}
```

---

## Mock Examples

### Mock Database

```go
type MockDB struct {
    users map[string]*User
}

func (m *MockDB) GetUser(ctx context.Context, id string) (*User, error) {
    user, ok := m.users[id]
    if !ok {
        return nil, errors.New("user not found")
    }
    return user, nil
}

func (m *MockDB) CreateUser(ctx context.Context, user *User) error {
    m.users[user.ID] = user
    return nil
}
```

### Mock HTTP Client

```go
type MockHTTPClient struct {
    Response *http.Response
    Error    error
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
    return m.Response, m.Error
}

// Usage
mockClient := &MockHTTPClient{
    Response: &http.Response{
        StatusCode: 200,
        Body:       ioutil.NopCloser(strings.NewReader(`{"id": "123"}`)),
    },
}
```

---

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.22'

      - name: Install dependencies
        run: go mod download

      - name: Run tests
        run: make test

      - name: Run integration tests
        run: make test-integration

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.out
```

---

## Test Database Setup

### Create Test Database

```sql
-- Create test database
CREATE DATABASE openidx_test;

-- Run migrations
psql -U openidx -d openidx_test < deployments/docker/init-db.sql
```

### Use Separate Test DB

```go
const (
    devDatabaseURL  = "postgres://openidx:secret@localhost:5432/openidx"
    testDatabaseURL = "postgres://openidx:secret@localhost:5432/openidx_test"
)

func getTestDB() *database.PostgresDB {
    db, err := database.NewPostgres(testDatabaseURL)
    if err != nil {
        panic(err)
    }
    return db
}
```

---

## Benchmarking

### Write Benchmarks

```go
func BenchmarkGetUser(b *testing.B) {
    ctx := context.Background()
    svc := setupService()

    b.ResetTimer() // Reset timer after setup

    for i := 0; i < b.N; i++ {
        _, _ = svc.GetUser(ctx, "user-123")
    }
}

func BenchmarkListUsers(b *testing.B) {
    ctx := context.Background()
    svc := setupService()

    b.Run("10 users", func(b *testing.B) {
        for i := 0; i < b.N; i++ {
            _, _, _ = svc.ListUsers(ctx, 0, 10)
        }
    })

    b.Run("100 users", func(b *testing.B) {
        for i := 0; i < b.N; i++ {
            _, _, _ = svc.ListUsers(ctx, 0, 100)
        }
    })
}
```

### Run Benchmarks

```bash
# Run all benchmarks
go test -bench=. ./...

# Run specific benchmark
go test -bench=BenchmarkGetUser ./internal/identity/

# With memory allocation stats
go test -bench=. -benchmem ./...

# Example output:
# BenchmarkGetUser-8          10000    120543 ns/op    2048 B/op    15 allocs/op
# BenchmarkListUsers/10-8     5000     235689 ns/op    4096 B/op    42 allocs/op
```

---

## Troubleshooting Tests

### Tests Hang
```bash
# Add timeout
go test -timeout 30s ./...
```

### Race Conditions
```bash
# Run with race detector
go test -race ./...
```

### Verbose Output
```bash
# See all test output
go test -v ./...

# See individual test logs
go test -v -run TestGetUser ./internal/identity/
```

### Failed Tests
```bash
# Run only failed tests
go test -failfast ./...

# Stop on first failure
```

---

## Resources

- [Go Testing Documentation](https://golang.org/pkg/testing/)
- [Testify Library](https://github.com/stretchr/testify)
- [Table Driven Tests](https://github.com/golang/go/wiki/TableDrivenTests)
- [Go Test Comments](https://golang.org/cmd/go/#hdr-Test_packages)

---

## Next Steps

1. ✅ Read this guide
2. ✅ Run existing tests: `make test`
3. ✅ Add tests for new features
4. ✅ Achieve 80% coverage
5. ✅ Set up CI/CD pipeline
6. ✅ Write integration tests
7. ✅ Add E2E tests

---

**Remember**: Good tests are:
- **Fast** - Run quickly
- **Independent** - Don't depend on other tests
- **Repeatable** - Same result every time
- **Self-validating** - Pass or fail clearly
- **Timely** - Written with or before code
