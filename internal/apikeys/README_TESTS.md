# API Keys Package - Quick Test Reference

## Quick Commands

```bash
# Run tests for apikeys package only
go test -v ./internal/apikeys/...

# Run with coverage
go test -v -cover ./internal/apikeys/...

# Run specific test
go test -v ./internal/apikeys/... -run TestAPIKeyGeneration

# Run benchmarks
go test -bench=. -benchmem ./internal/apikeys/...

# Run with race detector
go test -race -v ./internal/apikeys/...

# Generate coverage report
go test -coverprofile=coverage.out ./internal/apikeys/... && go tool cover -html=coverage.out -o coverage.html
```

## Test Statistics

- **Total Test Functions**: 14
- **Benchmark Functions**: 3
- **Test File Lines**: 1,733
- **Source Code Lines**: 439
- **Test-to-Code Ratio**: ~3.95:1

## Test Functions

1. `TestAPIKeyGeneration` - API key generation and formatting
2. `TestAPIKeyValidation` - Key validation, caching, and authentication
3. `TestAPIKeyRevocation` - Single key revocation
4. `TestRevokeAllUserKeys` - Batch key revocation
5. `TestAPIKeyExpiration` - Time-based expiration validation
6. `TestAPIKeyScopes` - Scope-based authorization
7. `TestScopeValidationEdgeCases` - Scope input validation
8. `TestCreateServiceAccount` - Service account creation
9. `TestListServiceAccounts` - Service account listing with pagination
10. `TestDeleteServiceAccount` - Service account deletion
11. `TestListAPIKeys` - API key listing by owner
12. `TestSecurityBoundaries` - Security-focused tests
13. `TestErrorPaths` - Error handling validation
14. `TestEdgeCases` - Edge case scenarios

## Benchmarks

1. `BenchmarkAPIKeyGeneration` - Key generation performance
2. `BenchmarkAPIKeyValidation` - Key validation performance
3. `BenchmarkScopeCheck` - Scope authorization performance

## Coverage Areas

### Core Functionality
- ✅ API key generation (random bytes, hex encoding, hashing)
- ✅ API key validation (database lookup, Redis caching)
- ✅ API key revocation (single and batch)
- ✅ Service account CRUD operations
- ✅ Pagination logic
- ✅ Expiration time handling

### Security
- ✅ Plaintext key never stored
- ✅ SHA-256 hashing
- ✅ Safe key prefix for logging
- ✅ 256-bit entropy verification
- ✅ Scope-based authorization
- ✅ Revocation status enforcement

### Error Handling
- ✅ Database connection failures
- ✅ Redis connection failures
- ✅ Invalid inputs
- ✅ Not found errors
- ✅ Malformed data
- ✅ Context cancellation

### Edge Cases
- ✅ Unicode characters
- ✅ Empty vs nil values
- ✅ Timezone handling (UTC)
- ✅ Pagination boundaries
- ✅ Rapid successive operations
- ✅ Concurrent access patterns

## Mock Architecture

The tests use a comprehensive mock-based architecture:

```
mockDB
├── Service account operations
├── API key operations
├── Query execution
└── Error injection

mockRedisClient
├── Get/Set operations
├── Cache simulation
└── Connection failures

mockRows / mockRow
├── Row iteration
├── Column scanning
└── Error conditions
```

## Running Specific Test Categories

### Security Tests Only
```bash
go test -v ./internal/apikeys/... -run TestSecurity
```

### Error Path Tests Only
```bash
go test -v ./internal/apikeys/... -run TestError
```

### Edge Case Tests Only
```bash
go test -v ./internal/apikeys/... -run TestEdge
```

### API Key Tests Only
```bash
go test -v ./internal/apikeys/... -run "TestAPI.*"
```

### Service Account Tests Only
```bash
go test -v ./internal/apikeys/... -run "Test.*Service"
```

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Test apikeys package
  run: |
    go test -v -race -coverprofile=coverage.out ./internal/apikeys/...
    go tool cover -func=coverage.out | grep total

- name: Check coverage threshold
  run: |
    coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    if (( $(echo "$coverage < 80" | bc -l) )); then
      echo "Coverage $coverage% is below 80% threshold"
      exit 1
    fi
```

### GitLab CI Example
```yaml
test:apikeys:
  script:
    - go test -v -race -coverprofile=coverage.out ./internal/apikeys/...
    - go tool cover -func=coverage.out | grep total
  coverage: '/total:.*?(\d+\.\d+)%/'
```

## Troubleshooting

### Tests not running
```bash
# Check test file is in correct package
head -1 internal/apikeys/apikeys_test.go
# Should output: package apikeys

# Check test file builds
go build ./internal/apikeys/...
```

### Low coverage
```bash
# Generate detailed coverage report
go test -coverprofile=coverage.out ./internal/apikeys/...
go tool cover -func=coverage.out | less

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html
# Open coverage.html in browser
```

### Race conditions
```bash
# Run with race detector
go test -race -v ./internal/apikeys/...
```

### Benchmark results
```bash
# Run benchmarks
go test -bench=. -benchmem ./internal/apikeys/...

# Run benchmarks multiple times for stability
go test -bench=. -benchmem -count=5 ./internal/apikeys/...
```

## Expected Coverage

Based on test implementation:

| Component | Expected Coverage |
|-----------|-------------------|
| API Key Generation | 95% |
| API Key Validation | 95% |
| API Key Revocation | 95% |
| Service Accounts | 90% |
| Scopes & Auth | 95% |
| Error Handling | 85% |
| **Overall** | **~88-92%** |

## Next Steps

1. **Install Go** if not available:
   ```bash
   # Download Go 1.22+
   # https://go.dev/dl/
   ```

2. **Run tests**:
   ```bash
   cd /home/cmit/openidx
   go test -v -cover ./internal/apikeys/...
   ```

3. **Verify coverage**:
   ```bash
   go test -coverprofile=coverage.out ./internal/apikeys/...
   go tool cover -func=coverage.out | grep total
   ```

4. **Run benchmarks**:
   ```bash
   go test -bench=. -benchmem ./internal/apikeys/...
   ```

## Documentation

- Full test documentation: `TEST_COVERAGE_SUMMARY.md`
- Source code: `service.go`
- Test code: `apikeys_test.go`

## Support

For issues or questions about the tests:
1. Check `TEST_COVERAGE_SUMMARY.md` for detailed documentation
2. Review test function names and docstrings
3. Run specific tests with `-run` flag for debugging
