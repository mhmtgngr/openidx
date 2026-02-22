# TOTP Implementation Summary

This document summarizes the TOTP (Time-based One-Time Password) implementation for OpenIDX.

## Files Created

### 1. `internal/mfa/totp.go`
Core TOTP functionality implementing RFC 6238.

**Key Features:**
- `GenerateSecret(userID, accountName)` - Generates TOTP secret with QR code URL
- `ValidateCode(secret, code, window)` - Validates TOTP with configurable time window
- `ValidateCodeConstantTime(secret, code, window)` - Constant-time validation (prevents timing attacks)
- `EnrollTOTP(ctx, userID, accountName)` - Handles enrollment with encryption
- `VerifyTOTP(ctx, userID, secret, code)` - Validation with replay attack prevention

**Security Features:**
- Constant-time comparison using `crypto/subtle.ConstantTimeCompare`
- Replay attack prevention using Redis
- Configurable time window for clock drift tolerance
- Base32 encoding for compatibility with authenticator apps

### 2. `internal/mfa/repository.go`
Database persistence layer for TOTP enrollments.

**Interface Methods:**
- `CreateTOTP(ctx, enrollment)` - Create new enrollment
- `GetTOTPByUserID(ctx, userID)` - Retrieve enrollment
- `UpdateTOTP(ctx, enrollment)` - Update enrollment
- `DeleteTOTP(ctx, userID)` - Delete enrollment
- `VerifyTOTP(ctx, userID)` - Mark as verified
- `MarkTOTPUsed(ctx, userID)` - Update last used timestamp

**Data Model:**
```go
type TOTPEnrollment struct {
    ID          uuid.UUID
    UserID      uuid.UUID
    Secret      string    // Encrypted
    AccountName string
    Verified    bool
    Enabled     bool
    BackupCodes []string
    CreatedAt   time.Time
    VerifiedAt  *time.Time
    LastUsedAt  *time.Time
}
```

### 3. `internal/mfa/service.go`
High-level service layer combining TOTP logic and persistence.

**Public Methods:**
- `EnrollTOTP(ctx, userID, accountName)` - Initiate enrollment
- `VerifyAndEnableTOTP(ctx, userID, code)` - Complete enrollment
- `AuthenticateTOTP(ctx, userID, code)` - Authenticate with TOTP
- `DisableTOTP(ctx, userID)` - Disable TOTP
- `GetTOTPStatus(ctx, userID)` - Get enrollment status
- `DeleteTOTP(ctx, userID)` - Remove enrollment

### 4. `internal/mfa/encrypter.go`
Secret encryption utilities.

**AES256GCMEncrypter (Production):**
- AES-256-GCM authenticated encryption
- 32-byte key requirement
- Base64 encoding for database storage
- Nonce included with ciphertext

**NoopEncrypter (Testing):**
- No-op encryption for development/testing
- WARNING: Not for production use

### 5. `migrations/009_add_totp_mfa.sql`
Database migration for TOTP table.

**Table: `mfa_totp`**
- `id` - UUID primary key
- `user_id` - Foreign key to users (unique)
- `secret` - Encrypted TOTP secret
- `account_name` - Display name in authenticator
- `verified` - Verification status
- `enabled` - Active status
- `backup_codes` - Recovery codes array
- `created_at`, `verified_at`, `last_used_at` - Timestamps

### 6. `internal/mfa/totp_test.go`
Comprehensive test suite.

**Test Coverage:**
- Secret generation
- Code validation (with/without window)
- Constant-time comparison
- Enrollment flow
- Verification flow
- Replay attack prevention
- Time-based code generation
- Encryption/decryption
- Benchmarks

### 7. `internal/mfa/example_test.go`
Usage examples for all major operations.

### 8. `internal/mfa/README.md`
Complete documentation including:
- Overview and architecture
- API reference
- Usage examples
- Security considerations
- Troubleshooting guide

## Technical Details

### RFC 6238 Compliance

The implementation follows RFC 6238 (TOTP):
- HOTP algorithm with time-based counter
- Default 30-second time step
- Support for SHA1, SHA256, SHA512
- Support for 6 or 8 digit codes
- Base32 encoding (RFC 4648)

### Security Features

1. **Constant-Time Comparison**
   - Prevents timing attacks
   - Uses `crypto/subtle.ConstantTimeCompare`
   - Recommended for all validation

2. **Replay Attack Prevention**
   - Tracks used codes in Redis
   - TTL of 5 minutes for used codes
   - Prevents code reuse

3. **Secret Encryption**
   - AES-256-GCM encryption
   - Separate encryption key
   - Nonce included with ciphertext
   - Base64 encoding for storage

4. **Time Window Configuration**
   - Allows for clock drift
   - Default: ±1 time step (±30 seconds)
   - Configurable per validation

### Dependencies

- `github.com/pquerna/otp/totp` - TOTP generation/validation
- `github.com/redis/go-redis/v9` - Replay attack prevention
- `github.com/jackc/pgx/v5` - PostgreSQL persistence
- `go.uber.org/zap` - Structured logging

## Configuration

### Environment Variables

```bash
# Encryption key (32 bytes for AES-256)
MFA_ENCRYPTION_KEY=your-32-byte-encryption-key

# Redis for replay attack prevention
REDIS_URL=redis://:password@localhost:6379

# Database
DATABASE_URL=postgres://user:pass@localhost:5432/openidx
```

### Default Configuration

```go
const (
    DefaultTOTPIssuer   = "OpenIDX"
    DefaultTOTPPeriod   = 30        // seconds
    DefaultTOTPDigits   = 6         // digits
    DefaultTOTPAlgorithm = SHA1     // RFC 6238 default
    DefaultSecretLength = 20        // bytes (160 bits)
    DefaultTOTPWindow  = 1         // time steps
)
```

## Usage Workflow

### Enrollment Flow

1. User requests TOTP enrollment
2. Server generates secret and QR code URL
3. User scans QR code with authenticator app
4. User enters first code to verify setup
5. Server verifies code and enables TOTP

### Authentication Flow

1. User enters password
2. Server prompts for TOTP code
3. User enters code from authenticator app
4. Server validates code (with replay protection)
5. Access granted if valid

## Testing

Run tests:
```bash
go test ./internal/mfa/... -v
```

Run benchmarks:
```bash
go test ./internal/mfa/... -bench=. -benchmem
```

## Migration

Apply the migration:
```bash
psql -U openidx -d openidx -f migrations/009_add_totp_mfa.sql
```

## Integration Points

The TOTP service integrates with:
- Identity Service (user enrollment)
- Authentication Service (login validation)
- Admin Console (TOTP management UI)

## Future Enhancements

Possible improvements:
- Backup code generation and validation
- TOTP with custom algorithms (SHA256, SHA512)
- Multiple TOTP devices per user
- TOTP usage analytics
- Risk-based TOTP requirements

## Compliance

This implementation supports:
- RFC 6238 (TOTP)
- NIST SP 800-63B guidelines
- OAuth 2.0 MFA requirements
- PCI-DSS MFA requirements

## Notes

- TOTP secrets are sensitive - always encrypt at rest
- Use constant-time comparison in production
- Implement rate limiting on verification endpoints
- Provide backup codes for account recovery
- Monitor for suspicious TOTP patterns
- Keep system time synchronized (NTP)
