# MFA Package - TOTP Implementation

This package provides a complete implementation of TOTP (Time-based One-Time Password) authentication following RFC 6238.

## Overview

The TOTP implementation includes:
- RFC 6238 compliant TOTP generation and validation
- Constant-time comparison for security against timing attacks
- Replay attack prevention using Redis
- Encrypted secret storage using AES-256-GCM
- Database persistence with PostgreSQL
- Comprehensive test coverage

## Components

### TOTPService (`totp.go`)

Core TOTP functionality using `github.com/pquerna/otp/totp`.

#### Key Functions:

**`GenerateSecret(userID, accountName string) (*TOTPSecret, error)`**
- Generates a new TOTP secret
- Returns base32-encoded secret and QR code URL
- QR code URL can be used with authenticator apps (Google Authenticator, Authy, etc.)

**`ValidateCode(secret, code string, window int) (bool, error)`**
- Validates a TOTP code with configurable time window
- Allows for clock drift between client and server
- Default window is 1 (allows ±1 time step)

**`ValidateCodeConstantTime(secret, code string, window int) (bool, error)`**
- Validates TOTP code using constant-time comparison
- Prevents timing attacks that could leak information
- **Recommended for production use**

**`EnrollTOTP(ctx, userID, accountName) (*TOTPSecret, string, error)`**
- Handles TOTP enrollment flow
- Generates secret, encrypts it, and returns enrollment details
- Returns both plaintext secret (for QR code) and encrypted secret (for storage)

**`VerifyTOTP(ctx, userID, secret, code string) (bool, error)`**
- Validates TOTP code during authentication or enrollment
- Includes replay attack prevention using Redis
- Marks used codes to prevent reuse

### Repository (`repository.go`)

Database persistence layer for TOTP enrollments.

#### Interface:

```go
type Repository interface {
    CreateTOTP(ctx context.Context, enrollment *TOTPEnrollment) error
    GetTOTPByUserID(ctx context.Context, userID uuid.UUID) (*TOTPEnrollment, error)
    UpdateTOTP(ctx context.Context, enrollment *TOTPEnrollment) error
    DeleteTOTP(ctx context.Context, userID uuid.UUID) error
    VerifyTOTP(ctx context.Context, userID uuid.UUID) error
    MarkTOTPUsed(ctx context.Context, userID uuid.UUID) error
    Ping(ctx context.Context) error
}
```

### Service (`service.go`)

High-level service layer combining TOTP logic and persistence.

#### Methods:

**`EnrollTOTP(ctx, userID, accountName) (*TOTPSecret, error)`**
- Initiates TOTP enrollment for a user
- Removes existing enrollment if present
- Returns secret with QR code URL for user to scan

**`VerifyAndEnableTOTP(ctx, userID, code) error`**
- Verifies TOTP code during enrollment
- Marks enrollment as verified and enabled
- Called when user confirms they can generate valid codes

**`AuthenticateTOTP(ctx, userID, code) (bool, error)`**
- Validates TOTP code during authentication
- Checks if TOTP is enabled for user
- Updates last used timestamp

**`DisableTOTP(ctx, userID) error`**
- Disables TOTP for a user without removing enrollment
- Useful for temporary disable

**`GetTOTPStatus(ctx, userID) (*TOTPEnrollment, error)`**
- Returns TOTP enrollment status
- Secret is excluded from response

**`DeleteTOTP(ctx, userID) error`**
- Completely removes TOTP enrollment
- Useful when switching to different MFA method

### Encryption (`encrypter.go`)

Secret encryption utilities for secure storage.

#### AES256GCMEncrypter

Production-ready encrypter using AES-256-GCM:
- Authenticated encryption
- 32-byte key required
- Base64 encoding for storage

```go
encrypter, err := mfa.NewAES256GCMEncrypter(encryptionKey)
```

#### NoopEncrypter

No-op encrypter for testing only:
- Does not encrypt (WARNING: Do not use in production!)
- Useful for development and testing

```go
encrypter := mfa.NewNoopEncrypter()
```

## Database Schema

### Table: `mfa_totp`

```sql
CREATE TABLE mfa_totp (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    secret VARCHAR(255) NOT NULL, -- Encrypted TOTP secret
    account_name VARCHAR(255) NOT NULL, -- Account name for authenticator
    verified BOOLEAN DEFAULT false, -- User has verified TOTP setup
    enabled BOOLEAN DEFAULT false, -- TOTP is active
    backup_codes TEXT[], -- Backup recovery codes (encrypted)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE
);
```

Indexes:
- `idx_mfa_totp_user_id` on `user_id`
- `idx_mfa_totp_enabled` on `enabled`

## Configuration

### Default TOTP Configuration

```go
const (
    DefaultTOTPIssuer   = "OpenIDX"
    DefaultTOTPPeriod   = 30      // 30-second time step
    DefaultTOTPDigits   = 6       // 6-digit codes
    DefaultTOTPAlgorithm = SHA1    // RFC 6238 default
    DefaultSecretLength = 20      // 160-bit secret
    DefaultTOTPWindow  = 1        // Allow ±1 time step
)
```

### Custom Configuration

```go
config := &mfa.TOTPConfig{
    Issuer:      "MyApp",
    Period:      30,
    Digits:      totp.Digits(8),  // 8-digit codes
    Algorithm:   totp.AlgorithmSHA256,
    SecretLength: 32,
}

service := mfa.NewTOTPServiceWithConfig(logger, redis, encrypter, config)
```

## Usage Examples

### Initialization

```go
import (
    "github.com/openidx/openidx/internal/mfa"
    "github.com/redis/go-redis/v9"
    "go.uber.org/zap"
    "github.com/jackc/pgx/v5/pgxpool"
)

// Initialize logger
logger := zap.NewExample()

// Initialize database pool
pool, _ := pgxpool.New(ctx, databaseURL)

// Initialize Redis
redisClient := redis.NewClient(&redis.Options{
    Addr: "localhost:6379",
})

// Initialize encrypter (use a 32-byte key from env/config)
encryptionKey := os.Getenv("MFA_ENCRYPTION_KEY")
encrypter, _ := mfa.NewAES256GCMEncrypter(encryptionKey)

// Create service
service := mfa.NewService(logger, pool, redisClient, encrypter)
```

### Enroll User in TOTP

```go
userID := uuid.Parse("user-uuid-123")
accountName := "user@example.com"

// Generate TOTP secret
secret, err := service.EnrollTOTP(ctx, userID, accountName)
if err != nil {
    log.Fatal(err)
}

// Display QR code URL to user
fmt.Println("Scan this QR code:", secret.QRCodeURL)
fmt.Println("Or enter this code:", secret.Secret)

// User scans QR code with authenticator app
// Then user enters first code to verify
```

### Verify Enrollment

```go
code := "123456" // Code from authenticator app

err := service.VerifyAndEnableTOTP(ctx, userID, code)
if err != nil {
    // Invalid code
    return fmt.Errorf("verification failed: %w", err)
}

// TOTP is now enabled for user
```

### Authenticate with TOTP

```go
code := "654321" // Code from authenticator app

valid, err := service.AuthenticateTOTP(ctx, userID, code)
if err != nil {
    return fmt.Errorf("authentication error: %w", err)
}

if !valid {
    return fmt.Errorf("invalid code")
}

// User authenticated successfully
```

### Check TOTP Status

```go
status, err := service.GetTOTPStatus(ctx, userID)
if err != nil {
    return fmt.Errorf("failed to get status: %w", err)
}

fmt.Printf("Enabled: %v\n", status.Enabled)
fmt.Printf("Verified: %v\n", status.Verified)
fmt.Printf("Last used: %v\n", status.LastUsedAt)
```

### Disable TOTP

```go
err := service.DisableTOTP(ctx, userID)
if err != nil {
    return fmt.Errorf("failed to disable TOTP: %w", err)
}
```

## Security Considerations

### 1. Constant-Time Comparison
Always use `ValidateCodeConstantTime` instead of `ValidateCode` in production to prevent timing attacks.

### 2. Secret Encryption
Never store TOTP secrets in plaintext. Use `AES256GCMEncrypter` with a 32-byte key.

### 3. Replay Attack Prevention
The `VerifyTOTP` method automatically tracks used codes in Redis to prevent replay attacks.

### 4. Time Window Configuration
- **Development**: Window of 1-2 is acceptable
- **Production**: Window of 1 is recommended
- **High Security**: Window of 0 (no tolerance for clock skew)

### 5. Rate Limiting
Implement rate limiting on TOTP verification endpoints to prevent brute force attacks.

### 6. Backup Codes
Generate and provide backup codes for users who lose access to their authenticator device.

## Testing

Run tests:

```bash
go test ./internal/mfa/... -v
```

Run benchmarks:

```bash
go test ./internal/mfa/... -bench=. -benchmem
```

## Dependencies

- `github.com/pquerna/otp/totp` - TOTP generation and validation
- `github.com/redis/go-redis/v9` - Redis client for replay attack prevention
- `github.com/jackc/pgx/v5` - PostgreSQL driver
- `go.uber.org/zap` - Structured logging

## RFC 6238 Compliance

This implementation follows RFC 6238 (TOTP):
- HOTP algorithm with time-based counter
- Configurable time step (default 30 seconds)
- Support for SHA1, SHA256, and SHA512
- Support for 6 or 8 digit codes

## Migration

Run the migration to create the TOTP table:

```bash
psql -U openidx -d openidx -f migrations/009_add_totp_mfa.sql
```

## Troubleshooting

### Invalid TOTP Codes

1. Check system time synchronization: `timedatectl status`
2. Verify time window configuration
3. Ensure secret is correctly stored (not corrupted)

### Redis Connection Issues

1. Verify Redis is running: `redis-cli ping`
2. Check connection string in configuration
3. Ensure Redis TTL is configured correctly

### Database Errors

1. Check migration was applied: `\dt mfa_totp` in psql
2. Verify database user has proper permissions
3. Check encryption key is correct for secret decryption

## License

This implementation is part of OpenIDX and follows the project license.
