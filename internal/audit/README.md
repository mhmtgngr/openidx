# Audit Logger

The `audit` package provides tamper-evident audit logging with blockchain-style cryptographic chaining for enterprise compliance and security.

## Overview

The audit logger provides:
- **Tamper-evident logging**: Each event is cryptographically linked to the previous one
- **SHA-256 checksums**: Ensures data integrity
- **Immutable storage**: Append-only interface prevents event modification
- **Chain verification**: Detects any tampering with audit logs

## Usage

### Basic Setup

```go
import (
    "context"
    "github.com/openidx/openidx/internal/audit"
    "github.com/openidx/openidx/pkg/storage"
)

// Create an in-memory store (for testing/development)
store := storage.NewMemoryAppendOnlyStore()
logger := audit.NewAuditLogger(store)

// Or use file-based storage (for production)
store, err := storage.NewFileAppendOnlyStore("/var/log/openidx/audit.log")
if err != nil {
    log.Fatal(err)
}
logger := audit.NewAuditLogger(store)
```

### Logging Events

```go
ctx := context.Background()

event := audit.AuditEvent{
    EventType:    "authentication",
    ActorID:      "user-123",
    ActorType:    "user",
    ResourceID:   "api-endpoint",
    ResourceType: "api",
    Action:       "login",
    Metadata: map[string]interface{}{
        "ip":         "192.168.1.100",
        "user_agent": "Mozilla/5.0",
        "success":    true,
    },
}

if err := logger.LogEvent(ctx, event); err != nil {
    log.Printf("Failed to log event: %v", err)
}
```

### Querying Events

```go
// Get event by ID
event, err := logger.GetEventByID(ctx, "event-id")
if err != nil {
    // handle error
}

// Get events by time range
start := time.Now().Add(-24 * time.Hour)
end := time.Now()
events, err := logger.GetEventsByTimeRange(ctx, start, end)

// Get events by actor
events, err := logger.GetEventsByActor(ctx, "user-123")

// Get events by resource
events, err := logger.GetEventsByResource(ctx, "resource-456")

// Get events by type
events, err := logger.GetEventsByType(ctx, "authentication")
```

### Verifying Chain Integrity

```go
// Verify the entire audit chain
valid, err := logger.VerifyChain(ctx)
if err != nil {
    log.Printf("Chain verification error: %v", err)
} else if !valid {
    log.Println("WARNING: Audit chain has been tampered with!")
}

// Verify a single event's checksum
if logger.VerifyChecksum(event) {
    log.Println("Event checksum is valid")
} else {
    log.Println("WARNING: Event checksum is invalid!")
}
```

## Architecture

### AuditEvent Structure

Each audit event contains:
- `ID`: Unique identifier (UUID)
- `Timestamp`: When the event occurred
- `EventType`: Category of event (authentication, authorization, etc.)
- `ActorID`, `ActorType`: Who performed the action
- `ResourceID`, `ResourceType`: What was affected
- `Action`: The action performed
- `Metadata`: Additional context as key-value pairs
- `Checksum`: SHA-256 hash of event + previous hash
- `PreviousHash`: Checksum of the previous event

### Chain Integrity

Events are cryptographically linked:
```
Event 1: Checksum = SHA256(Event1_Data + "")
Event 2: Checksum = SHA256(Event2_Data + Checksum1)
Event 3: Checksum = SHA256(Event3_Data + Checksum2)
...
```

This creates a tamper-evident chain where modifying any event breaks all subsequent checksums.

### Storage Interface

The `AppendOnlyStore` interface provides:
- `Append(data []byte)`: Add new data (immutable)
- `ReadAll()`: Read all entries
- `GetLastHash()`: Get last event's checksum for chaining

Implementations:
- `MemoryAppendOnlyStore`: In-memory (testing/dev)
- `FileAppendOnlyStore`: File-based with locking (production)

## Event Types

Common event types:
- `authentication`: Login, logout, MFA
- `authorization`: Permission checks, access denials
- `user_management`: User creation, modification, deletion
- `group_management`: Group changes
- `role_management`: Role assignments
- `configuration`: System config changes
- `data_access`: Data read/write operations
- `system`: System events, errors

## Compliance Features

The audit logger supports compliance requirements:

- **SOX/ISO 27001**: Tamper-evident logging
- **SOC 2**: Immutable audit trails
- **GDPR**: Data access logging
- **PCI DSS**: Audit log retention and integrity
- **HIPAA**: Access tracking for PHI

## Performance Considerations

- File-based store uses O(1) append operations
- Chain verification is O(n) where n = number of events
- Consider periodic compaction for long-running deployments
- Use time-range queries to limit data processed

## Security Notes

1. **File permissions**: Ensure audit logs have restricted permissions (0600)
2. **Log rotation**: Implement log rotation with backup/retention
3. **Monitoring**: Alert on chain verification failures
4. **Backup**: Regular backup of immutable audit logs
5. **Access control**: Limit write access to audit service only

## Example: Audit Middleware

```go
func AuditMiddleware(logger *audit.AuditLogger) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()

        // Process request
        c.Next()

        // Log audit event
        event := audit.AuditEvent{
            EventType: "data_access",
            ActorID:   getUserID(c),
            Action:    c.Request.Method + " " + c.Request.URL.Path,
            Metadata: map[string]interface{}{
                "status":      c.Writer.Status(),
                "latency_ms":  time.Since(start).Milliseconds(),
                "path":        c.Request.URL.Path,
            },
        }

        logger.LogEvent(c.Request.Context(), event)
    }
}
```
