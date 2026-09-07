# audit

`import "github.com/openidx/openidx/internal/audit"`

Package audit provides tamper-evident event logging, compliance reporting, real-time WebSocket streaming, and webhook delivery. Runs as the Audit Service on port **8004**.

## Service

```go
type Service struct { /* unexported fields */ }

func NewService(db *database.PostgresDB, es *database.ElasticsearchClient, cfg *config.Config, logger *zap.Logger) *Service
```

## Routes

```go
func RegisterRoutes(router *gin.Engine, svc *Service, extraMiddleware ...gin.HandlerFunc)
```

`POST /api/v1/audit/events` is the ingestion endpoint and is deliberately outside
the authenticated group: it is the server-to-server write path (access-service
posts proxy-access events with no user token) and is protected by network
isolation. Everything else reads or exports the trail and carries the JWT
middleware passed as `extraMiddleware`: `GET /events`, `GET /events/:id`,
`GET /events/search`, `GET /event-types`, `GET /chain/verify`,
`GET /statistics`, `GET /usage`, the `/reports` group and `POST /export`.

## Audit Events

```go
type ServiceAuditEvent struct {
    ID string; Timestamp time.Time
    EventType EventType; Category EventCategory; Action string; Outcome ServiceEventOutcome
    ActorID, ActorType, ActorIP, TargetID, TargetType, ResourceID string
    Details map[string]interface{}; SessionID, RequestID string
}

type EventType string     // "authentication", "authorization", "user_management", "group_management", "role_management", "configuration", "data_access", "system"
type EventCategory string // "security", "compliance", "operational", "access"
type ServiceEventOutcome string // "success", "failure", "pending"
```

## Tamper evidence (hash chain)

```go
type ChainSealer struct { /* unexported fields */ }
func NewChainSealer(db poolQuerier, secret string, log *zap.Logger) (*ChainSealer, error)
func (s *ChainSealer) Start(ctx context.Context, interval time.Duration)
func (s *ChainSealer) SealAll(ctx context.Context) (int, error)
func (s *ChainSealer) SealOrg(ctx context.Context, orgID string) (int, error)
func (s *ChainSealer) VerifyChain(ctx context.Context, orgID string) (*ChainVerification, error)

type ChainVerification struct {
    OrgID string; Sealed, Unsealed, LastSeq int64
    Intact bool; Break, BreakEventID string
}
```

Audit rows are written unchained and sealed by a background sweep, which chains
each organization's events into its own sequence: `chain_seq` dense from 1,
`prev_hash` linking to the event before it, and `event_hash` an HMAC-SHA256 over
a canonical form of **every** stored column (migration v181 adds the three
columns). The sweep runs under a per-org advisory lock, so one order is
produced no matter how many services are writing.

Sealing is a sweep rather than a hash on insert because sixteen statements
across the tree insert into `audit_events`, several inside request transactions:
taking a per-org lock at each would put a serialization point in the middle of
login. The consequence is stated rather than hidden — an event is tamper-evident
once sealed, and `VerifyChain` reports the unsealed count so the sweep's lag is
visible in the evidence rather than assumed away.

The chain detects an edit to any sealed row, a deleted sealed row (the gap in
`chain_seq` cannot be closed without recomputing every later hash) and a row
backdated into a sealed run. It does not protect a row that has not been sealed
yet, nor defend against an attacker holding the HMAC key — which is why
`AUDIT_CHAIN_SECRET` is generated separately from every other secret and belongs
in a different trust domain from the audit database.

### Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUDIT_CHAIN_SECRET` | *(empty)* | HMAC key. Empty means the chain does not run; `ValidateProduction` refuses a production start without it. `scripts/generate-secrets.sh` writes one. |
| `AUDIT_CHAIN_INTERVAL` | `60s` | How often the sweep looks for unsealed rows. |

### Verifying a trail

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://localhost:8004/api/v1/audit/chain/verify
```

```json
{
  "enabled": true,
  "org_id": "…",
  "sealed_events": 18342,
  "unsealed_events": 7,
  "last_sequence": 18342,
  "intact": true
}
```

`intact: false` carries `break` (what is wrong, in a sentence) and
`break_event_id` (where). `enabled: false` means no secret is configured: the
trail is readable and complete, and it carries no tamper evidence.

## Search

```go
func (s *Service) QueryEvents(ctx context.Context, query *AuditQuery) ([]ServiceAuditEvent, int, error)

type AuditQuery struct {
    StartTime, EndTime *time.Time
    EventType EventType; Category EventCategory
    ActorID, TargetID string; Outcome ServiceEventOutcome
    Offset, Limit int
}
```

Full-text search goes through Elasticsearch when it is configured
(`GET /events/search`); `QueryEvents` reads PostgreSQL, which is authoritative.

## WebSocket Streaming

```go
type EventStreamer struct { /* unexported fields */ }
func NewEventStreamer(logger *zap.Logger, service *Service, allowedOrigins []string) *EventStreamer

type StreamClient struct { ID string; Conn *websocket.Conn; Filters *StreamFilters }
type StreamFilters struct { EventTypes []EventType; Categories []EventCategory; ActorID string }
```

## Origin Validation

```go
type OriginValidator struct { /* unexported fields */ }
func NewOriginValidator(logger *zap.Logger, allowedOrigins []string, enableLogging bool) *OriginValidator
func (ov *OriginValidator) CheckOrigin(r *http.Request) bool
```

When no allowed origins are configured, enforces same-origin policy. Supports wildcard (`*`) entries.

## Compliance Reports

```go
type ComplianceReport struct { ID, Name string; Type ReportType; Framework string; Status ReportStatus; Summary ReportSummary; Findings []ReportFinding }
type ReportType string   // "soc2", "iso27001", "gdpr", "hipaa", "pci_dss", "custom"
type ReportStatus string // "pending", "generating", "completed", "failed"
```
