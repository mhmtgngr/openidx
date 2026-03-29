# audit

`import "github.com/openidx/openidx/internal/audit"`

Package audit provides tamper-evident event logging, compliance reporting, real-time WebSocket streaming, and webhook delivery. Runs as the Audit Service on port **8004**.

## Service

```go
type Service struct { /* unexported fields */ }

func NewService(db *database.PostgresDB, es *database.ElasticsearchClient, cfg *config.Config, logger *zap.Logger) *Service
```

## Handler

```go
type Handler struct { /* unexported fields */ }

func NewHandler(store *Store, searcher *Searcher, logger *zap.Logger) *Handler
func (h *Handler) RegisterRoutes(r *gin.RouterGroup)
```

Registered routes: `GET /events`, `GET /events/:id`, `GET /integrity`.

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

## Store (Tamper-Evident)

```go
type Store struct { /* unexported fields: buffer, HMAC secret, batch config */ }
type StoreConfig struct { BatchSize int; FlushInterval time.Duration; Secret string }

func DefaultStoreConfig() StoreConfig
func NewStore(db *pgxpool.Pool, config StoreConfig, logger *zap.Logger) (*Store, error)
```

Events are buffered and batch-flushed. Each event is chained via HMAC for tamper detection.

## Search

```go
type Searcher struct { /* unexported fields */ }
func NewSearcher(db *pgxpool.Pool, secret string) *Searcher
func (s *Searcher) Search(ctx context.Context, query *SearchQuery) (*SearchResult, error)

type SearchQuery struct { ActorID, Action, ResourceType, Outcome, TenantID string; From, To time.Time; AfterID string; Limit int }
type SearchResult struct { Events []*AuditEvent; NextCursor string; HasMore bool; TotalCount int }
```

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
