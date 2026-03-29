# governance

`import "github.com/openidx/openidx/internal/governance"`

Package governance provides access reviews, policy evaluation (via OPA), approval workflows, and just-in-time (JIT) access. Runs as the Governance Service on port **8002**.

## Service

```go
type Service struct { /* unexported fields */ }

func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service
func (s *Service) RegisterRoutes(r *gin.Engine)
```

## Access Reviews

```go
type AccessReview struct {
    ID, Name, Description string
    Type ReviewType; Status ReviewStatus; ReviewerID string
    Scope ReviewScope; StartDate, EndDate time.Time
    TotalItems, ReviewedItems int
}

type ReviewType string   // "user_access", "role_assignment", "application_access", "privileged_access"
type ReviewStatus string // "pending", "in_progress", "completed", "expired", "canceled"

type ReviewItem struct {
    ID, ReviewID, UserID, ResourceType, ResourceID string
    Decision ReviewDecision; DecidedBy string; Comments string
}
type ReviewDecision string // "pending", "approved", "revoked", "flagged"
```

## Policies

```go
type Policy struct {
    ID, Name, Description string; Type PolicyType
    Rules []PolicyRule; Enabled bool; Priority int
}
type PolicyType string // "separation_of_duty", "risk_based", "timebound", "location", "conditional_access"
type PolicyRule struct { ID string; Condition map[string]interface{}; Effect string; Priority int }
```

## Policy Evaluation (OPA)

```go
type PolicyInput struct { User PolicyUser; Resource PolicyResource; Action string; Context PolicyContext }
type PolicyResult struct { Allow bool; Denials, Warnings []string }
```

`PolicyInput` is the structure passed to OPA for evaluation. `PolicyResult` contains the allow/deny decision and any denial reasons or warnings.

## Approval Workflows

```go
type AccessRequest struct {
    ID, RequesterID, ResourceType, ResourceID, Justification, Status string
    Approvals []Approval; ExpiresAt *time.Time
}
type Approval struct { ID, RequestID, ApproverID, Decision, Comments string; StepOrder int }
type ApprovalPolicy struct {
    ID, Name, ResourceType string; ApprovalSteps []ApprovalStep
    AutoApproveConditions *AutoApproveConditions; MaxWaitHours int; Enabled bool
}
```
