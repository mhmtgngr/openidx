# provisioning

`import "github.com/openidx/openidx/internal/provisioning"`

Package provisioning provides SCIM 2.0 user and group provisioning, automated lifecycle rules, and patch operations. Runs as the Provisioning Service on port **8003**.

## Service

```go
type Service struct { /* unexported fields */ }

func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service
func (s *Service) RegisterRoutes(r *gin.Engine)
```

Routes are registered under `/scim/v2/` for SCIM endpoints and `/api/v1/provisioning/` for management endpoints.

## SCIM 2.0 Types

```go
type SCIMUser struct {
    Schemas []string; ID, ExternalID, UserName, DisplayName string
    Name SCIMName; Emails []SCIMEmail; Active bool
    Groups []SCIMGroupRef; Meta SCIMMeta
}
type SCIMGroup struct {
    Schemas []string; ID, ExternalID, DisplayName string
    Members []SCIMMember; Meta SCIMMeta
}
type SCIMName struct { Formatted, FamilyName, GivenName, MiddleName string }
type SCIMEmail struct { Value, Type string; Primary bool }
type SCIMMeta struct { ResourceType string; Created, LastModified time.Time; Location, Version string }
```

## SCIM Operations

```go
type SCIMListResponse struct { Schemas []string; TotalResults, StartIndex, ItemsPerPage int; Resources interface{} }
type SCIMPatchRequest struct { Schemas []string; Operations []SCIMPatchOperation }
type SCIMPatchOperation struct { Op, Path string; Value interface{} }  // Op: "add", "remove", "replace"
type SCIMError struct { Schemas []string; Status, ScimType, Detail string }
```

## Provisioning Rules

```go
type ProvisioningRule struct {
    ID, Name, Description string; Trigger RuleTrigger
    Conditions []RuleCondition; Actions []RuleAction
    Enabled bool; Priority int
}
type RuleTrigger string  // "user_created", "user_updated", "user_deleted", "group_membership", "attribute_change", "scheduled"
type RuleCondition struct { Field, Operator, Value string }
type RuleAction struct { Type, Target string; Parameters map[string]interface{} }
```

## Context Helpers

```go
func ContextWithActorID(ctx context.Context, actorID string) context.Context
```
