# OpenIDX Governance Policy Evaluation Module

This module provides comprehensive policy evaluation capabilities using Open Policy Agent (OPA) and Rego for the OpenIDX Zero Trust Access Platform.

## Overview

The `PolicyEvaluator` provides:
- In-memory OPA policy compilation and evaluation
- Hot-reloading of policies without service restart
- Policy caching for high-performance evaluation
- Comprehensive metrics and observability
- Support for complex RBAC, ABAC, and time-based access controls

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PolicyEvaluator                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │ Policy Cache │  │ OPA Compiler │  │ Metrics/Telemetry│ │
│  │  (sync.Map)  │  │  (Rego/AST)  │  │   (Prometheus)   │ │
│  └──────────────┘  └──────────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Rego Policies                           │
│  - access_control.rego (RBAC/ABAC rules)                   │
│  - session_management.rego (session controls)              │
│  - data_classification.rego (data sensitivity)             │
└─────────────────────────────────────────────────────────────┘
```

## Installation

Add the OPA dependency:

```bash
go get github.com/open-policy-agent/opa@v0.69.0
go mod tidy
```

## Quick Start

### Basic Usage

```go
import (
    "context"
    "github.com/openidx/openidx/internal/governance"
)

// Create evaluator
config := governance.PolicyEvaluatorConfig{
    OPAURL:               "http://localhost:8181",
    DefaultPolicyTimeout: 5 * time.Second,
    EnableMetrics:        true,
    Logger:               logger,
}

evaluator := governance.NewPolicyEvaluator(config)

// Load policy from file
err := evaluator.LoadPolicyFromFile("/etc/openidx/policies/access_control.rego")

// Evaluate policy
input := governance.PolicyInput{
    User: governance.PolicyUser{
        ID:            "user123",
        Username:      "johndoe",
        Roles:         []string{"user", "developer"},
        Groups:        []string{"engineering"},
        Authenticated: true,
    },
    Resource: governance.PolicyResource{
        Type: "document",
        ID:   "doc456",
        Attributes: map[string]string{
            "classification": "confidential",
            "department":     "engineering",
        },
    },
    Action: "read",
    Context: governance.PolicyContext{
        IPAddress: "10.0.0.1",
        Time:      time.Now(),
    },
}

result, err := evaluator.EvaluatePolicy(context.Background(), "access_control", input)
if err != nil {
    // Handle error
}

if result.Allow {
    // Grant access
} else {
    // Deny access
    fmt.Println("Denials:", result.Denials)
    fmt.Println("Warnings:", result.Warnings)
}
```

### Loading Policies from Directory

```go
evaluator := governance.NewPolicyEvaluator(config)

// Load all .rego files from directory
err := evaluator.LoadPoliciesFromDirectory("/etc/openidx/policies")
```

### Hot-Reloading Policies

```go
// Reload all policies without restart
ctx := context.Background()
err := evaluator.ReloadPolicies(ctx)
```

## Policy Input Structure

### PolicyInput

```go
type PolicyInput struct {
    User     PolicyUser     // User identity and attributes
    Resource PolicyResource // Resource being accessed
    Action   string         // Action being performed
    Context  PolicyContext  // Additional context
}
```

### PolicyUser

```go
type PolicyUser struct {
    ID            string            // Unique user ID
    Username      string            // Username
    Email         string            // Email address
    Roles         []string          // Assigned roles
    Groups        []string          // Group memberships
    TenantID      string            // Tenant ID (multi-tenant)
    Attributes    map[string]string // Custom attributes
    Authenticated bool              // Authentication status
}
```

### PolicyResource

```go
type PolicyResource struct {
    Type       string            // Resource type
    ID         string            // Resource ID
    Name       string            // Resource name
    Owner      string            // Resource owner
    Path       string            // Resource path
    Attributes map[string]string // Custom attributes
    Tags       []string          // Resource tags
}
```

### PolicyContext

```go
type PolicyContext struct {
    IPAddress     string            // Client IP address
    UserAgent     string            // Client user agent
    Time          time.Time         // Request time
    Environment   string            // Environment (dev/prod)
    RequestID     string            // Request ID
    Attributes    map[string]string // Custom attributes
    SessionID     string            // Session ID
    DeviceID      string            // Device ID
    Location      string            // Geographic location
}
```

## Policy Result

```go
type PolicyResult struct {
    Allow      bool          // Access decision
    Denials    []string      // Denial reasons
    Warnings   []string      // Warning messages
    Reason     string        // Primary reason
    Score      float64       // Risk/confidence score
    EvaluatedAt time.Time    // When evaluated
    Duration   time.Duration // Evaluation time
}
```

## Rego Policy Examples

### Basic RBAC

```rego
package rbac

default allow = false

allow {
    input.user.roles[_] == "admin"
}

allow {
    input.user.roles[_] == "reader"
    input.action == "read"
}
```

### Resource Owner Access

```rego
package owner

allow {
    input.user.id == input.resource.owner
}

allow {
    input.user.roles[_] == "admin"
}
```

### Group-Based Access

```rego
package groups

allow {
    input.user.groups[_] == "finance"
    input.resource.attributes["department"] == "finance"
}
```

### Time-Based Access

```rego
package timebased

allow {
    hour := time.clock_ns(input.context.time)[0]
    hour >= 9
    hour <= 17
}

deny[msg] {
    hour := time.clock_ns(input.context.time)[0]
    hour < 6
    msg := "Access denied: off-hours"
}
```

### Data Classification

```rego
package classification

allow {
    input.resource.attributes["classification"] == "public"
    input.action == "read"
}

allow {
    input.resource.attributes["classification"] == "confidential"
    input.user.groups[_] == input.resource.attributes["department"]
}
```

## Metrics

The policy evaluator tracks the following metrics:

- `openidx_policy_evaluation_duration_seconds` - Evaluation latency histogram
- `openidx_policy_evaluation_total` - Total evaluation count by policy name
- `openidx_policy_cache_hits_total` - Cache hit count
- `openidx_policy_cache_misses_total` - Cache miss count
- `openidx_policy_reloads_total` - Policy reload count
- `openidx_policy_errors_total` - Error count by type

## API Reference

### Constructor

```go
func NewPolicyEvaluator(config PolicyEvaluatorConfig) *PolicyEvaluator
```

### Core Methods

```go
// Evaluate a policy
func (pe *PolicyEvaluator) EvaluatePolicy(ctx context.Context, policyName string, input PolicyInput) (*PolicyResult, error)

// Load policy from bytes
func (pe *PolicyEvaluator) LoadPolicyFromBytes(policyName string, regoContent []byte) error

// Load policy from file
func (pe *PolicyEvaluator) LoadPolicyFromFile(policyPath string) error

// Load policies from directory
func (pe *PolicyEvaluator) LoadPoliciesFromDirectory(dir string) error

// Hot-reload all policies
func (pe *PolicyEvaluator) ReloadPolicies(ctx context.Context) error

// Check if policy exists
func (pe *PolicyEvaluator) PolicyExists(policyName string) bool

// Get policy names
func (pe *PolicyEvaluator) GetPolicyNames() []string

// Get policy info
func (pe *PolicyEvaluator) GetPolicyInfo(policyName string) (*PolicyInfo, error)

// Remove policy
func (pe *PolicyEvaluator) RemovePolicy(policyName string) error

// Get metrics
func (pe *PolicyEvaluator) GetMetrics() map[string]interface{}

// Enable/disable evaluator
func (pe *PolicyEvaluator) Enable()
func (pe *PolicyEvaluator) Disable()
func (pe *PolicyEvaluator) IsEnabled() bool
```

## Integration with Governance Service

The policy evaluator integrates with the governance service for:

1. **Access Reviews** - Evaluate policies during access certification campaigns
2. **Just-In-Time Access** - Validate JIT access requests against policies
3. **Compliance Reporting** - Generate policy compliance reports
4. **Audit Logging** - Log all policy decisions for compliance

## Testing

```bash
# Run unit tests
go test -v ./internal/governance -run TestPolicyEvaluator

# Run benchmarks
go test -v ./internal/governance -bench=BenchmarkPolicyEvaluator -benchmem

# Run with coverage
go test -v ./internal/governance -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Best Practices

1. **Policy Organization**
   - Keep policies focused and single-purpose
   - Use descriptive package names
   - Document complex rules with comments

2. **Performance**
   - Policies are compiled and cached in memory
   - Evaluation is typically < 1ms for simple policies
   - Use hot-reload instead of restarts for updates

3. **Security**
   - Default deny: `default allow = false`
   - Use specific denials with clear messages
   - Log all policy decisions for audit

4. **Testing**
   - Write unit tests for each policy
   - Test edge cases and failure modes
   - Use benchmarks for performance validation

## Files

- `policy.go` - Core policy evaluator implementation
- `policy_test.go` - Unit tests and benchmarks
- `policy_example_test.go` - Usage examples
- `policies/access_control.rego` - Example access control policy
- `POLICY_README.md` - This documentation

## License

Copyright (c) OpenIDX Project. All rights reserved.
