// Package governance provides policy evaluation examples
package governance

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.uber.org/zap"
)

// examplePolicyEvaluator demonstrates basic usage of the PolicyEvaluator
func examplePolicyEvaluator() {
	// Create a new policy evaluator
	config := PolicyEvaluatorConfig{
		OPAURL:               "http://localhost:8181",
		DefaultPolicyTimeout: 5 * time.Second,
		EnableMetrics:        true,
		Logger:               zap.NewExample(),
	}

	evaluator := NewPolicyEvaluator(config)

	// Load a policy from bytes
	regoPolicy := `
package example

default allow = false

allow {
    input.user.roles[_] == "admin"
}

allow {
    input.action == "read"
    input.resource.type == "public"
}

deny[msg] {
    not allow
    msg := "Access denied: insufficient permissions"
}
`

	if err := evaluator.LoadPolicyFromBytes("example", []byte(regoPolicy)); err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}

	// Evaluate a policy decision
	ctx := context.Background()
	input := PolicyInput{
		User: PolicyUser{
			ID:            "user123",
			Username:      "johndoe",
			Roles:         []string{"user"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "document",
			ID:    "doc456",
		},
		Action: "read",
	}

	result, err := evaluator.EvaluatePolicy(ctx, "example", input)
	if err != nil {
		log.Fatalf("Policy evaluation failed: %v", err)
	}

	fmt.Printf("Allowed: %v\n", result.Allow)
	fmt.Printf("Duration: %v\n", result.Duration)
}

// ExampleGroupBasedAccess demonstrates group-based access control
func exampleGroupBasedAccess() {
	config := PolicyEvaluatorConfig{
		Logger: zap.NewExample(),
	}

	evaluator := NewPolicyEvaluator(config)

	regoPolicy := `
package groups

allow {
    input.user.groups[_] = "finance"
    input.resource.attributes["department"] = "finance"
}
`

	evaluator.LoadPolicyFromBytes("groups", []byte(regoPolicy))

	ctx := context.Background()
	input := PolicyInput{
		User: PolicyUser{
			ID:            "user123",
			Username:      "finuser",
			Groups:        []string{"finance", "employees"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "report",
			ID:   "report1",
			Attributes: map[string]string{
				"department": "finance",
				"class":      "confidential",
			},
		},
		Action: "read",
		Context: PolicyContext{
			IPAddress: "10.0.0.1",
			Time:      time.Now(),
		},
	}

	result, _ := evaluator.EvaluatePolicy(ctx, "groups", input)
	fmt.Printf("Finance access allowed: %v\n", result.Allow)
}

// ExampleResourceOwnerAccess demonstrates resource owner-based access
func exampleResourceOwnerAccess() {
	config := PolicyEvaluatorConfig{
		Logger: zap.NewExample(),
	}

	evaluator := NewPolicyEvaluator(config)

	regoPolicy := `
package owner

default allow = false

allow {
    input.user.id == input.resource.owner
}

allow {
    input.user.roles[_] == "admin"
}

deny[msg] {
    input.action == "delete"
    input.user.id != input.resource.owner
    not input.user.roles[_] == "admin"
    msg = "Only resource owner or admin can delete"
}
`

	evaluator.LoadPolicyFromBytes("owner", []byte(regoPolicy))

	ctx := context.Background()
	input := PolicyInput{
		User: PolicyUser{
			ID:            "user123",
			Username:      "owner",
			Roles:         []string{"user"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type:  "document",
			ID:    "doc1",
			Owner: "user123",
		},
		Action: "write",
	}

	result, _ := evaluator.EvaluatePolicy(ctx, "owner", input)
	fmt.Printf("Owner can write: %v\n", result.Allow)
}

// ExampleTimeBasedAccess demonstrates time-based access controls
func exampleTimeBasedAccess() {
	config := PolicyEvaluatorConfig{
		Logger: zap.NewExample(),
	}

	evaluator := NewPolicyEvaluator(config)

	regoPolicy := `
package timebased

allow {
    input.context.environment == "development"
}

warnings[msg] {
    input.context.time
    hour := time.clock_ns(input.context.time)[0]
    hour < 6
    msg := "Access during off-hours is monitored"
}
`

	evaluator.LoadPolicyFromBytes("timebased", []byte(regoPolicy))

	ctx := context.Background()
	input := PolicyInput{
		User: PolicyUser{
			ID:            "user123",
			Username:      "devuser",
			Roles:         []string{"developer"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "api",
		},
		Action: "read",
		Context: PolicyContext{
			Environment: "development",
			Time:        time.Now(),
		},
	}

	result, _ := evaluator.EvaluatePolicy(ctx, "timebased", input)
	fmt.Printf("Allowed in dev: %v\n", result.Allow)
	if len(result.Warnings) > 0 {
		fmt.Printf("Warning: %v\n", result.Warnings)
	}
}

// ExamplePolicyReloading demonstrates hot-reloading policies
func examplePolicyReloading() {
	config := PolicyEvaluatorConfig{
		PolicyDir:            "/etc/openidx/policies",
		DefaultPolicyTimeout: 5 * time.Second,
		Logger:               zap.NewExample(),
	}

	evaluator := NewPolicyEvaluator(config)

	// Initial load
	ctx := context.Background()
	if err := evaluator.ReloadPolicies(ctx); err != nil {
		log.Printf("Failed to reload policies: %v", err)
		return
	}

	// Check loaded policies
	names := evaluator.GetPolicyNames()
	fmt.Printf("Loaded policies: %v\n", names)

	// Get policy info
	if len(names) > 0 {
		info, err := evaluator.GetPolicyInfo(names[0])
		if err == nil {
			fmt.Printf("Policy %s: %d rules, %d bytes\n",
				info.Name, info.RuleCount, info.Size)
		}
	}

	// Get metrics
	metrics := evaluator.GetMetrics()
	fmt.Printf("Metrics: %+v\n", metrics)
}

// ExampleMultiRoleEvaluation demonstrates evaluating policies with multiple roles
func exampleMultiRoleEvaluation() {
	config := PolicyEvaluatorConfig{
		Logger: zap.NewExample(),
	}

	evaluator := NewPolicyEvaluator(config)

	regoPolicy := `
package multirole

default allow = false

allow {
    input.user.roles[_] == "reader"
    input.action == "read"
}

allow {
    input.user.roles[_] == "writer"
    input.action in ["read", "write"]
}

allow {
    input.user.roles[_] == "admin"
}

deny[msg] {
    input.action == "delete"
    not input.user.roles[_] == "admin"
    msg = "Only admins can delete"
}
`

	evaluator.LoadPolicyFromBytes("multirole", []byte(regoPolicy))

	ctx := context.Background()

	// User with reader role only
	readerInput := PolicyInput{
		User: PolicyUser{
			ID:            "user1",
			Username:      "reader",
			Roles:         []string{"reader"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "document",
		},
		Action: "read",
	}

	result, _ := evaluator.EvaluatePolicy(ctx, "multirole", readerInput)
	fmt.Printf("Reader can read: %v\n", result.Allow)

	// User with multiple roles
	multiRoleInput := PolicyInput{
		User: PolicyUser{
			ID:            "user2",
			Username:      "poweruser",
			Roles:         []string{"reader", "writer"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "document",
		},
		Action: "write",
	}

	result, _ = evaluator.EvaluatePolicy(ctx, "multirole", multiRoleInput)
	fmt.Printf("Multi-role user can write: %v\n", result.Allow)
}

// ExampleContextRichEvaluation demonstrates evaluation with rich context
func exampleContextRichEvaluation() {
	config := PolicyEvaluatorConfig{
		Logger: zap.NewExample(),
	}

	evaluator := NewPolicyEvaluator(config)

	regoPolicy := `
package context

default allow = false

allow {
    input.user.authenticated
    not input.context.attributes["suspicious_location"] == "true"
}

deny[msg] {
    input.context.attributes["suspicious_location"] == "true"
    msg = "Access blocked: suspicious location"
}

warnings[msg] {
    input.context.attributes["new_device"] == "true"
    msg = "New device access being monitored"
}

deny[msg] {
    input.context.attributes["rate_limit_exceeded"] == "true"
    msg = "Rate limit exceeded"
}
`

	evaluator.LoadPolicyFromBytes("context", []byte(regoPolicy))

	ctx := context.Background()

	// Normal access
	normalInput := PolicyInput{
		User: PolicyUser{
			ID:            "user123",
			Roles:         []string{"user"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "api",
		},
		Action: "read",
		Context: PolicyContext{
			IPAddress: "10.0.0.1",
			Attributes: map[string]string{
				"new_device": "false",
			},
		},
	}

	result, _ := evaluator.EvaluatePolicy(ctx, "context", normalInput)
	fmt.Printf("Normal access allowed: %v\n", result.Allow)

	// Suspicious location
	suspiciousInput := PolicyInput{
		User: PolicyUser{
			ID:            "user123",
			Roles:         []string{"user"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "api",
		},
		Action: "read",
		Context: PolicyContext{
			IPAddress: "1.2.3.4",
			Attributes: map[string]string{
				"suspicious_location": "true",
			},
		},
	}

	result, _ = evaluator.EvaluatePolicy(ctx, "context", suspiciousInput)
	fmt.Printf("Suspicious access allowed: %v, Denials: %v\n", result.Allow, result.Denials)
}

// ExampleDataClassification demonstrates data classification-based access
func exampleDataClassification() {
	config := PolicyEvaluatorConfig{
		Logger: zap.NewExample(),
	}

	evaluator := NewPolicyEvaluator(config)

	regoPolicy := `
package classification

default allow = false

allow {
    input.resource.attributes["classification"] == "public"
    input.action == "read"
    input.user.authenticated
}

allow {
    input.resource.attributes["classification"] == "internal"
    input.action == "read"
    count(input.user.roles) > 0
    input.user.authenticated
}

allow {
    input.resource.attributes["classification"] == "confidential"
    input.action == "read"
    input.user.groups[_] == input.resource.attributes["department"]
    input.user.authenticated
}

deny[msg] {
    input.resource.attributes["classification"] == "confidential"
    not input.user.groups[_] == input.resource.attributes["department"]
    msg = "Access denied: department membership required for confidential data"
}
`

	evaluator.LoadPolicyFromBytes("classification", []byte(regoPolicy))

	ctx := context.Background()

	// Access public resource
	publicInput := PolicyInput{
		User: PolicyUser{
			ID:            "user123",
			Roles:         []string{"user"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "document",
			Attributes: map[string]string{
				"classification": "public",
			},
		},
		Action: "read",
	}

	result, _ := evaluator.EvaluatePolicy(ctx, "classification", publicInput)
	fmt.Printf("Public access allowed: %v\n", result.Allow)

	// Access confidential resource with wrong department
	confidentialInput := PolicyInput{
		User: PolicyUser{
			ID:            "user123",
			Roles:         []string{"user"},
			Groups:        []string{"engineering"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "document",
			Attributes: map[string]string{
				"classification": "confidential",
				"department":     "finance",
			},
		},
		Action: "read",
	}

	result, _ = evaluator.EvaluatePolicy(ctx, "classification", confidentialInput)
	fmt.Printf("Confidential access allowed: %v, Reason: %v\n", result.Allow, result.Denials)
}
