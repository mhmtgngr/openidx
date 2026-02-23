// Package governance provides policy evaluation tests
package governance

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// TestPolicyEvaluator_LoadPolicyFromBytes tests loading policies from bytes
func TestPolicyEvaluator_LoadPolicyFromBytes(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: true,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	regoContent := []byte(`
package openidx

default allow = false

allow {
	some i
	input.user.roles[i] == "admin"
}

allow {
	some i
	input.user.roles[i] == "user"
	input.resource.type == "public"
}

deny[msg] {
	not allow
	msg := "Access denied: insufficient permissions"
}
`)

	err := eval.LoadPolicyFromBytes("openidx", regoContent)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if !eval.PolicyExists("openidx") {
		t.Error("Policy should exist after loading")
	}
}

// TestPolicyEvaluator_EvaluatePolicy tests basic policy evaluation
func TestPolicyEvaluator_EvaluatePolicy(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: true,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	regoContent := []byte(`
package test

default allow = false

allow {
	some i
	input.user.roles[i] == "admin"
}

allow {
	input.action == "read"
	input.resource.type == "public"
}

deny[msg] {
	not allow
	msg := sprintf("Access denied for user %s on resource %s", [input.user.id, input.resource.id])
}

warnings[msg] {
	allow
	input.action == "delete"
	msg := "Deleting resource is irreversible"
}
`)

	err := eval.LoadPolicyFromBytes("test", regoContent)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name      string
		input     PolicyInput
		wantAllow bool
		wantDeny  bool
	}{
		{
			name: "admin user has full access",
			input: PolicyInput{
				User: PolicyUser{
					ID:            "user1",
					Username:      "admin",
					Roles:         []string{"admin"},
					Authenticated: true,
				},
				Resource: PolicyResource{
					Type: "sensitive",
					ID:    "res1",
				},
				Action: "write",
			},
			wantAllow: true,
			wantDeny:  false,
		},
		{
			name: "regular user can read public resources",
			input: PolicyInput{
				User: PolicyUser{
					ID:            "user2",
					Username:      "regular",
					Roles:         []string{"user"},
					Authenticated: true,
				},
				Resource: PolicyResource{
					Type: "public",
					ID:    "res2",
				},
				Action: "read",
			},
			wantAllow: true,
			wantDeny:  false,
		},
		{
			name: "regular user cannot write to sensitive resources",
			input: PolicyInput{
				User: PolicyUser{
					ID:            "user2",
					Username:      "regular",
					Roles:         []string{"user"},
					Authenticated: true,
				},
				Resource: PolicyResource{
					Type: "sensitive",
					ID:    "res1",
				},
				Action: "write",
			},
			wantAllow: false,
			wantDeny:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := eval.EvaluatePolicy(ctx, "test", tt.input)
			if err != nil {
				t.Fatalf("EvaluatePolicy failed: %v", err)
			}

			if result.Allow != tt.wantAllow {
				t.Errorf("Allow = %v, want %v", result.Allow, tt.wantAllow)
			}

			hasDenials := len(result.Denials) > 0
			if hasDenials != tt.wantDeny {
				t.Errorf("Has denials = %v, want %v. Denials: %v", hasDenials, tt.wantDeny, result.Denials)
			}

			if result.Duration == 0 {
				t.Error("Duration should be recorded")
			}

			if result.EvaluatedAt.IsZero() {
				t.Error("EvaluatedAt should be set")
			}
		})
	}
}

// TestPolicyEvaluator_ContextEvaluation tests evaluation with additional context
func TestPolicyEvaluator_ContextEvaluation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: true,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	regoContent := []byte(`
package context

default allow = false

allow {
	input.context.environment == "development"
}

allow {
	some i
	input.user.roles[i] == "prod_admin"
	input.context.environment == "production"
}

deny[msg] {
	input.context.environment == "maintenance"
	msg := "System under maintenance"
}

warnings[msg] {
	input.context.attributes["off_hours"] == "true"
	msg := "Access during off-hours is monitored"
}
`)

	err := eval.LoadPolicyFromBytes("context", regoContent)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name      string
		input     PolicyInput
		wantAllow bool
		wantWarn  bool
	}{
		{
			name: "allow in development environment",
			input: PolicyInput{
				User: PolicyUser{
					ID:            "user1",
					Roles:         []string{"user"},
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
			},
			wantAllow: true,
		},
		{
			name: "deny during maintenance",
			input: PolicyInput{
				User: PolicyUser{
					ID:            "user1",
					Roles:         []string{"admin"},
					Authenticated: true,
				},
				Resource: PolicyResource{
					Type: "api",
				},
				Action: "read",
				Context: PolicyContext{
					Environment: "maintenance",
				},
			},
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := eval.EvaluatePolicy(ctx, "context", tt.input)
			if err != nil {
				t.Fatalf("EvaluatePolicy failed: %v", err)
			}

			if result.Allow != tt.wantAllow {
				t.Errorf("Allow = %v, want %v", result.Allow, tt.wantAllow)
			}

			hasWarnings := len(result.Warnings) > 0
			if hasWarnings != tt.wantWarn {
				t.Errorf("Has warnings = %v, want %v", hasWarnings, tt.wantWarn)
			}
		})
	}
}

// TestPolicyEvaluator_GroupBasedAccess tests group-based access control
func TestPolicyEvaluator_GroupBasedAccess(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: true,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	regoContent := []byte(`
package groups

default allow = false

allow {
	input.user.groups[_] == "finance"
	input.resource.attributes["department"] == "finance"
}

allow {
	input.user.groups[_] == "hr"
	input.resource.attributes["department"] == "hr"
}

deny[msg] {
	count(input.user.groups) == 0
	msg := "User must belong to at least one group"
}
`)

	err := eval.LoadPolicyFromBytes("groups", regoContent)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Test finance group access
	input := PolicyInput{
		User: PolicyUser{
			ID:            "user1",
			Username:      "finance_user",
			Groups:        []string{"finance", "employees"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "document",
			ID:   "doc1",
			Attributes: map[string]string{
				"department": "finance",
				"class":      "confidential",
			},
		},
		Action: "read",
	}

	ctx := context.Background()
	result, err := eval.EvaluatePolicy(ctx, "groups", input)
	if err != nil {
		t.Fatalf("EvaluatePolicy failed: %v", err)
	}

	if !result.Allow {
		t.Errorf("Finance user should have access to finance documents. Got denials: %v", result.Denials)
	}
}

// TestPolicyEvaluator_ResourceOwner tests resource owner-based access
func TestPolicyEvaluator_ResourceOwner(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: true,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	regoContent := []byte(`
package owner

default allow = false

allow {
	input.user.id == input.resource.owner
}

allow {
	some i
	input.user.roles[i] == "admin"
}

deny[msg] {
	input.action == "delete"
	input.user.id != input.resource.owner
	not count([i | input.user.roles[i] == "admin"]) > 0
	msg = "Only resource owner or admin can delete"
}
`)

	err := eval.LoadPolicyFromBytes("owner", regoContent)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Test owner access
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

	ctx := context.Background()
	result, err := eval.EvaluatePolicy(ctx, "owner", input)
	if err != nil {
		t.Fatalf("EvaluatePolicy failed: %v", err)
	}

	if !result.Allow {
		t.Error("Owner should have write access to their own resource")
	}

	// Test non-owner delete (should be denied)
	input.Action = "delete"
	result, err = eval.EvaluatePolicy(ctx, "owner", input)
	if err != nil {
		t.Fatalf("EvaluatePolicy failed: %v", err)
	}

	// Owner can still delete their own resource
	if !result.Allow {
		t.Error("Owner should be able to delete their own resource")
	}
}

// TestPolicyEvaluator_MultiRole tests evaluation with multiple roles
func TestPolicyEvaluator_MultiRole(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: true,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	regoContent := []byte(`
package multirole

default allow = false

allow {
	some i
	input.user.roles[i] == "reader"
	input.action == "read"
}

allow {
	some i
	input.user.roles[i] == "writer"
	input.action == "read"
}

allow {
	some i
	input.user.roles[i] == "writer"
	input.action == "write"
}

allow {
	some i
	input.user.roles[i] == "admin"
}

deny[msg] {
	input.action == "delete"
	not count([i | input.user.roles[i] == "admin"]) > 0
	msg = "Only admins can delete"
}
`)

	err := eval.LoadPolicyFromBytes("multirole", regoContent)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Test user with multiple roles
	input := PolicyInput{
		User: PolicyUser{
			ID:            "user1",
			Username:      "multi_role_user",
			Roles:         []string{"reader", "writer"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "document",
		},
		Action: "write",
	}

	ctx := context.Background()
	result, err := eval.EvaluatePolicy(ctx, "multirole", input)
	if err != nil {
		t.Fatalf("EvaluatePolicy failed: %v", err)
	}

	if !result.Allow {
		t.Error("User with writer role should have write access")
	}
}

// TestPolicyEvaluator_GetPolicyInfo tests getting policy information
func TestPolicyEvaluator_GetPolicyInfo(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: true,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	regoContent := []byte(`
package info

allow { true }
deny { false }
`)

	err := eval.LoadPolicyFromBytes("info", regoContent)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	info, err := eval.GetPolicyInfo("info")
	if err != nil {
		t.Fatalf("GetPolicyInfo failed: %v", err)
	}

	if info.Name != "info" {
		t.Errorf("Name = %s, want info", info.Name)
	}

	if info.RuleCount == 0 {
		t.Error("RuleCount should be greater than 0")
	}

	if info.Size == 0 {
		t.Error("Size should be greater than 0")
	}

	if info.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

// TestPolicyEvaluator_RemovePolicy tests removing policies
func TestPolicyEvaluator_RemovePolicy(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: true,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	regoContent := []byte(`package test
allow { true }
`)

	err := eval.LoadPolicyFromBytes("test", regoContent)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if !eval.PolicyExists("test") {
		t.Error("Policy should exist")
	}

	err = eval.RemovePolicy("test")
	if err != nil {
		t.Fatalf("RemovePolicy failed: %v", err)
	}

	if eval.PolicyExists("test") {
		t.Error("Policy should not exist after removal")
	}
}

// TestPolicyEvaluator_GetMetrics tests getting metrics
func TestPolicyEvaluator_GetMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: true,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	regoContent := []byte(`package metrics
allow { true }
`)

	err := eval.LoadPolicyFromBytes("metrics", regoContent)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	metrics := eval.GetMetrics()

	if metrics["policy_count"].(int) != 1 {
		t.Errorf("policy_count = %v, want 1", metrics["policy_count"])
	}

	names := metrics["policy_names"].([]string)
	if len(names) != 1 || names[0] != "metrics" {
		t.Errorf("policy_names = %v, want [metrics]", names)
	}
}

// TestPolicyEvaluator_EnableDisable tests enabling and disabling
func TestPolicyEvaluator_EnableDisable(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: true,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	if !eval.IsEnabled() {
		t.Error("Evaluator should be enabled by default")
	}

	eval.Disable()
	if eval.IsEnabled() {
		t.Error("Evaluator should be disabled")
	}

	eval.Enable()
	if !eval.IsEnabled() {
		t.Error("Evaluator should be enabled")
	}
}

// BenchmarkPolicyEvaluator_Evaluation benchmarks policy evaluation
func BenchmarkPolicyEvaluator_Evaluation(b *testing.B) {
	logger := zaptest.NewLogger(b)
	config := PolicyEvaluatorConfig{
		OPAURL:        "http://localhost:8181",
		EnableMetrics: false,
		Logger:        logger,
	}

	eval := NewPolicyEvaluator(config)

	regoContent := []byte(`
package bench

allow {
	some i
	input.user.roles[i] == "admin"
}

allow {
	input.action == "read"
	input.resource.type == "public"
}

deny[msg] {
	not allow
	msg := "Access denied"
}
`)

	err := eval.LoadPolicyFromBytes("bench", regoContent)
	if err != nil {
		b.Fatalf("Failed to load policy: %v", err)
	}

	input := PolicyInput{
		User: PolicyUser{
			ID:            "user1",
			Roles:         []string{"user"},
			Authenticated: true,
		},
		Resource: PolicyResource{
			Type: "public",
		},
		Action: "read",
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := eval.EvaluatePolicy(ctx, "bench", input)
		if err != nil {
			b.Fatalf("Evaluation failed: %v", err)
		}
	}
}
