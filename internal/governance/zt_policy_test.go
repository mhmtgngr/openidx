// Package governance provides tests for Zero Trust policy evaluation
package governance

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// TestZTPolicyEvaluator_AllowPolicy tests simple allow policy
func TestZTPolicyEvaluator_AllowPolicy(t *testing.T) {
	_ = zaptest.NewLogger(t) // Logger available for debugging
	eval := NewZTPolicyEvaluator()

	policy := NewZTPolicy(
		"Admin Full Access",
		"Allow admins full access",
		EffectAllow,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "subject.authenticated",
					Operator: OpEquals,
					Value:    true,
				},
				{
					Field:    "subject.roles",
					Operator: OpHasRole,
					Value:    "admin",
				},
			},
		},
		100,
	)
	eval.AddPolicy(policy)

	input := ZTPolicyInput{
		Subject: Subject{
			ID:            "user1",
			Type:          "user",
			Authenticated: true,
			Roles:         []string{"admin"},
			Groups:        []string{},
		},
		Resource: Resource{
			ID:   "res1",
			Type: "document",
		},
		Action: "read",
		Context: EvaluationContext{
			Time: time.Now(),
		},
	}

	result := eval.Evaluate(input)
	if !result.Allowed {
		t.Errorf("Expected allow, got deny. Reason: %s", result.Reason)
	}

	if len(result.MatchedPolicies) != 1 {
		t.Errorf("Expected 1 matched policy, got %d", len(result.MatchedPolicies))
	}

	if result.Effect != EffectAllow {
		t.Errorf("Expected effect allow, got %s", result.Effect)
	}
}

// TestZTPolicyEvaluator_DenyPolicy tests deny policy takes precedence
func TestZTPolicyEvaluator_DenyPolicy(t *testing.T) {
	_ = zaptest.NewLogger(t) // Logger available for debugging
	eval := NewZTPolicyEvaluator()

	// Add allow policy with lower priority
	allowPolicy := NewZTPolicy(
		"Allow Users",
		"Allow regular users",
		EffectAllow,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "subject.roles",
					Operator: OpHasRole,
					Value:    "user",
				},
			},
		},
		10,
	)
	eval.AddPolicy(allowPolicy)

	// Add deny policy with higher priority
	denyPolicy := NewZTPolicy(
		"Block Suspicious",
		"Block suspicious IP addresses",
		EffectDeny,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "context.ip",
					Operator: OpIPInRange,
					Value:    "192.168.1.0/24",
				},
			},
		},
		100,
	)
	eval.AddPolicy(denyPolicy)

	input := ZTPolicyInput{
		Subject: Subject{
			ID:            "user1",
			Authenticated: true,
			Roles:         []string{"user"},
		},
		Resource: Resource{
			Type: "document",
		},
		Action: "read",
		Context: EvaluationContext{
			IPAddress: "192.168.1.50",
			Time:      time.Now(),
		},
	}

	result := eval.Evaluate(input)
	if result.Allowed {
		t.Error("Deny policy should take precedence")
	}

	if len(result.DeniedBy) != 1 {
		t.Errorf("Expected 1 deny policy, got %d", len(result.DeniedBy))
	}
}

// TestZTPolicyEvaluator_NestedConditions tests nested AND/OR/NOT conditions
func TestZTPolicyEvaluator_NestedConditions(t *testing.T) {
	eval := NewZTPolicyEvaluator()

	// Policy: (admin OR (user AND during_business_hours)) AND NOT suspicious_ip
	policy := NewZTPolicy(
		"Complex Access",
		"Complex access control",
		EffectAllow,
		ConditionGroup{
			Operator: OpAnd,
			Groups: []ConditionGroup{
				{
					Operator: OpOr,
					Conditions: []Condition{
						{
							Field:    "subject.roles",
							Operator: OpHasRole,
							Value:    "admin",
						},
					},
					Groups: []ConditionGroup{
						{
							Operator: OpAnd,
							Conditions: []Condition{
								{
									Field:    "subject.roles",
									Operator: OpHasRole,
									Value:    "user",
								},
								{
									Field:    "context.time",
									Operator: OpTimeInRange,
									Value: map[string]string{
										"start": "09:00",
										"end":   "17:00",
									},
								},
							},
						},
					},
				},
				{
					Operator: OpNot,
					Conditions: []Condition{
						{
							Field:    "context.ip",
							Operator: OpIPInRange,
							Value:    "10.0.0.0/8",
						},
					},
				},
			},
		},
		50,
	)
	eval.AddPolicy(policy)

	tests := []struct {
		name     string
		input    ZTPolicyInput
		expected bool
	}{
		{
			name: "Admin access (not in suspicious range)",
			input: ZTPolicyInput{
				Subject: Subject{
					Roles:         []string{"admin"},
					Authenticated: true,
				},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context: EvaluationContext{
					IPAddress: "192.168.1.1",
					Time:      time.Now(),
				},
			},
			expected: true,
		},
		{
			name: "Admin blocked by suspicious IP",
			input: ZTPolicyInput{
				Subject: Subject{
					Roles:         []string{"admin"},
					Authenticated: true,
				},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context: EvaluationContext{
					IPAddress: "10.0.0.5",
					Time:      time.Now(),
				},
			},
			expected: false,
		},
		{
			name: "User access during business hours",
			input: ZTPolicyInput{
				Subject: Subject{
					Roles:         []string{"user"},
					Authenticated: true,
				},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context: EvaluationContext{
					IPAddress: "192.168.1.1",
					Time:      parseTime(t, "14:00"),
				},
			},
			expected: true,
		},
		{
			name: "User denied outside business hours",
			input: ZTPolicyInput{
				Subject: Subject{
					Roles:         []string{"user"},
					Authenticated: true,
				},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context: EvaluationContext{
					IPAddress: "192.168.1.1",
					Time:      parseTime(t, "20:00"),
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eval.Evaluate(tt.input)
			if result.Allowed != tt.expected {
				t.Errorf("Expected %v, got %v. Reason: %s", tt.expected, result.Allowed, result.Reason)
			}
		})
	}
}

// TestZTPolicyEvaluator_ResourceConditions tests resource-based conditions
func TestZTPolicyEvaluator_ResourceConditions(t *testing.T) {
	eval := NewZTPolicyEvaluator()

	// Policy: Access to public resources or own resources
	policy := NewZTPolicy(
		"Resource Based Access",
		"Allow access to public or own resources",
		EffectAllow,
		ConditionGroup{
			Operator: OpOr,
			Conditions: []Condition{
				{
					Field:    "resource.attributes.classification",
					Operator: OpEquals,
					Value:    "public",
				},
			},
			Groups: []ConditionGroup{
				{
					Operator: OpAnd,
					Conditions: []Condition{
						{
							Field:    "resource.owner",
							Operator: OpEquals,
							Value:    "subject.id",
						},
					},
				},
			},
		},
		50,
	)
	eval.AddPolicy(policy)

	// Mock the field value comparison for owner check
	// In real implementation, we'd support variable substitution

	tests := []struct {
		name     string
		input    ZTPolicyInput
		expected bool
	}{
		{
			name: "Public resource",
			input: ZTPolicyInput{
				Subject: Subject{
					ID:            "user1",
					Authenticated: true,
				},
				Resource: Resource{
					ID:   "doc1",
					Type: "document",
					Attributes: map[string]string{
						"classification": "public",
					},
				},
				Action: "read",
				Context: EvaluationContext{Time: time.Now()},
			},
			expected: true,
		},
		{
			name: "Confidential resource",
			input: ZTPolicyInput{
				Subject: Subject{
					ID:            "user1",
					Authenticated: true,
				},
				Resource: Resource{
					ID:   "doc2",
					Type: "document",
					Attributes: map[string]string{
						"classification": "confidential",
					},
				},
				Action: "read",
				Context: EvaluationContext{Time: time.Now()},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eval.Evaluate(tt.input)
			if result.Allowed != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result.Allowed)
			}
		})
	}
}

// TestZTPolicyEvaluator_GroupBasedAccess tests group-based access control
func TestZTPolicyEvaluator_GroupBasedAccess(t *testing.T) {
	eval := NewZTPolicyEvaluator()

	// Policy: User must be in the same department as the resource
	policy := NewZTPolicy(
		"Department Access",
		"Allow access to resources in user's department",
		EffectAllow,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "subject.groups",
					Operator: OpHasGroup,
					Value:    "finance",
				},
				{
					Field:    "resource.attributes.department",
					Operator: OpEquals,
					Value:    "finance",
				},
			},
		},
		50,
	)
	eval.AddPolicy(policy)

	input := ZTPolicyInput{
		Subject: Subject{
			ID:            "user1",
			Authenticated: true,
			Groups:        []string{"finance", "employees"},
		},
		Resource: Resource{
			ID:   "report1",
			Type: "report",
			Attributes: map[string]string{
				"department": "finance",
			},
		},
		Action: "read",
		Context: EvaluationContext{Time: time.Now()},
	}

	result := eval.Evaluate(input)
	if !result.Allowed {
		t.Error("Expected access for same department")
	}
}

// TestZTPolicyEvaluator_DayOfWeekTests tests day of week conditions
func TestZTPolicyEvaluator_DayOfWeekTests(t *testing.T) {
	eval := NewZTPolicyEvaluator()

	// Policy: Only allow on weekdays
	policy := NewZTPolicy(
		"Weekday Access",
		"Allow access only on weekdays",
		EffectAllow,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "context.time",
					Operator: OpDayOfWeek,
					Value:    []int{1, 2, 3, 4, 5}, // Mon-Fri
				},
			},
		},
		50,
	)
	eval.AddPolicy(policy)

	// Monday
	mondayTime := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC) // Jan 15, 2024 is a Monday
	input := ZTPolicyInput{
		Subject:  Subject{ID: "user1", Authenticated: true},
		Resource: Resource{Type: "api"},
		Action:   "read",
		Context:  EvaluationContext{Time: mondayTime},
	}

	result := eval.Evaluate(input)
	if !result.Allowed {
		t.Error("Expected access on Monday")
	}

	// Saturday
	saturdayTime := time.Date(2024, 1, 20, 10, 0, 0, 0, time.UTC) // Jan 20, 2024 is a Saturday
	input.Context.Time = saturdayTime

	result = eval.Evaluate(input)
	if result.Allowed {
		t.Error("Expected deny on Saturday")
	}
}

// TestZTPolicyEvaluator_NegatedConditions tests negated conditions
func TestZTPolicyEvaluator_NegatedConditions(t *testing.T) {
	eval := NewZTPolicyEvaluator()

	// Policy: Allow if authenticated AND NOT in blocked_users group
	policy := NewZTPolicy(
		"Non-Blocked Access",
		"Allow access to authenticated users not in blocked group",
		EffectAllow,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "subject.authenticated",
					Operator: OpEquals,
					Value:    true,
				},
				{
					Field:    "subject.groups",
					Operator: OpHasGroup,
					Value:    "blocked_users",
					Negated:  true,
				},
			},
		},
		50,
	)
	eval.AddPolicy(policy)

	tests := []struct {
		name     string
		groups   []string
		expected bool
	}{
		{
			name:     "Regular user allowed",
			groups:   []string{"users"},
			expected: true,
		},
		{
			name:     "Blocked user denied",
			groups:   []string{"users", "blocked_users"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := ZTPolicyInput{
				Subject: Subject{
					ID:            "user1",
					Authenticated: true,
					Groups:        tt.groups,
				},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context:  EvaluationContext{Time: time.Now()},
			}

			result := eval.Evaluate(input)
			if result.Allowed != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result.Allowed)
			}
		})
	}
}

// TestZTPolicyEvaluator_TimeRangeTests tests time range conditions
func TestZTPolicyEvaluator_TimeRangeTests(t *testing.T) {
	eval := NewZTPolicyEvaluator()

	// Policy: Business hours only
	policy := NewZTPolicy(
		"Business Hours",
		"Allow access during business hours only",
		EffectAllow,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "context.time",
					Operator: OpTimeInRange,
					Value: map[string]string{
						"start": "09:00",
						"end":   "17:00",
					},
				},
			},
		},
		50,
	)
	eval.AddPolicy(policy)

	tests := []struct {
		name     string
		hour     int
		expected bool
	}{
		{"Before business hours", 8, false},
		{"Start of business hours", 9, true},
		{"Middle of day", 12, true},
		{"End of business hours", 17, false},
		{"After business hours", 18, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testTime := time.Date(2024, 1, 15, tt.hour, 0, 0, 0, time.UTC)
			input := ZTPolicyInput{
				Subject:  Subject{ID: "user1", Authenticated: true},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context:  EvaluationContext{Time: testTime},
			}

			result := eval.Evaluate(input)
			if result.Allowed != tt.expected {
				t.Errorf("Hour %d: expected %v, got %v", tt.hour, tt.expected, result.Allowed)
			}
		})
	}
}

// TestZTPolicyEvaluator_IPRangeTests tests IP range conditions
func TestZTPolicyEvaluator_IPRangeTests(t *testing.T) {
	eval := NewZTPolicyEvaluator()

	// Policy: Only allow from corporate network
	policy := NewZTPolicy(
		"Corporate Network Only",
		"Allow access only from corporate IP range",
		EffectAllow,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "context.ip",
					Operator: OpIPInRange,
					Value:    "10.0.0.0/8",
				},
			},
		},
		50,
	)
	eval.AddPolicy(policy)

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Corporate IP", "10.0.1.50", true},
		{"Corporate IP 2", "10.255.255.255", true},
		{"Outside IP", "192.168.1.1", false},
		{"Public IP", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := ZTPolicyInput{
				Subject:  Subject{ID: "user1", Authenticated: true},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context: EvaluationContext{
					IPAddress: tt.ip,
					Time:      time.Now(),
				},
			}

			result := eval.Evaluate(input)
			if result.Allowed != tt.expected {
				t.Errorf("IP %s: expected %v, got %v", tt.ip, tt.expected, result.Allowed)
			}
		})
	}
}

// TestZTPolicyEvaluator_EvaluateSingle tests evaluating a single policy
func TestZTPolicyEvaluator_EvaluateSingle(t *testing.T) {
	eval := NewZTPolicyEvaluator()

	policy := NewZTPolicy(
		"Test Policy",
		"Test policy for single evaluation",
		EffectAllow,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "subject.roles",
					Operator: OpHasRole,
					Value:    "admin",
				},
			},
		},
		50,
	)
	eval.AddPolicy(policy)

	input := ZTPolicyInput{
		Subject:  Subject{ID: "user1", Roles: []string{"admin"}, Authenticated: true},
		Resource: Resource{Type: "api"},
		Action:   "read",
		Context:  EvaluationContext{Time: time.Now()},
	}

	result, err := eval.EvaluateSingle(policy.ID, input)
	if err != nil {
		t.Fatalf("EvaluateSingle failed: %v", err)
	}

	if !result.Allowed {
		t.Error("Expected policy to match")
	}

	// Test non-existent policy
	_, err = eval.EvaluateSingle("non-existent", input)
	if err == nil {
		t.Error("Expected error for non-existent policy")
	}
}

// TestZTPolicyEvaluator_DefaultDeny tests Zero Trust default deny
func TestZTPolicyEvaluator_DefaultDeny(t *testing.T) {
	eval := NewZTPolicyEvaluator()

	// No policies defined - should default to deny
	input := ZTPolicyInput{
		Subject:  Subject{ID: "user1", Authenticated: true},
		Resource: Resource{Type: "api"},
		Action:   "read",
		Context:  EvaluationContext{Time: time.Now()},
	}

	result := eval.Evaluate(input)
	if result.Allowed {
		t.Error("Zero Trust should default to deny when no policies match")
	}

	if result.Reason == "" {
		t.Error("Reason should be set for deny")
	}
}

// TestZTPolicyEvaluator_PriorityTests tests policy priority ordering
func TestZTPolicyEvaluator_PriorityTests(t *testing.T) {
	eval := NewZTPolicyEvaluator()

	// Low priority allow
	allowLow := NewZTPolicy(
		"Allow Low",
		"Allow with low priority",
		EffectAllow,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
		10,
	)
	eval.AddPolicy(allowLow)

	// High priority deny
	denyHigh := NewZTPolicy(
		"Deny High",
		"Deny with high priority",
		EffectDeny,
		ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.id", Operator: OpEquals, Value: "user1"},
			},
		},
		100,
	)
	eval.AddPolicy(denyHigh)

	input := ZTPolicyInput{
		Subject:  Subject{ID: "user1", Authenticated: true},
		Resource: Resource{Type: "api"},
		Action:   "read",
		Context:  EvaluationContext{Time: time.Now()},
	}

	result := eval.Evaluate(input)
	if result.Allowed {
		t.Error("High priority deny should override low priority allow")
	}

	// The implementation returns immediately on a deny, so only the deny policy is matched
	if len(result.MatchedPolicies) != 1 {
		t.Errorf("Expected 1 matched policy (deny), got %d", len(result.MatchedPolicies))
	}
}

// TestConditionGroup_MarshalJSON tests JSON marshaling of condition groups
func TestConditionGroup_MarshalJSON(t *testing.T) {
	group := ConditionGroup{
		Operator: OpAnd,
		Conditions: []Condition{
			{
				Field:    "subject.roles",
				Operator: OpHasRole,
				Value:    "admin",
			},
		},
		Groups: []ConditionGroup{
			{
				Operator: OpOr,
				Conditions: []Condition{
					{
						Field:    "context.ip",
						Operator: OpIPInRange,
						Value:    "10.0.0.0/8",
					},
				},
			},
		},
	}

	data, err := json.Marshal(group)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var unmarshaled ConditionGroup
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if unmarshaled.Operator != group.Operator {
		t.Errorf("Operator mismatch: got %v, want %v", unmarshaled.Operator, group.Operator)
	}

	if len(unmarshaled.Conditions) != len(group.Conditions) {
		t.Errorf("Conditions count mismatch: got %d, want %d", len(unmarshaled.Conditions), len(group.Conditions))
	}
}

// BenchmarkZTPolicyEvaluator_Evaluate benchmarks policy evaluation
func BenchmarkZTPolicyEvaluator_Evaluate(b *testing.B) {
	eval := NewZTPolicyEvaluator()

	// Add 100 policies
	for i := 0; i < 100; i++ {
		policy := NewZTPolicy(
			"Policy "+strconv.Itoa(i),
			"Test policy",
			EffectAllow,
			ConditionGroup{
				Operator: OpAnd,
				Conditions: []Condition{
					{
						Field:    "subject.roles",
						Operator: OpHasRole,
						Value:    "role" + strconv.Itoa(i%10),
					},
				},
			},
			i,
		)
		eval.AddPolicy(policy)
	}

	input := ZTPolicyInput{
		Subject:  Subject{ID: "user1", Roles: []string{"role5"}, Authenticated: true},
		Resource: Resource{Type: "api"},
		Action:   "read",
		Context:  EvaluationContext{Time: time.Now()},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Evaluate(input)
	}
}
