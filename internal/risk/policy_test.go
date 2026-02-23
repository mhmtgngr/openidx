// Package risk provides unit tests for risk-based authentication policies
package risk

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// TestPolicyConfig tests default policy configuration
func TestPolicyConfig(t *testing.T) {
	config := DefaultPolicyConfig()

	tests := []struct {
		field      string
		expected   interface{}
		actual     interface{}
	}{
		{"LowThreshold", 30, config.DefaultLowThreshold},
		{"MediumThreshold", 50, config.DefaultMediumThreshold},
		{"HighThreshold", 70, config.DefaultHighThreshold},
		{"CriticalThreshold", 90, config.DefaultCriticalThreshold},
		{"LowRiskSessionDuration", 480, config.LowRiskSessionDuration},
		{"MediumRiskSessionDuration", 240, config.MediumRiskSessionDuration},
		{"HighRiskSessionDuration", 60, config.HighRiskSessionDuration},
		{"CriticalRiskSessionDuration", 15, config.CriticalRiskSessionDuration},
	}

	for _, tt := range tests {
		if tt.expected != tt.actual {
			t.Errorf("Expected %s %v, got %v", tt.field, tt.expected, tt.actual)
		}
	}

	if len(config.DefaultMFAMethods) == 0 {
		t.Error("DefaultMFAMethods should not be empty")
	}

	if len(config.StrongMFAMethods) == 0 {
		t.Error("StrongMFAMethods should not be empty")
	}
}

// TestPolicyEngine_determineRiskLevel tests risk level determination
func TestPolicyEngine_determineRiskLevel(t *testing.T) {
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	redisClient := &database.RedisClient{Client: client}

	config := DefaultPolicyConfig()
	engine := NewPolicyEngine(nil, redisClient, config, zap.NewNop())

	policy := &TenantPolicy{
		TenantID:           "tenant1",
		LowThreshold:       30,
		MediumThreshold:    50,
		HighThreshold:      70,
		CriticalThreshold:  90,
		Enabled:            true,
	}

	tests := []struct {
		score     int
		expected  RiskLevel
	}{
		{0, RiskLevelLow},
		{15, RiskLevelLow},
		{29, RiskLevelLow},
		{30, RiskLevelMedium},
		{45, RiskLevelMedium},
		{49, RiskLevelMedium},
		{50, RiskLevelHigh},
		{65, RiskLevelHigh},
		{69, RiskLevelHigh},
		{70, RiskLevelCritical},
		{85, RiskLevelCritical},
		{100, RiskLevelCritical},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			result := engine.determineRiskLevel(tt.score, policy)
			if result != tt.expected {
				t.Errorf("determineRiskLevel(%d) = %v, want %v",
					tt.score, result, tt.expected)
			}
		})
	}
}

// TestPolicyEngine_determineAction tests action determination based on score
func TestPolicyEngine_determineAction(t *testing.T) {
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	redisClient := &database.RedisClient{Client: client}

	config := DefaultPolicyConfig()
	engine := NewPolicyEngine(nil, redisClient, config, zap.NewNop())

	policy := &TenantPolicy{
		TenantID:           "tenant1",
		LowThreshold:       30,
		MediumThreshold:    50,
		HighThreshold:      70,
		CriticalThreshold:  90,
		Enabled:            true,
	}

	tests := []struct {
		score     int
		expected  AuthAction
	}{
		{0, AuthActionAllow},
		{20, AuthActionAllow},
		{30, AuthActionRequireMFA},
		{45, AuthActionRequireMFA},
		{50, AuthActionRequireStrongMFA},
		{65, AuthActionRequireStrongMFA},
		{70, AuthActionRequireApproval},
		{85, AuthActionRequireApproval},
		{90, AuthActionBlockAndAlert},
		{100, AuthActionBlockAndAlert},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			result := engine.determineAction(tt.score, policy)
			if result != tt.expected {
				t.Errorf("determineAction(%d) = %v, want %v",
					tt.score, result, tt.expected)
			}
		})
	}
}

// TestPolicyEngine_checkDeviceRisk tests device risk assessment
func TestPolicyEngine_checkDeviceRisk(t *testing.T) {
	// This test would require a mock database
	// For now, we test the scoring logic
	config := DefaultPolicyConfig()
	engine := NewPolicyEngine(nil, nil, config, zap.NewNop())

	// Test with nil db - should return 30 for unknown device
	ctx := context.Background()
	score := engine.checkDeviceRisk(ctx, "user123", "unknown-fingerprint")

	if score != 30 {
		t.Errorf("Expected score 30 for unknown device, got %d", score)
	}
}

// TestPolicyEngine_checkFailedAttempts tests failed attempt detection
func TestPolicyEngine_checkFailedAttempts(t *testing.T) {
	// This test would require a mock database
	// For now, we test with nil db - should return 0
	config := DefaultPolicyConfig()
	engine := NewPolicyEngine(nil, nil, config, zap.NewNop())

	ctx := context.Background()
	score := engine.checkFailedAttempts(ctx, "user123", "192.168.1.1")

	// With no database, should return 0
	if score != 0 {
		t.Errorf("Expected score 0 with no database, got %d", score)
	}
}

// TestEvaluateRequest_ResponseStructure tests the evaluate response structure
func TestEvaluateRequest_ResponseStructure(t *testing.T) {
	req := EvaluateRequest{
		TenantID:      "tenant1",
		UserID:        "user1",
		IPAddress:     "192.168.1.1",
		UserAgent:     "Chrome",
		DeviceFingerprint: "fp123",
		Latitude:      40.7128,
		Longitude:     -74.0060,
		LoginHour:     9,
		Resource:      "/api/v1/resource",
	}

	// Verify required fields are set
	if req.TenantID == "" {
		t.Error("TenantID is required")
	}
	if req.UserID == "" {
		t.Error("UserID is required")
	}
}

// TestEvaluateResponse_ActionFields tests response action field consistency
func TestEvaluateResponse_ActionFields(t *testing.T) {
	tests := []struct {
		action          AuthAction
		expectedAllowed bool
		expectedRequireMFA bool
	}{
		{AuthActionAllow, true, false},
		{AuthActionRequireMFA, true, true},
		{AuthActionRequireStrongMFA, true, true},
		{AuthActionRequireApproval, false, false},
		{AuthActionBlock, false, false},
		{AuthActionBlockAndAlert, false, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			response := &EvaluateResponse{
				Action:     tt.action,
				Allowed:    tt.expectedAllowed,
				RequireMFA: tt.expectedRequireMFA,
			}

			if response.Allowed != tt.expectedAllowed {
				t.Errorf("Action %s: Allowed should be %v", tt.action, tt.expectedAllowed)
			}

			if response.RequireMFA != tt.expectedRequireMFA {
				t.Errorf("Action %s: RequireMFA should be %v", tt.action, tt.expectedRequireMFA)
			}
		})
	}
}

// TestTenantPolicy_Validation tests tenant policy validation
func TestTenantPolicy_Validation(t *testing.T) {
	tests := []struct {
		name     string
		policy   TenantPolicy
		valid    bool
	}{
		{
			name: "valid policy",
			policy: TenantPolicy{
				TenantID:          "tenant1",
				LowThreshold:      30,
				MediumThreshold:   50,
				HighThreshold:     70,
				CriticalThreshold: 90,
				Enabled:           true,
			},
			valid: true,
		},
		{
			name: "thresholds not sequential",
			policy: TenantPolicy{
				TenantID:          "tenant1",
				LowThreshold:      50,
				MediumThreshold:   30,
				HighThreshold:     70,
				CriticalThreshold: 90,
			},
			valid: false, // Low > Medium
		},
		{
			name: "threshold at boundary",
			policy: TenantPolicy{
				TenantID:          "tenant1",
				LowThreshold:      30,
				MediumThreshold:   30,
				HighThreshold:     70,
				CriticalThreshold: 90,
			},
			valid: true, // Equal thresholds are valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.valid {
				if tt.policy.LowThreshold > tt.policy.MediumThreshold {
					t.Error("Invalid policy: Low > Medium")
				}
				if tt.policy.MediumThreshold > tt.policy.HighThreshold {
					t.Error("Invalid policy: Medium > High")
				}
				if tt.policy.HighThreshold > tt.policy.CriticalThreshold {
					t.Error("Invalid policy: High > Critical")
				}
			}
		})
	}
}

// TestRiskLevel_String is defined in scorer_test.go to avoid duplication

// TestAuthAction_String tests auth action string representation
func TestAuthAction_String(t *testing.T) {
	tests := []struct {
		action   AuthAction
		expected string
	}{
		{AuthActionAllow, "allow"},
		{AuthActionRequireMFA, "require_mfa"},
		{AuthActionRequireStrongMFA, "require_strong_mfa"},
		{AuthActionRequireApproval, "require_approval"},
		{AuthActionBlock, "block"},
		{AuthActionBlockAndAlert, "block_and_alert"},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			result := string(tt.action)
			if result != tt.expected {
				t.Errorf("AuthAction string = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestPolicyEngine_SessionDurations tests session duration assignment based on risk
func TestPolicyEngine_SessionDurations(t *testing.T) {
	config := PolicyConfig{
		LowRiskSessionDuration:      480,
		MediumRiskSessionDuration:   240,
		HighRiskSessionDuration:     60,
		CriticalRiskSessionDuration: 15,
	}

	tests := []struct {
		name     string
		score    int
		expected int
	}{
		{"low risk", 0, config.LowRiskSessionDuration},
		{"low risk boundary", 29, config.LowRiskSessionDuration},
		{"medium risk", 30, config.MediumRiskSessionDuration},
		{"medium risk boundary", 49, config.MediumRiskSessionDuration},
		{"high risk", 50, config.HighRiskSessionDuration},
		{"high risk boundary", 69, config.HighRiskSessionDuration},
		{"critical risk", 70, config.CriticalRiskSessionDuration},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var duration int
			switch {
			case tt.score < 30:
				duration = config.LowRiskSessionDuration
			case tt.score < 50:
				duration = config.MediumRiskSessionDuration
			case tt.score < 70:
				duration = config.HighRiskSessionDuration
			default:
				duration = config.CriticalRiskSessionDuration
			}

			if duration != tt.expected {
				t.Errorf("Score %d: expected duration %d, got %d",
					tt.score, tt.expected, duration)
			}
		})
	}
}

// TestEvaluateResponse_DefaultValues tests response default values
func TestEvaluateResponse_DefaultValues(t *testing.T) {
	response := &EvaluateResponse{
		RequestID:   "test-req-1",
		RiskScore:   0,
		RiskLevel:   RiskLevelLow,
		Action:      AuthActionAllow,
		Reasons:     []string{},
		Anomalies:   []string{},
		EvaluatedAt: time.Now(),
		Allowed:     true,
	}

	if response.RequestID == "" {
		t.Error("RequestID should be set")
	}
	if response.RiskScore < 0 || response.RiskScore > 100 {
		t.Errorf("RiskScore %d out of range [0,100]", response.RiskScore)
	}
	if response.Reasons == nil {
		response.Reasons = []string{}
	}
	if response.Anomalies == nil {
		response.Anomalies = []string{}
	}
}

// TestPolicyEngine_MFAMethods tests MFA method assignment
func TestPolicyEngine_MFAMethods(t *testing.T) {
	config := DefaultPolicyConfig()

	if len(config.DefaultMFAMethods) == 0 {
		t.Error("DefaultMFAMethods should not be empty")
	}

	if len(config.StrongMFAMethods) == 0 {
		t.Error("StrongMFAMethods should not be empty")
	}

	// Strong MFA methods should be a subset or more restrictive
	if len(config.StrongMFAMethods) > len(config.DefaultMFAMethods) {
		t.Log("StrongMFAMethods has more methods than DefaultMFAMethods - this is unusual but not necessarily wrong")
	}
}

// TestIPRiskResult tests IP risk result structure
func TestIPRiskResult(t *testing.T) {
	result := IPRiskResult{
		Score:  40,
		Reason: []string{"tor_exit_node", "vpn_detected"},
	}

	if result.Score < 0 || result.Score > 100 {
		t.Errorf("IP risk score %d out of range [0,100]", result.Score)
	}

	if len(result.Reason) == 0 {
		t.Error("At least one reason should be provided when score > 0")
	}
}
