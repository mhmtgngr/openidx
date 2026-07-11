// Package risk provides unit tests for risk-based authentication policies
package risk

import (
	"testing"
)

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
