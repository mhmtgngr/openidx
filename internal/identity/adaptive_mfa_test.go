package identity

import (
	"testing"
)

// TestParseJSON_ActuallyParses is the regression guard for the risk-policy
// "silent no-op" bug: parseJSON used to do nothing, so every risk policy loaded
// with nil Conditions/Actions and never applied. These assertions fail if the
// function is ever reverted to a no-op.
func TestParseJSON_ActuallyParses(t *testing.T) {
	t.Run("populates the target map", func(t *testing.T) {
		var out map[string]interface{}
		if err := parseJSON([]byte(`{"risk_score_gte":70,"require_mfa":true}`), &out); err != nil {
			t.Fatalf("parseJSON returned error: %v", err)
		}
		if out == nil {
			t.Fatal("parseJSON left the target nil — the no-op regression is back")
		}
		if got, ok := out["risk_score_gte"].(float64); !ok || got != 70 {
			t.Errorf("risk_score_gte = %v (%T), want 70", out["risk_score_gte"], out["risk_score_gte"])
		}
		if got, ok := out["require_mfa"].(bool); !ok || !got {
			t.Errorf("require_mfa = %v, want true", out["require_mfa"])
		}
	})

	t.Run("empty input is a no-op without error", func(t *testing.T) {
		var out map[string]interface{}
		if err := parseJSON(nil, &out); err != nil {
			t.Errorf("parseJSON(nil) returned error: %v", err)
		}
	})

	t.Run("malformed input returns an error (so the policy is skipped, not applied empty)", func(t *testing.T) {
		var out map[string]interface{}
		if err := parseJSON([]byte(`{not valid json`), &out); err == nil {
			t.Error("parseJSON accepted malformed JSON; a broken policy must surface an error, not load empty")
		}
	})
}
