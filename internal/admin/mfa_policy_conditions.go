package admin

import (
	"encoding/json"
	"fmt"
)

// validateMFAConditions rejects a policy whose conditions this server does not
// evaluate. Accepting unknown keys silently is exactly how mfa_policies became a
// knob that did nothing: the admin authors a condition, no code reads it, and the
// policy appears to be in force while it is not.
func validateMFAConditions(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var conds map[string]any
	if err := json.Unmarshal(raw, &conds); err != nil {
		return fmt.Errorf("conditions must be a JSON object: %w", err)
	}
	for key, val := range conds {
		switch key {
		case "factor_enrolled":
			if _, ok := val.(bool); !ok {
				return fmt.Errorf("condition %q must be a boolean", key)
			}
		case "min_risk_score":
			if _, ok := val.(float64); !ok {
				return fmt.Errorf("condition %q must be a number", key)
			}
		case "client_ids":
			items, ok := val.([]any)
			if !ok {
				return fmt.Errorf("condition %q must be an array of client ids", key)
			}
			for _, it := range items {
				if _, ok := it.(string); !ok {
					return fmt.Errorf("condition %q must contain only strings", key)
				}
			}
		default:
			return fmt.Errorf("unsupported condition %q (supported: factor_enrolled, min_risk_score, client_ids)", key)
		}
	}
	return nil
}
