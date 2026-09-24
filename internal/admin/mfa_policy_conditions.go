package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// errMFAPolicyNotEnforced marks a policy setting that nothing enforces. The
// handlers answer it with 400.
var errMFAPolicyNotEnforced = errors.New("MFA policy setting refused")

// An MFA policy does one thing: while it is enabled, every user with a second
// factor enrolled is challenged at login (evaluateMFA in internal/oauth ORs
// identity.IsMFARequired into the decision). Everything else a policy used to
// store was decoration (#990):
//
//   - required_methods and grace_period_hours are read by nothing. The login
//     path discards the policy it matched, so any enrolled factor satisfies
//     it, including SMS under a policy that names WebAuthn.
//   - conditions never met in the middle. This API accepted factor_enrolled,
//     min_risk_score and client_ids, which no code reads. The evaluator reads
//     groups, ip_ranges, time_windows and attributes, which this API refused.
//
// So these are refused until something enforces them, the rule #956 applied
// to delegation scopes. An update may still clear them, or send back the value
// already stored, so that a policy created before this rule can be renamed and
// toggled.

// checkNewMFAPolicy refuses a new policy that carries a setting nothing enforces.
func checkNewMFAPolicy(conditions, requiredMethods json.RawMessage, graceHours int) error {
	if err := checkMFAConditions(conditions); err != nil {
		return err
	}
	if !isEmptyJSON(requiredMethods) {
		return errRequiredMethods()
	}
	if graceHours != 0 {
		return errGracePeriod()
	}
	return nil
}

// storedMFAPolicySettings is what an update is compared with.
type storedMFAPolicySettings struct {
	conditions      json.RawMessage
	requiredMethods json.RawMessage
	graceHours      int
}

// checkMFAPolicyUpdate refuses an update that sets one of these fields to a new,
// non-empty value. A nil field is one the request did not send.
func checkMFAPolicyUpdate(stored storedMFAPolicySettings, conditions, requiredMethods *json.RawMessage, graceHours *int) error {
	if conditions != nil && !sameJSON(*conditions, stored.conditions) {
		if err := checkMFAConditions(*conditions); err != nil {
			return err
		}
	}
	if requiredMethods != nil && !isEmptyJSON(*requiredMethods) && !sameJSON(*requiredMethods, stored.requiredMethods) {
		return errRequiredMethods()
	}
	if graceHours != nil && *graceHours != 0 && *graceHours != stored.graceHours {
		return errGracePeriod()
	}
	return nil
}

// checkMFAConditions accepts only an empty set of conditions.
func checkMFAConditions(raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var conds map[string]any
	if err := json.Unmarshal(raw, &conds); err != nil {
		return fmt.Errorf("%w: conditions must be a JSON object: %v", errMFAPolicyNotEnforced, err)
	}
	if len(conds) == 0 {
		return nil
	}
	keys := make([]string, 0, len(conds))
	for key := range conds {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return fmt.Errorf("%w: conditions are not enforced (%s), so a policy cannot have any yet; "+
		"it applies to every user with a second factor enrolled", errMFAPolicyNotEnforced, strings.Join(keys, ", "))
}

func errRequiredMethods() error {
	return fmt.Errorf("%w: required_methods is not enforced, so a policy cannot require a particular "+
		"method yet; any factor the user has enrolled satisfies it", errMFAPolicyNotEnforced)
}

func errGracePeriod() error {
	return fmt.Errorf("%w: grace_period_hours is not enforced, so a policy cannot have a grace period yet",
		errMFAPolicyNotEnforced)
}

// isEmptyJSON reports whether raw is absent, null, {} or [].
func isEmptyJSON(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	switch x := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(x) == 0
	case []any:
		return len(x) == 0
	}
	return false
}

// sameJSON compares two JSON values by content, so that a client sending back
// the stored value in a different spacing or key order is not refused.
func sameJSON(a, b json.RawMessage) bool {
	if isEmptyJSON(a) && isEmptyJSON(b) {
		return true
	}
	var va, vb any
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}
