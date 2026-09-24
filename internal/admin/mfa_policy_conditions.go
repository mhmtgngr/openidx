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

// errMFAPolicyInvalid marks a required-methods list or grace period the login
// path could not enforce as written. The handlers answer it with 400.
var errMFAPolicyInvalid = errors.New("MFA policy setting invalid")

// What an MFA policy does at password sign-in (evaluateMFA in internal/oauth):
//
//   - With no required methods, every user with a second factor enrolled is
//     challenged, and any enrolled factor satisfies it.
//   - With required methods, the challenge offers only those, plus an
//     administrator's bypass code. A user with none of them gets the grace
//     period, counted from their first sign-in under the policy, to add one,
//     and signs in as before meanwhile. After it, sign-in is refused unless
//     they have a bypass code.
//
// Conditions are still refused (#990): this API used to accept
// factor_enrolled, min_risk_score and client_ids, which no code reads, and
// refused groups, ip_ranges, time_windows and attributes, which the evaluator
// reads. An update may clear them, or send back the value already stored, so
// that a policy created before #991 can still be edited.

// mfaPolicyMethods are the methods a policy can require: the primary factors
// the login offers (evaluateMFA). Backup and bypass codes are recovery, not a
// method a policy can ask for.
var mfaPolicyMethods = []string{"totp", "webauthn", "push", "sms", "email"}

// maxMFAGraceHours bounds the grace period: 30 days.
const maxMFAGraceHours = 720

// checkNewMFAPolicy refuses a new policy with a setting that nothing enforces,
// or one the login path could not enforce as written.
func checkNewMFAPolicy(conditions, requiredMethods json.RawMessage, graceHours int) error {
	if err := checkMFAConditions(conditions); err != nil {
		return err
	}
	methods, err := parseMFAMethods(requiredMethods)
	if err != nil {
		return err
	}
	return checkMFAGrace(len(methods) > 0, graceHours)
}

// storedMFAPolicySettings is what an update is compared with.
type storedMFAPolicySettings struct {
	conditions      json.RawMessage
	requiredMethods json.RawMessage
	graceHours      int
}

// checkMFAPolicyUpdate checks an update against the policy it changes, and
// reports whether it changes the set of required methods. A nil field is one
// the request did not send, and keeps its stored value. When the method set
// changes, every user's grace period under the policy starts again: their
// window was the time to add one of the old methods.
func checkMFAPolicyUpdate(stored storedMFAPolicySettings, conditions, requiredMethods *json.RawMessage, graceHours *int) (methodsChanged bool, err error) {
	if conditions != nil && !sameJSON(*conditions, stored.conditions) {
		if err := checkMFAConditions(*conditions); err != nil {
			return false, err
		}
	}
	// Stored methods were cleared by migration v203 or written by this API.
	storedMethods, _ := parseMFAMethods(stored.requiredMethods)
	methods := storedMethods
	if requiredMethods != nil {
		if methods, err = parseMFAMethods(*requiredMethods); err != nil {
			return false, err
		}
		methodsChanged = !sameMethodSet(storedMethods, methods)
	}
	grace := stored.graceHours
	if graceHours != nil {
		grace = *graceHours
	}
	if err := checkMFAGrace(len(methods) > 0, grace); err != nil {
		return false, err
	}
	return methodsChanged, nil
}

// parseMFAMethods reads a required-methods list: absent, null or [] is none;
// otherwise a JSON array of distinct method names from mfaPolicyMethods.
func parseMFAMethods(raw json.RawMessage) ([]string, error) {
	if isEmptyJSON(raw) {
		return nil, nil
	}
	var methods []string
	if err := json.Unmarshal(raw, &methods); err != nil {
		return nil, fmt.Errorf("%w: required_methods must be a list of method names", errMFAPolicyInvalid)
	}
	seen := map[string]bool{}
	for _, m := range methods {
		if !isMFAPolicyMethod(m) {
			return nil, fmt.Errorf("%w: %q is not a method a policy can require; use one of %s",
				errMFAPolicyInvalid, m, strings.Join(mfaPolicyMethods, ", "))
		}
		if seen[m] {
			return nil, fmt.Errorf("%w: required_methods lists %q twice", errMFAPolicyInvalid, m)
		}
		seen[m] = true
	}
	return methods, nil
}

func isMFAPolicyMethod(m string) bool {
	for _, known := range mfaPolicyMethods {
		if m == known {
			return true
		}
	}
	return false
}

// checkMFAGrace bounds the grace period, and refuses one on a policy that
// requires no method: there is nothing to add, so it would change nothing.
func checkMFAGrace(hasMethods bool, hours int) error {
	if hours < 0 || hours > maxMFAGraceHours {
		return fmt.Errorf("%w: grace_period_hours must be between 0 and %d", errMFAPolicyInvalid, maxMFAGraceHours)
	}
	if hours > 0 && !hasMethods {
		return fmt.Errorf("%w: a grace period applies only to a policy that requires methods; "+
			"set required_methods, or set grace_period_hours to 0", errMFAPolicyInvalid)
	}
	return nil
}

func sameMethodSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	return reflect.DeepEqual(as, bs)
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
		"it applies to every user who signs in with a password", errMFAPolicyNotEnforced, strings.Join(keys, ", "))
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
