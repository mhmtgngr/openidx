// Package abac owns the single question "do this tenant's attribute-based
// policies permit this action?", and the answer is now consumed by the
// enforcement points rather than only by the page that authors the policies.
//
// It exists because that was not true. EvaluateABACPolicies lived in
// internal/governance and had exactly two callers: the handler behind the ABAC
// Policies page's own "Test" button, and a benchmark. No policy decision point
// in the product consulted it. An admin could write a deny policy, watch the
// page confirm it evaluates to deny, save it, and change nothing about who
// could reach what -- the flagship instance of this codebase's defect class, a
// control that displays without enforcing.
//
// Two other things travelled with it. The evaluator ended in
//
//	// Default: allowed (fail-open in dev mode)
//	return ABACEvaluationResult{Allowed: true, ...}
//
// with no dev-mode check anywhere in the function: it defaulted to allow in
// every environment. That default is correct semantics -- ABAC policies here
// are additive, so "no policy matched" means "these policies have nothing to
// say", not "deny" -- but the comment described a safeguard that did not
// exist, sixty lines below a query-error path that fails CLOSED with a comment
// explaining why. And the query carried no org predicate, relying on the RLS
// belt alone; it now names org_id, which is what tools/orgscope checks.
//
// orgID is an explicit parameter rather than read from orgctx, for the same
// reason internal/appaccess takes one: this package is consumed by services
// with different context plumbing, and an explicit scope is testable.
package abac

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/openidx/openidx/internal/common/database"
)

// Policy is one attribute-based access control policy.
type Policy struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	ResourceType string      `json:"resource_type"`
	ResourceID   *string     `json:"resource_id,omitempty"`
	Conditions   []Condition `json:"conditions"`
	Effect       string      `json:"effect"`
	Priority     int         `json:"priority"`
	Enabled      bool        `json:"enabled"`
}

// Condition is a single attribute test within a policy. Every condition of a
// policy must match for the policy to apply.
type Condition struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
}

// EvaluationRequest is the subject and resource a decision is asked about.
type EvaluationRequest struct {
	UserAttributes map[string]interface{} `json:"user_attributes"`
	ResourceType   string                 `json:"resource_type"`
	ResourceID     string                 `json:"resource_id"`
}

// Result is one decision. PolicyID names the policy that decided it, empty
// when none matched.
type Result struct {
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
	// Matched reports whether any policy applied. A decision that matched
	// nothing is an absence of opinion, not an approval, and an enforcement
	// point that wants to distinguish the two reads this rather than Allowed.
	Matched bool `json:"matched"`
}

// Evaluate returns the tenant's ABAC decision for req.
//
// Deny beats allow, and among policies of the same effect the highest priority
// is reported. With no matching policy the result is Allowed with Matched
// false: these policies are additive, so silence permits. A query error fails
// CLOSED -- a decision point that cannot read its policies must deny, because
// returning "allowed" would tell every consumer to permit the action precisely
// when the evaluation could not run.
func Evaluate(ctx context.Context, db *database.PostgresDB, orgID string, req EvaluationRequest) Result {
	if db == nil || db.Pool == nil {
		return Result{Allowed: false, Reason: "policy evaluation unavailable, failing closed"}
	}
	if orgID == "" {
		return Result{Allowed: false, Reason: "no organization context, failing closed"}
	}

	rows, err := db.Pool.Query(ctx, `
		SELECT id, name, conditions, effect, priority
		FROM abac_policies
		WHERE org_id = $3
			AND enabled = true
			AND resource_type IN ($1, '*')
			AND (resource_id IS NULL OR resource_id = '' OR resource_id = $2)
		ORDER BY priority DESC
	`, req.ResourceType, req.ResourceID, orgID)
	if err != nil {
		return Result{Allowed: false, Reason: "policy evaluation error, failing closed"}
	}
	defer rows.Close()

	var denyMatch, allowMatch *Result
	for rows.Next() {
		var policyID, name, effect string
		var conditionsJSON []byte
		var priority int
		if err := rows.Scan(&policyID, &name, &conditionsJSON, &effect, &priority); err != nil {
			continue
		}
		var conditions []Condition
		if len(conditionsJSON) > 0 {
			if err := json.Unmarshal(conditionsJSON, &conditions); err != nil {
				continue
			}
		}
		if !conditionsMatch(conditions, req.UserAttributes) {
			continue
		}
		if effect == "deny" {
			denyMatch = &Result{
				Allowed:  false,
				Reason:   fmt.Sprintf("denied by policy: %s", name),
				PolicyID: policyID,
				Matched:  true,
			}
			break // deny takes immediate precedence
		}
		if allowMatch == nil && effect == "allow" {
			allowMatch = &Result{
				Allowed:  true,
				Reason:   fmt.Sprintf("allowed by policy: %s", name),
				PolicyID: policyID,
				Matched:  true,
			}
		}
	}
	if err := rows.Err(); err != nil {
		return Result{Allowed: false, Reason: "policy evaluation error, failing closed"}
	}

	if denyMatch != nil {
		return *denyMatch
	}
	if allowMatch != nil {
		return *allowMatch
	}
	return Result{Allowed: true, Reason: "no matching policies", Matched: false}
}

// conditionsMatch reports whether every condition holds. A policy with no
// conditions matches everything of its resource type, which is how a blanket
// deny for a resource is written.
func conditionsMatch(conditions []Condition, attrs map[string]interface{}) bool {
	for _, c := range conditions {
		if !EvaluateCondition(c, attrs) {
			return false
		}
	}
	return true
}

// EvaluateCondition evaluates one condition against the subject's attributes.
// An attribute the subject does not carry never matches -- a policy written
// against an attribute this install never populates therefore matches nothing,
// which the ABAC page's Test button now shows honestly.
func EvaluateCondition(cond Condition, attrs map[string]interface{}) bool {
	attrVal, exists := attrs[cond.Attribute]
	if !exists {
		return false
	}

	switch cond.Operator {
	case "eq":
		return fmt.Sprintf("%v", attrVal) == fmt.Sprintf("%v", cond.Value)
	case "neq":
		return fmt.Sprintf("%v", attrVal) != fmt.Sprintf("%v", cond.Value)
	case "in":
		return evalIn(attrVal, cond.Value)
	case "not_in":
		return !evalIn(attrVal, cond.Value)
	case "gt":
		a, b, ok := toFloat64Pair(attrVal, cond.Value)
		return ok && a > b
	case "gte":
		a, b, ok := toFloat64Pair(attrVal, cond.Value)
		return ok && a >= b
	case "lt":
		a, b, ok := toFloat64Pair(attrVal, cond.Value)
		return ok && a < b
	case "lte":
		a, b, ok := toFloat64Pair(attrVal, cond.Value)
		return ok && a <= b
	case "between":
		return evalBetween(attrVal, cond.Value)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", attrVal), fmt.Sprintf("%v", cond.Value))
	default:
		return false
	}
}

// evalIn reports whether attrVal appears in a list-valued condition. A
// subject attribute that is itself a list (roles, groups) matches when ANY of
// its members is in the list -- without that, no policy could ever be written
// against a multi-valued attribute.
func evalIn(attrVal interface{}, condValue interface{}) bool {
	list, ok := condValue.([]interface{})
	if !ok {
		return false
	}
	want := map[string]bool{}
	for _, v := range list {
		want[fmt.Sprintf("%v", v)] = true
	}
	for _, have := range stringsOf(attrVal) {
		if want[have] {
			return true
		}
	}
	return false
}

// stringsOf renders a subject attribute as the set of strings it stands for:
// one for a scalar, one per member for a list.
func stringsOf(v interface{}) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, e := range val {
			out = append(out, fmt.Sprintf("%v", e))
		}
		return out
	default:
		return []string{fmt.Sprintf("%v", v)}
	}
}

func evalBetween(attrVal interface{}, condValue interface{}) bool {
	list, ok := condValue.([]interface{})
	if !ok || len(list) != 2 {
		return false
	}
	a, aOk := toFloat64(attrVal)
	lo, loOk := toFloat64(list[0])
	hi, hiOk := toFloat64(list[1])
	if !aOk || !loOk || !hiOk {
		return false
	}
	return a >= lo && a <= hi
}

func toFloat64Pair(a, b interface{}) (float64, float64, bool) {
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	return af, bf, aOk && bOk
}

func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case json.Number:
		f, err := val.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(val, 64)
		return f, err == nil
	default:
		f, err := strconv.ParseFloat(fmt.Sprintf("%v", v), 64)
		return f, err == nil
	}
}
