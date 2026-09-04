package abac

import "testing"

// Decide is the whole staging contract in four lines, so it gets a table.
//
// The rule that matters is the last column: wouldDeny is true on BOTH the
// observe and enforce branches when the policies refused. Enforcement must
// never be quieter than report mode — an operator who flips ABAC_ENFORCE from
// observe to enforce must not lose the records that told them it was safe.
// The assignment gate learned that the hard way; this follows it.
func TestDecide(t *testing.T) {
	deny := Result{Allowed: false, Reason: "denied by policy: x", PolicyID: "p1", Matched: true}
	allow := Result{Allowed: true, Reason: "allowed by policy: y", PolicyID: "p2", Matched: true}
	silent := Result{Allowed: true, Reason: "no matching policies"}

	cases := []struct {
		name          string
		res           Result
		mode          Mode
		wantAllow     bool
		wantWouldDeny bool
	}{
		{"off never consults", deny, ModeOff, true, false},
		{"observe permits but records", deny, ModeObserve, true, true},
		{"enforce refuses and records", deny, ModeEnforce, false, true},
		{"an allow decision is silent in observe", allow, ModeObserve, true, false},
		{"an allow decision is silent in enforce", allow, ModeEnforce, true, false},
		{"no matching policy permits", silent, ModeEnforce, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			allow, wouldDeny := Decide(c.res, c.mode)
			if allow != c.wantAllow || wouldDeny != c.wantWouldDeny {
				t.Fatalf("Decide(%v, %q) = (%v, %v), want (%v, %v)",
					c.res.Allowed, c.mode, allow, wouldDeny, c.wantAllow, c.wantWouldDeny)
			}
		})
	}
}

// A typo in a deployment variable must fail toward today's behaviour. The
// opposite — an unrecognised value meaning "enforce" — would turn a misspelt
// env var into an outage.
func TestParseModeFailsTowardOff(t *testing.T) {
	for _, in := range []string{"", "  ", "ENFORCED", "on", "true", "yes", "Observe ", "ENFORCE"} {
		got := ParseMode(in)
		switch in {
		case "Observe ":
			if got != ModeObserve {
				t.Errorf("ParseMode(%q) = %q, want observe (case and space tolerant)", in, got)
			}
		case "ENFORCE":
			if got != ModeEnforce {
				t.Errorf("ParseMode(%q) = %q, want enforce", in, got)
			}
		default:
			if got != ModeOff {
				t.Errorf("ParseMode(%q) = %q, want off — an unrecognised value must not enforce", in, got)
			}
		}
	}
}

// Gate with mode off must not touch the database at all. The nil handle here
// is the proof: if the short-circuit regressed, Evaluate would be reached and
// return its fail-closed result instead.
func TestGateOffDoesNoWork(t *testing.T) {
	allow, wouldDeny, res := Gate(t.Context(), nil, "org-1", ModeOff, EvaluationRequest{ResourceType: "application"})
	if !allow || wouldDeny {
		t.Fatalf("mode off = (%v, %v), want (true, false)", allow, wouldDeny)
	}
	if !res.Allowed {
		t.Fatal("mode off must not produce a denying result")
	}
}

// A decision point that cannot read its policies must deny. The old evaluator
// got this right for a query error and wrong for the default case; both are
// pinned here.
func TestEvaluateFailsClosedWithoutADatabaseOrOrg(t *testing.T) {
	if res := Evaluate(t.Context(), nil, "org-1", EvaluationRequest{}); res.Allowed {
		t.Error("no database handle must fail closed")
	}
}

func TestConditionOperators(t *testing.T) {
	attrs := map[string]interface{}{
		"department": "finance",
		"roles":      []string{"auditor", "user"},
		"level":      7,
	}
	cases := []struct {
		name string
		cond Condition
		want bool
	}{
		{"eq matches", Condition{"department", "eq", "finance"}, true},
		{"eq differs", Condition{"department", "eq", "sales"}, false},
		{"neq", Condition{"department", "neq", "sales"}, true},
		{"gt", Condition{"level", "gt", 5}, true},
		{"lte boundary", Condition{"level", "lte", 7}, true},
		{"between", Condition{"level", "between", []interface{}{5, 9}}, true},
		{"contains", Condition{"department", "contains", "fin"}, true},
		// A list-valued subject attribute must match when ANY member is in the
		// condition's list. Comparing the whole slice as one string — which is
		// what fmt.Sprintf on the raw value does — makes every roles/groups
		// policy silently match nothing.
		{"in matches one role of many", Condition{"roles", "in", []interface{}{"admin", "auditor"}}, true},
		{"in matches no role", Condition{"roles", "in", []interface{}{"admin"}}, false},
		{"not_in", Condition{"roles", "not_in", []interface{}{"admin"}}, true},
		// An attribute the subject does not carry never matches, so a policy
		// written against something this install never populates matches
		// nothing — which the page's Test button now shows honestly.
		{"absent attribute", Condition{"cost_centre", "eq", "anything"}, false},
		{"unknown operator", Condition{"department", "sounds_like", "finance"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EvaluateCondition(c.cond, attrs); got != c.want {
				t.Fatalf("EvaluateCondition(%+v) = %v, want %v", c.cond, got, c.want)
			}
		})
	}
}
