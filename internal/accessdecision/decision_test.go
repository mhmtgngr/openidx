package accessdecision

import (
	"strings"
	"testing"
)

func intp(i int) *int { return &i }

// A condition whose input the caller does not know is listed and does not
// deny; one the caller knows and the subject fails denies and asks for
// step-up where the proxy already does.
func TestConditionsAreJudgedOnlyWhenKnown(t *testing.T) {
	c := Conditions{RequireDeviceTrust: true, MaxRiskScore: intp(50), AllowedCountries: []string{"TR", "DE"}}

	d := judgeConditions(Decision{Grant: GrantDirect}, c, Subject{})
	if len(d.Reasons) != 0 || len(d.Conditions) != 3 {
		t.Fatalf("an unknown situation denied or dropped conditions: %+v", d)
	}
	for _, cr := range d.Conditions {
		if cr.Judged {
			t.Errorf("%s was judged without an input", cr.Name)
		}
	}

	d = judgeConditions(Decision{Grant: GrantDirect}, c, Subject{KnowsSituation: true, DeviceTrusted: false, RiskScore: 70, Country: "FR"})
	want := map[string]bool{ReasonDeviceTrust: true, ReasonRiskAboveMax: true, ReasonCountry: true}
	for _, r := range d.Reasons {
		delete(want, r)
	}
	if len(want) != 0 {
		t.Errorf("missing reasons: %v (got %v)", want, d.Reasons)
	}
	if !d.StepUp {
		t.Error("an untrusted device over the risk ceiling must ask for step-up")
	}

	d = judgeConditions(Decision{Grant: GrantDirect}, c, Subject{KnowsSituation: true, DeviceTrusted: true, RiskScore: 10, Country: "tr"})
	if len(d.Reasons) != 0 {
		t.Errorf("a trusted, low-risk subject in an allowed country was refused: %v", d.Reasons)
	}
}

// The verdict applies only under enforcement; what it would have been is
// always carried.
func TestObserveModeAllowsButSaysWhatItWouldDo(t *testing.T) {
	d := deny(Decision{Enforced: false}, ReasonNotAssigned)
	if !d.Allowed || !d.WouldDeny {
		t.Errorf("observe mode: allowed=%v wouldDeny=%v", d.Allowed, d.WouldDeny)
	}
	d = deny(Decision{Enforced: true}, ReasonNotAssigned)
	if d.Allowed || !d.WouldDeny {
		t.Errorf("enforce mode: allowed=%v wouldDeny=%v", d.Allowed, d.WouldDeny)
	}
}

// Explain names the grant, every condition and the verdict, in that order.
func TestExplainReadsAsOneSentence(t *testing.T) {
	d := Decision{AppName: "Payroll", Grant: GrantGroupPrefix + "Finance", Enforced: true,
		Conditions: []ConditionResult{
			{Name: ConditionDeviceTrust, Required: "trusted", Observed: "trusted", Satisfied: true, Judged: true},
			{Name: ConditionRiskCeiling, Required: "<= 50", Observed: "72", Satisfied: false, Judged: true},
			{Name: ConditionCountry, Required: "TR,DE", Observed: "unknown", Judged: false},
		},
		Reasons: []string{ReasonRiskAboveMax}}
	got := Explain(d)
	for _, want := range []string{"Payroll: assigned through group Finance", "device_trust ✓", "risk_ceiling ✗ (<= 50, observed 72)", "country ? (TR,DE, observed unknown)", "→ denied: risk_above_max"} {
		if !strings.Contains(got, want) {
			t.Errorf("explain lacks %q:\n%s", want, got)
		}
	}
	if got := Explain(Decision{AppID: "app-1"}); !strings.Contains(got, "app-1: not assigned") || !strings.Contains(got, "→ allowed") {
		t.Errorf("an unassigned, unenforced decision reads wrong: %s", got)
	}
	if got := Explain(Decision{AppName: "VPN", Grant: GrantLegacyRolePrefix + "admin", Enforced: false, Reasons: []string{ReasonDeviceTrust}}); !strings.Contains(got, "legacy role admin") || !strings.Contains(got, "would deny") {
		t.Errorf("legacy role / observe wording wrong: %s", got)
	}
}
