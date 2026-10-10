package accessdecision

import "testing"

// A fresh second factor is judged only by a caller that can tell. The proxy
// knows the device, the country and the risk of a request but not when the
// person last proved a factor, so for it the condition is listed, not failed.
func TestAFreshFactorIsJudgedOnlyWhenTheCallerKnowsIt(t *testing.T) {
	c := Conditions{RequireStepUp: true}

	d := judgeConditions(Decision{Grant: GrantDirect}, c, Subject{KnowsSituation: true, FreshMFA: false})
	if len(d.Conditions) != 1 || d.Conditions[0].Name != ConditionStepUp {
		t.Fatalf("the condition must be listed: %+v", d.Conditions)
	}
	if d.Conditions[0].Judged || d.Conditions[0].Observed != "unknown" || len(d.Reasons) != 0 || d.StepUp {
		t.Fatalf("a caller that cannot tell must not fail the condition: %+v reasons %v stepup %v", d.Conditions[0], d.Reasons, d.StepUp)
	}

	d = judgeConditions(Decision{Grant: GrantDirect}, c, Subject{KnowsSituation: true, MFAKnown: true, FreshMFA: false})
	if !d.Conditions[0].Judged || d.Conditions[0].Observed != "stale" || len(d.Reasons) != 1 || d.Reasons[0] != ReasonStepUp || !d.StepUp {
		t.Fatalf("a caller that knows the factor is stale must fail it: %+v reasons %v stepup %v", d.Conditions[0], d.Reasons, d.StepUp)
	}

	d = judgeConditions(Decision{Grant: GrantDirect}, c, Subject{KnowsSituation: true, MFAKnown: true, FreshMFA: true})
	if !d.Conditions[0].Satisfied || len(d.Reasons) != 0 || d.StepUp {
		t.Fatalf("a fresh factor satisfies it: %+v reasons %v", d.Conditions[0], d.Reasons)
	}
}
