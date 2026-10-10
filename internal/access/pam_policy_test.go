package access

import (
	"testing"
	"time"

	"github.com/openidx/openidx/internal/externalid"
)

// An organization with no policy row runs the secure defaults: every session
// capped, internal sessions recorded, a bounded approval window.
func TestDefaultPamPolicyIsTheSecureOne(t *testing.T) {
	p := defaultPamPolicy()
	if p.MaxSessionHours <= 0 {
		t.Error("the default leaves sessions uncapped")
	}
	if !p.RecordInternal {
		t.Error("the default does not record internal sessions")
	}
	if p.RequireApprovalInternal {
		t.Error("the default asks approval for every internal session; that is a policy, not a default")
	}
	if p.LaunchApprovalWindow() != 60*time.Minute {
		t.Errorf("default approval window = %v, want 60m", p.LaunchApprovalWindow())
	}
	if p.Source != "default" {
		t.Errorf("source = %q, want default", p.Source)
	}
}

// The policy adds to an internal caller's entry and never subtracts from it,
// and leaves an external caller to external_pam.go.
func TestPinOrgPamPolicyOnlyEverAddsForInternalCallers(t *testing.T) {
	pol := PamPolicy{RequireApprovalInternal: true, RecordInternal: true}

	e := pamLaunchEntry{}
	pinOrgPamPolicy(&e, pamCaller{}, pol)
	if !e.RequireApproval || !e.RecordSession {
		t.Errorf("policy not applied to an internal caller: %+v", e)
	}

	e = pamLaunchEntry{RequireApproval: true, RecordSession: true}
	pinOrgPamPolicy(&e, pamCaller{}, PamPolicy{})
	if !e.RequireApproval || !e.RecordSession {
		t.Errorf("an empty policy switched the entry's own settings off: %+v", e)
	}

	e = pamLaunchEntry{}
	pinOrgPamPolicy(&e, pamCaller{External: true}, pol)
	if e.RequireApproval || e.RecordSession {
		t.Errorf("an external caller was touched here; that is pinExternalPamPolicy's job: %+v", e)
	}
}

// The 8-hour ceiling for external users is a ceiling: the policy may shorten
// it, never lengthen it, and 0 (no cap) means the ceiling.
func TestExternalSessionCapNeverExceedsTheCeiling(t *testing.T) {
	cases := map[int]time.Duration{
		0:   externalid.MaxPamSession,
		2:   2 * time.Hour,
		8:   externalid.MaxPamSession,
		168: externalid.MaxPamSession,
	}
	for hours, want := range cases {
		if got := (PamPolicy{MaxSessionHours: hours}).externalSessionCap(); got != want {
			t.Errorf("max_session_hours=%d: external cap %v, want %v", hours, got, want)
		}
	}
	if got := externalSessionPolicy(PamPolicy{MaxSessionHours: 2})["max_minutes"]; got != 120 {
		t.Errorf("session_policy max_minutes = %v, want 120", got)
	}
}

func TestSetPamPolicyRequestValidation(t *testing.T) {
	ok := setPamPolicyRequest{MaxSessionHours: 8, LaunchApprovalWindowMinutes: 60}
	if msg := ok.validate(); msg != "" {
		t.Fatalf("a valid request was refused: %s", msg)
	}
	for _, bad := range []setPamPolicyRequest{
		{MaxSessionHours: -1, LaunchApprovalWindowMinutes: 60},
		{MaxSessionHours: 200, LaunchApprovalWindowMinutes: 60},
		{MaxSessionHours: 8, LaunchApprovalWindowMinutes: 1},
		{MaxSessionHours: 8, LaunchApprovalWindowMinutes: 60, IdleTimeoutMinutes: 99999},
	} {
		if bad.validate() == "" {
			t.Errorf("request %+v was accepted", bad)
		}
	}
}
