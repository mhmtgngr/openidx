package stepup

import (
	"context"
	"testing"
	"time"
)

// The decisions this gate makes are the ones an operator will be surprised by,
// so each is pinned here: which callers are exempt, what happens when the
// freshness cannot be established at all, and — the property that makes the
// staged rollout work — that observe and enforce disagree about the OUTCOME
// and agree about the RECORD.

func TestParseModeFailsTowardTodaysBehaviour(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Mode
	}{
		{"", ModeOff},
		{"off", ModeOff},
		{"observe", ModeObserve},
		{"enforce", ModeEnforce},
		{"ENFORCE", ModeEnforce},
		{"  Observe  ", ModeObserve},
		// A typo must not silently enforce. An operator who writes "enforc"
		// gets today's behaviour, not a locked-out admin team.
		{"enforc", ModeOff},
		{"on", ModeOff},
		{"true", ModeOff},
	} {
		if got := ParseMode(tc.in); got != tc.want {
			t.Errorf("ParseMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMachineCallersAreNeverGated(t *testing.T) {
	for _, tc := range []struct {
		name   string
		caller Caller
		want   bool
	}{
		{"client-credentials token has no subject", Caller{}, true},
		{"api key", Caller{UserID: "u1", AuthMethod: "api_key"}, true},
		{"api key, odd casing", Caller{UserID: "u1", AuthMethod: "API_KEY"}, true},
		{"service account", Caller{UserID: "u1", ServiceAccountID: "sa1"}, true},
		{"a person", Caller{UserID: "u1", SessionID: "s1"}, false},
		// A person whose token carries no session is NOT a machine: freshness
		// cannot be established, which is a different answer from "exempt".
		{"a person with no session", Caller{UserID: "u1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.caller.IsMachine(); got != tc.want {
				t.Errorf("IsMachine() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGateOffDecidesNothing(t *testing.T) {
	// nil db proves it: with the gate off, no query is attempted at all, so a
	// service that has not turned the gate on pays nothing for it.
	d := Gate(context.Background(), nil, ModeOff, time.Minute, Caller{UserID: "u1", SessionID: "s1"})
	if !d.Allowed || d.Required {
		t.Fatalf("gate off returned %+v, want allowed and not required", d)
	}
}

func TestMachineCallerPassesEvenUnderEnforce(t *testing.T) {
	// Also with a nil db: an unattended integration must not start failing at
	// 03:00 with a 403 nobody can clear, and must not cost a query either.
	for _, c := range []Caller{
		{},
		{UserID: "u1", AuthMethod: "api_key"},
		{UserID: "u1", ServiceAccountID: "sa1"},
	} {
		d := Gate(context.Background(), nil, ModeEnforce, time.Minute, c)
		if !d.Allowed || d.Reason != ReasonMachineCaller {
			t.Errorf("Gate(%+v) = %+v, want allowed with reason %q", c, d, ReasonMachineCaller)
		}
	}
}

// TestAPersonWithNoSessionFailsClosedUnderEnforce: freshness cannot be
// established for a user token with no sid. Under enforce that is a refusal,
// for the reason the assignment gate was changed in P5 — the flag an operator
// flips to lock something down must not come open when the fact it needs is
// missing. Under observe it is a record: that shape is a bug in whatever
// minted the token, and an operator needs to see it BEFORE they enforce.
func TestAPersonWithNoSessionFailsClosedUnderEnforce(t *testing.T) {
	caller := Caller{UserID: "u1"}

	obs := Gate(context.Background(), nil, ModeObserve, time.Minute, caller)
	if !obs.Allowed || !obs.Required || obs.Reason != ReasonNoSession {
		t.Errorf("observe: %+v, want allowed, required, reason %q", obs, ReasonNoSession)
	}

	enf := Gate(context.Background(), nil, ModeEnforce, time.Minute, caller)
	if enf.Allowed || !enf.Required || enf.Reason != ReasonNoSession {
		t.Errorf("enforce: %+v, want refused, required, reason %q", enf, ReasonNoSession)
	}
}

// TestEnforcementIsNeverQuieterThanReportMode is the property the staged
// rollout rests on. Whatever the mode, a session that fails the freshness test
// sets Required — which is what drives the audit write. If enforce recorded
// less than observe, an operator who flipped the flag would lose the very rows
// that told them it was safe to flip it.
func TestEnforcementIsNeverQuieterThanReportMode(t *testing.T) {
	caller := Caller{UserID: "u1"} // no session: fails the test without a DB

	obs := Gate(context.Background(), nil, ModeObserve, time.Minute, caller)
	enf := Gate(context.Background(), nil, ModeEnforce, time.Minute, caller)

	if !obs.Required || !enf.Required {
		t.Fatalf("observe.Required=%v enforce.Required=%v — both must record", obs.Required, enf.Required)
	}
	if obs.Reason != enf.Reason {
		t.Errorf("reasons differ between modes: observe %q, enforce %q", obs.Reason, enf.Reason)
	}
	if !obs.Allowed || enf.Allowed {
		t.Errorf("the modes must differ in OUTCOME: observe allowed=%v, enforce allowed=%v", obs.Allowed, enf.Allowed)
	}
}

// TestAZeroWindowUnderAnEnabledGateIsNotNoWindow. security.reauth_interval
// ships documented as "0 = disabled". If a zero window meant "no freshness
// required", an operator who turned STEPUP_GATE to enforce without touching
// that setting would get a gate that gates nothing — a control that displays
// without enforcing, which is the entire defect class this change exists to
// close. Turning the gate on is the request; the window only tunes it.
func TestAZeroWindowUnderAnEnabledGateIsNotNoWindow(t *testing.T) {
	d := Gate(context.Background(), nil, ModeEnforce, 0, Caller{UserID: "u1"})
	if d.MaxAge != DefaultMaxAge {
		t.Errorf("MaxAge = %v with a zero window, want the %v default", d.MaxAge, DefaultMaxAge)
	}
	if d.Allowed {
		t.Error("a zero window under enforce allowed a session that cannot prove a factor")
	}
}
