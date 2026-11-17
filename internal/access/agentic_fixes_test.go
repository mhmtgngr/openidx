package access

import (
	"testing"

	"github.com/openidx/openidx/internal/diagnose"
)

func TestDecideFix(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mode         agenticMode
		killed       bool
		action       string
		applied      int
		outcome, why string
	}{
		{"off does nothing", modeOff, false, diagnose.FixRestartTunnel, 0, "", ""},
		{"observe records", modeObserve, false, diagnose.FixRestartTunnel, 0, "observed", "observe_mode"},
		{"tier0 restarts", modeTier0, false, diagnose.FixRestartTunnel, 0, "applied", ""},
		{"tier0 collects logs", modeTier0, false, diagnose.FixCollectLogs, 1, "applied", ""},
		{"tier0 does not update", modeTier0, false, diagnose.FixUpdateAgent, 0, "observed", "mode_below_fix"},
		{"tier1 updates", modeTier1, false, diagnose.FixUpdateAgent, 0, "applied", ""},
		{"a fix that did not work twice is held", modeTier1, false, diagnose.FixRestartTunnel, maxAutoFixesPerDay, "suppressed", "anti_flap"},
		{"the kill switch beats the mode", modeTier1, true, diagnose.FixRestartTunnel, 0, "suppressed", "kill_switch"},
		{"re-enrolment is never automatic", modeTier1, false, diagnose.FixReenroll, 0, "", ""},
		{"a user's own fix is not the platform's", modeTier1, false, diagnose.FixSetClock, 0, "", ""},
	} {
		outcome, why := decideFix(tc.mode, tc.killed, tc.action, tc.applied)
		if outcome != tc.outcome || why != tc.why {
			t.Errorf("%s: got %q/%q, want %q/%q", tc.name, outcome, why, tc.outcome, tc.why)
		}
	}
}

func TestEveryAutoFixIsASafeFixOfSomeCause(t *testing.T) {
	// An auto fix the rule engine never offers as safe would be dead code, and
	// one it offers at a higher tier would be a way round the approval.
	offered := map[string]diagnose.Tier{}
	for _, code := range diagnose.AllCauses() {
		for _, f := range diagnose.FixesFor(code) {
			offered[f.Action] = f.Tier
		}
	}
	for action := range autoFixes {
		if offered[action] != diagnose.TierSafeFix {
			t.Errorf("%s is automatic but the rule engine offers it as %q", action, offered[action])
		}
	}
}

func TestAgenticModeCap(t *testing.T) {
	for _, tc := range []struct {
		org      agenticMode
		cap, out string
	}{
		{modeTier1, "", "tier1"},
		{modeTier1, "observe", "observe"},
		{modeObserve, "tier1", "observe"},
		{modeTier0, "off", "off"},
		{modeTier0, "nonsense", "tier0"},
	} {
		if got := tc.org.cappedBy(tc.cap); string(got) != tc.out {
			t.Errorf("%s capped by %q = %s, want %s", tc.org, tc.cap, got, tc.out)
		}
	}
}
