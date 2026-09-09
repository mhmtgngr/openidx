package config

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// ReportModeGates spent its whole life with no caller: the function was right,
// its own test proved it named every open control, and no running process ever
// asked it. TestReportModeGatesNamesEveryOpenControl could not notice, because a
// test that calls the function IS a caller — the list looked read.
//
// These tests are about the reader rather than the list. They go through
// ValidateProductionConfig, which is what every cmd/*/main.go calls, so removing
// the call reddens them. That is the only thing standing between this list and
// the state it was in.

func observed() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)
	return zap.New(core), logs
}

func gateLines(logs *observer.ObservedLogs) []string {
	var out []string
	for _, e := range logs.All() {
		for _, f := range e.Context {
			if f.Key == "gate" {
				out = append(out, f.String)
			}
		}
	}
	return out
}

// TestStartupReportsEveryOpenGate: the list reaches a reader at all.
func TestStartupReportsEveryOpenGate(t *testing.T) {
	log, logs := observed()
	// Environment left at development on purpose: the case that matters most is
	// the one where a report-mode default is EXPECTED, because that is where
	// someone writes a deny policy, watches it permit, and has nothing to read.
	cfg := &Config{}
	if err := ValidateProductionConfig(cfg, log); err != nil {
		t.Fatalf("ValidateProductionConfig on a development config: %v", err)
	}

	reported := strings.Join(gateLines(logs), "\n")
	for _, want := range []string{
		"ACCESS_ASSIGNMENT_ENFORCE",
		"ABAC_ENFORCE",
		"STEPUP_GATE",
		"ENABLE_OPA_AUTHZ",
		"PAM_SESSION_RISK_GATE",
		"POSTURE_DEVICE_TRUST_GATE",
		"ACCESS_API_REQUIRE_AUTH",
		"ADMIN_API_REQUIRE_AUTH",
	} {
		if !strings.Contains(reported, want) {
			t.Errorf("service startup never mentions %s.\nreported:\n%s", want, reported)
		}
	}
}

// TestStartupReportsTheCountEvenWhenFullyEnforcing. The per-gate lines are what
// a person reads; the count is what a log query alerts on, and it has to be
// emitted at zero too or "fully enforcing" is indistinguishable from "this build
// stopped reporting".
func TestStartupReportsTheCountEvenWhenFullyEnforcing(t *testing.T) {
	log, logs := observed()
	cfg := &Config{
		AccessAssignmentEnforce: true,
		ABACEnforce:             "enforce",
		StepUpGate:              "enforce",
		EnableOPAAuthz:          true,
		PAMSessionRiskGate:      "enforce",
		PostureDeviceTrustGate:  "enforce",
		AccessAPIRequireAuth:    true,
		AdminAPIRequireAuth:     true,
	}
	if err := ValidateProductionConfig(cfg, log); err != nil {
		t.Fatalf("ValidateProductionConfig: %v", err)
	}

	if got := gateLines(logs); len(got) != 0 {
		t.Errorf("a fully-enforcing install still reports open gates: %v", got)
	}

	summaries := logs.FilterMessage("AUTHZ: report-mode summary").All()
	if len(summaries) != 1 {
		t.Fatalf("want exactly one summary line, got %d", len(summaries))
	}
	fields := summaries[0].ContextMap()
	if fields["open_gates"] != int64(0) {
		t.Errorf("open_gates = %v, want 0", fields["open_gates"])
	}
	if fields["fully_enforcing"] != true {
		t.Errorf("fully_enforcing = %v, want true", fields["fully_enforcing"])
	}
}

// TestProductionRaisesTheLevel. In development every gate is open by design, so
// warning there teaches people to skip the line — which is how a control ends up
// displayed and unread. In production the same fact needs to be hard to walk
// past.
func TestProductionRaisesTheLevel(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want zapcore.Level
	}{
		{"development", zapcore.InfoLevel},
		{"staging", zapcore.InfoLevel},
		{"production", zapcore.WarnLevel},
	} {
		t.Run(tc.env, func(t *testing.T) {
			log, logs := observed()
			// Only the gate reporting is under test here, so the config is
			// otherwise whatever it needs to be; a production config that fails
			// validation still has to have reported its gates FIRST, which is
			// the ordering this asserts by not caring about the error.
			cfg := &Config{Environment: tc.env}
			_ = ValidateProductionConfig(cfg, log)

			entries := logs.FilterMessage("AUTHZ: control not enforcing").All()
			if len(entries) == 0 {
				t.Fatal("no gate lines at all")
			}
			for _, e := range entries {
				if e.Level != tc.want {
					t.Errorf("gate %q logged at %s, want %s",
						e.ContextMap()["gate"], e.Level, tc.want)
				}
			}
		})
	}
}

// TestGatesAreReportedBeforeValidationCanAbort. A production config with a
// missing secret returns an error from ValidateProductionConfig, and an operator
// fixing that error is exactly the operator who needs to know which controls are
// open. Reporting after the error return would hide the list from the person
// most likely to act on it.
func TestGatesAreReportedBeforeValidationCanAbort(t *testing.T) {
	log, logs := observed()
	// Environment production with nothing else set: ValidateProduction refuses.
	cfg := &Config{Environment: "production"}
	if err := ValidateProductionConfig(cfg, log); err == nil {
		t.Fatal("an empty production config passed validation; this test needs one that fails")
	}
	if got := gateLines(logs); len(got) == 0 {
		t.Error("validation aborted without ever reporting the open gates")
	}
}
