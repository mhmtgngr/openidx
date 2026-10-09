package config

import (
	"strings"
	"testing"
	"time"
)

// A production config that passes every other ValidateProduction check, with
// the authorization controls at their defaults (open). Each test then sets
// what it is about.
func productionWithOpenControls() *Config {
	c := &Config{Environment: "production"}
	c.AccessSessionSecret = "0123456789abcdef0123456789abcdef"
	c.EncryptionKey = "0123456789abcdef0123456789abcdef"
	c.VaultKEK = "0123456789abcdef0123456789abcdef"
	c.AuditChainSecret = "0123456789abcdef0123456789abcdef"
	c.CORSAllowedOrigins = "https://console.example.test"
	c.AuditStreamAllowedOrigins = "https://console.example.test"
	c.CSRFEnabled = true
	c.DatabaseSSLMode = "require"
	c.RedisTLSEnabled = true
	c.TLS = TLSConfig{Enabled: true}
	c.AgentEnrollmentQuotaPerHour = 100
	c.DatabaseBypassURL = "postgres://openidx_bypass@db:5432/openidx"
	return c
}

func enforceAll(c *Config) {
	c.AccessAssignmentEnforce = true
	c.StepUpGate = "enforce"
	c.BotGate = "enforce"
	c.PostureDeviceTrustGate = "enforce"
	c.PAMRequireZTNA = "enforce"
	c.GuacamoleZitiPublicURL = "https://guacamole.ziti" // enforce needs the overlay broker's own address
	c.AccessAPIRequireAuth = true
	c.AdminAPIRequireAuth = true
	c.DatabaseBypassURL = "postgres://openidx_bypass@db:5432/openidx"
}

func day(offset int) string {
	return time.Now().UTC().AddDate(0, 0, offset).Format(observeUntilLayout)
}

// TestProductionRefusesOpenControls: the default install, promoted to
// production, must not start. Every open control is named with the hint.
func TestProductionRefusesOpenControls(t *testing.T) {
	c := productionWithOpenControls()
	err := c.ValidateProduction()
	if err == nil {
		t.Fatal("a production install with every authorization control open started")
	}
	for _, want := range productionRequiredGates {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %s:\n%s", want, err)
		}
	}
	if !strings.Contains(err.Error(), "ENFORCEMENT_OBSERVE_UNTIL") {
		t.Errorf("refusal does not tell the operator about the observe window:\n%s", err)
	}
}

// TestProductionStartsWhenEveryControlEnforces is the other half: enforcing
// everything is enough, no window needed.
func TestProductionStartsWhenEveryControlEnforces(t *testing.T) {
	c := productionWithOpenControls()
	enforceAll(c)
	if err := c.ValidateProduction(); err != nil {
		t.Fatalf("a fully enforcing production install was refused: %v", err)
	}
	if got := c.OpenProductionGates(); len(got) != 0 {
		t.Errorf("OpenProductionGates on a fully enforcing install = %v", got)
	}
}

// TestObserveWindowAllowsOpenControlsUntilItsDay: a declared rollout window
// lets the controls observe, and the status line counts the days.
func TestObserveWindowAllowsOpenControlsUntilItsDay(t *testing.T) {
	c := productionWithOpenControls()
	c.EnforcementObserveUntil = day(7)
	if err := c.ValidateProduction(); err != nil {
		t.Fatalf("inside the observe window, startup was refused: %v", err)
	}
	status := c.EnforcementWindowStatus(time.Now())
	if !strings.Contains(status, "observe window until "+day(7)) {
		t.Errorf("status = %q, want the window's end", status)
	}
}

// TestObserveWindowEndsTheGrace: the day after, the same config is refused,
// and the refusal says the window ended rather than offering a new one.
func TestObserveWindowEndsTheGrace(t *testing.T) {
	c := productionWithOpenControls()
	c.EnforcementObserveUntil = day(-1)
	err := c.ValidateProduction()
	if err == nil {
		t.Fatal("an ended observe window still let open controls start")
	}
	if !strings.Contains(err.Error(), "observe window ended on "+day(-1)) {
		t.Errorf("refusal does not say the window ended:\n%s", err)
	}
}

// TestObserveWindowIsBounded: a window far ahead is a setting, not a rollout.
func TestObserveWindowIsBounded(t *testing.T) {
	c := productionWithOpenControls()
	c.EnforcementObserveUntil = day(60)
	err := c.ValidateProduction()
	if err == nil || !strings.Contains(err.Error(), "more than 30 days ahead") {
		t.Fatalf("a 60-day observe window was accepted: %v", err)
	}
	c.EnforcementObserveUntil = "next week"
	err = c.ValidateProduction()
	if err == nil || !strings.Contains(err.Error(), "not a date") {
		t.Fatalf("a non-date observe window was accepted: %v", err)
	}
}

// TestProductionGateStatusesMatchReportModeGates: the structured view the
// console reads and the startup log's lines must name the same open controls
// with the same meaning, or the two will drift and one of them will lie.
func TestProductionGateStatusesMatchReportModeGates(t *testing.T) {
	c := productionWithOpenControls()
	c.StepUpGate = "observe"
	c.AdminAPIRequireAuth = true
	statuses := c.ProductionGateStatuses()
	if len(statuses) != len(productionRequiredGates) {
		t.Fatalf("got %d statuses, want %d", len(statuses), len(productionRequiredGates))
	}
	byName := map[string]GateStatus{}
	for _, s := range statuses {
		byName[s.Name] = s
	}
	if g := byName["STEPUP_GATE"]; g.Mode != "observe" || g.Enforcing || g.Meaning == "" {
		t.Errorf("STEPUP_GATE in observe = %+v", g)
	}
	if g := byName["ADMIN_API_REQUIRE_AUTH"]; g.Mode != "enforce" || !g.Enforcing || g.Meaning != "" {
		t.Errorf("an enforcing control still carries a meaning: %+v", g)
	}
	if g := byName["ACCESS_ASSIGNMENT_ENFORCE"]; g.ObserveAction != "access.assignment.would_deny" {
		t.Errorf("assignment observe action = %q", g.ObserveAction)
	}
	open := c.OpenProductionGates()
	var notEnforcing int
	for _, s := range statuses {
		if !s.Enforcing {
			notEnforcing++
		}
	}
	if notEnforcing != len(open) {
		t.Errorf("%d statuses not enforcing but OpenProductionGates lists %d", notEnforcing, len(open))
	}
}

// TestObserveWindowIsIgnoredOutsideProduction: development keeps its defaults
// and never refuses; the window is a production concept.
func TestObserveWindowIsIgnoredOutsideProduction(t *testing.T) {
	c := &Config{Environment: "development", EnforcementObserveUntil: "garbage"}
	if err := c.ValidateProduction(); err != nil {
		t.Fatalf("development refused to start over the observe window: %v", err)
	}
}
