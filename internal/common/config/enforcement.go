package config

import (
	"fmt"
	"strings"
	"time"
)

// A PRODUCTION INSTALL ENFORCES ITS AUTHORIZATION CONTROLS, OR SAYS UNTIL WHEN IT WON'T.
//
// Every control that decides reach — application assignment, the posture →
// device-trust link, the fresh-second-factor gate, the bot gate, the on-overlay
// requirement for privileged sessions, and the two require-auth switches — has
// an off or observe mode so an operator can read what it would refuse before
// anyone loses access. Those modes were the defaults, and nothing distinguished
// a production install mid-rollout from one that had simply never been
// switched on: ReportModeGates logged a warning, and the warning was the whole
// security posture.
//
// ValidateProduction now refuses to start a production service while any of
// these controls is open, with one exception: ENFORCEMENT_OBSERVE_UNTIL names
// the day the rollout ends. Until that day the controls may observe and
// startup logs the days left; from that day startup refuses again. The window
// is capped at maxObserveWindow so "observe" cannot quietly become forever.

// maxObserveWindow bounds how far ahead ENFORCEMENT_OBSERVE_UNTIL may lie.
const maxObserveWindow = 30 * 24 * time.Hour

// observeUntilLayout is the date form ENFORCEMENT_OBSERVE_UNTIL takes.
const observeUntilLayout = "2006-01-02"

// productionRequiredGates are the controls a production install must enforce,
// as the variable names ReportModeGates reports them under.
var productionRequiredGates = []string{
	"ACCESS_ASSIGNMENT_ENFORCE",
	"STEPUP_GATE",
	"BOT_GATE",
	"POSTURE_DEVICE_TRUST_GATE",
	"PAM_REQUIRE_ZTNA",
	"ACCESS_API_REQUIRE_AUTH",
	"ADMIN_API_REQUIRE_AUTH",
}

// GateStatus is one authorization control as the console and the startup log
// show it: its variable name, its current mode, and the audit action its
// observe mode records so the console can count what it would have refused.
type GateStatus struct {
	Name      string `json:"name"`
	Mode      string `json:"mode"` // off | observe | enforce
	Enforcing bool   `json:"enforcing"`
	// Meaning is what an open control leaves undone, in the operator's words.
	Meaning string `json:"meaning"`
	// ObserveAction is the unified-audit action recorded instead of a refusal,
	// or "" for a control that has no observe mode (on/off only).
	ObserveAction string `json:"observe_action,omitempty"`
}

func boolMode(on bool) string {
	if on {
		return "enforce"
	}
	return "off"
}

func triMode(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "off"
	}
	return v
}

// ProductionGateStatuses describes every control production requires, in the
// order productionRequiredGates lists them. Meaning text comes from the same
// place ReportModeGates draws it, so the two never disagree.
func (c *Config) ProductionGateStatuses() []GateStatus {
	modes := map[string]string{
		"ACCESS_ASSIGNMENT_ENFORCE": boolMode(c.AccessAssignmentEnforce),
		"STEPUP_GATE":               triMode(c.StepUpGate),
		"BOT_GATE":                  triMode(c.BotGate),
		"POSTURE_DEVICE_TRUST_GATE": triMode(c.PostureDeviceTrustGate),
		"PAM_REQUIRE_ZTNA":          triMode(c.PAMRequireZTNA),
		"ACCESS_API_REQUIRE_AUTH":   boolMode(c.AccessAPIRequireAuth),
		"ADMIN_API_REQUIRE_AUTH":    boolMode(c.AdminAPIRequireAuth),
	}
	observeActions := map[string]string{
		"ACCESS_ASSIGNMENT_ENFORCE": "access.assignment.would_deny",
		"PAM_REQUIRE_ZTNA":          "pam.ztna.would_deny",
	}
	meanings := map[string]string{}
	for _, line := range c.ReportModeGates() {
		if name, rest, ok := strings.Cut(line, "="); ok {
			if _, meaning, ok := strings.Cut(rest, " — "); ok {
				meanings[name] = meaning
			}
		}
	}
	out := make([]GateStatus, 0, len(productionRequiredGates))
	for _, name := range productionRequiredGates {
		mode := modes[name]
		out = append(out, GateStatus{
			Name:          name,
			Mode:          mode,
			Enforcing:     mode == "enforce",
			Meaning:       meanings[name], // "" when enforcing: nothing is left undone
			ObserveAction: observeActions[name],
		})
	}
	return out
}

// OpenProductionGates returns the required controls that are not enforcing,
// each as the line ReportModeGates gives it.
func (c *Config) OpenProductionGates() []string {
	var open []string
	for _, line := range c.ReportModeGates() {
		for _, name := range productionRequiredGates {
			if strings.HasPrefix(line, name+"=") {
				open = append(open, line)
				break
			}
		}
	}
	return open
}

// ObserveWindow parses ENFORCEMENT_OBSERVE_UNTIL. set is false when it is not
// configured; err reports a value that is not a date or lies more than
// maxObserveWindow after now.
func (c *Config) ObserveWindow(now time.Time) (until time.Time, set bool, err error) {
	raw := strings.TrimSpace(c.EnforcementObserveUntil)
	if raw == "" {
		return time.Time{}, false, nil
	}
	until, err = time.ParseInLocation(observeUntilLayout, raw, time.UTC)
	if err != nil {
		return time.Time{}, true, fmt.Errorf("enforcement_observe_until %q is not a date of the form YYYY-MM-DD", raw)
	}
	// The window ends at the start of the named day, so "2026-10-16" means
	// "through the 15th".
	if until.Sub(now) > maxObserveWindow {
		return until, true, fmt.Errorf("enforcement_observe_until %s is more than %d days ahead; an observe window is a rollout, not a setting",
			raw, int(maxObserveWindow.Hours()/24))
	}
	return until, true, nil
}

// enforcementIssues is ValidateProduction's share: the critical issues a
// production install has because a required control is open outside a valid
// observe window.
func (c *Config) enforcementIssues(now time.Time) []string {
	open := c.OpenProductionGates()
	until, set, err := c.ObserveWindow(now)
	if err != nil {
		return []string{err.Error()}
	}
	if len(open) == 0 {
		return nil
	}
	if set && now.Before(until) {
		return nil // inside the declared window; logEnforcementWindow reports it
	}
	var issues []string
	for _, line := range open {
		issues = append(issues, line+" (production requires enforce)")
	}
	hint := "set each control above to enforce, or declare a rollout window with ENFORCEMENT_OBSERVE_UNTIL=YYYY-MM-DD (at most 30 days ahead) to observe until then"
	if set {
		hint = fmt.Sprintf("the observe window ended on %s: set each control above to enforce", until.Format(observeUntilLayout))
	}
	return append(issues, hint)
}

// EnforcementWindowStatus is one line for the startup log and the console:
// how many days of the observe window are left, or "" when none is declared.
func (c *Config) EnforcementWindowStatus(now time.Time) string {
	until, set, err := c.ObserveWindow(now)
	if !set || err != nil {
		return ""
	}
	left := int(until.Sub(now).Hours() / 24)
	if now.After(until) || now.Equal(until) {
		return fmt.Sprintf("observe window ended on %s", until.Format(observeUntilLayout))
	}
	return fmt.Sprintf("observe window until %s (%d day(s) left): controls in observe mode report what they would refuse",
		until.Format(observeUntilLayout), left)
}
