package agent

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openidx/openidx/agent/internal/checks"
)

func res(check, severity string, status checks.Status, unsupported bool) checks.EngineResult {
	return checks.EngineResult{CheckType: check, Severity: severity, Result: &checks.CheckResult{
		Status: status, Unsupported: unsupported, Message: check + " says " + string(status),
		Remediation: "fix " + check,
	}}
}

func TestSummarizePosture(t *testing.T) {
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		results []checks.EngineResult
		want    string
		issues  int
	}{
		{"a critical failure", []checks.EngineResult{
			res("disk_encryption", "critical", checks.StatusFail, false),
			res("firewall", "high", checks.StatusPass, false)}, ComplianceNonCompliant, 1},
		{"a high failure", []checks.EngineResult{
			res("firewall", "high", checks.StatusFail, false),
			res("os_version", "low", checks.StatusPass, false)}, ComplianceAtRisk, 1},
		{"everything passes", []checks.EngineResult{
			res("firewall", "high", checks.StatusPass, false)}, ComplianceCompliant, 0},
		// An error is not a fact about the device: listed, never blocking.
		{"a critical check errored", []checks.EngineResult{
			res("disk_encryption", "critical", checks.StatusError, false),
			res("firewall", "high", checks.StatusPass, false)}, ComplianceUnknown, 1},
		// Nothing examined is not compliant either.
		{"only unsupported checks", []checks.EngineResult{
			res("screen_lock", "medium", checks.StatusWarn, true)}, ComplianceUnknown, 0},
		{"no checks at all", nil, ComplianceUnknown, 0},
		{"a medium failure", []checks.EngineResult{
			res("process_running", "medium", checks.StatusFail, false),
			res("firewall", "high", checks.StatusPass, false)}, ComplianceUnknown, 1},
	}
	for _, tc := range cases {
		got := summarizePosture(tc.results, "enforce", at)
		assert.Equal(t, tc.want, got.Compliance, tc.name)
		assert.Len(t, got.Issues, tc.issues, tc.name)
		assert.Equal(t, "enforce", got.EnforcementPolicy, tc.name)
		assert.Equal(t, at, got.CheckedAt, tc.name)
	}
	one := summarizePosture([]checks.EngineResult{res("disk_encryption", "critical", checks.StatusFail, false)}, "", at)
	assert.Equal(t, PostureIssue{Check: "disk_encryption", Severity: "critical", Status: "fail",
		Message: "disk_encryption says fail", Remediation: "fix disk_encryption"}, one.Issues[0])
}
