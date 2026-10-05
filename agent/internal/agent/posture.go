package agent

import (
	"time"

	"github.com/openidx/openidx/agent/internal/checks"
)

// The device's own reading of its posture, kept by the agent after each
// cycle so the person at the device can be told what is wrong and how to fix
// it. The server computes its own verdict from the same report; this one
// exists because nothing on the device used to look at the results at all:
// they were reported and forgotten, and a machine failing a critical check
// carried on as if nothing were wrong until an administrator noticed.

// Compliance values of a PostureSummary.
const (
	// ComplianceNonCompliant: a critical check failed. Privileged launches
	// from the tray are refused until it passes.
	ComplianceNonCompliant = "non_compliant"
	// ComplianceAtRisk: a high-severity check failed.
	ComplianceAtRisk = "at_risk"
	// ComplianceCompliant: something was examined and nothing failed.
	ComplianceCompliant = "compliant"
	// ComplianceUnknown: nothing could be examined, or only checks that
	// errored or are not implemented here ran.
	ComplianceUnknown = "unknown"
)

// PostureIssue is one check that did not pass, as the person is told it.
type PostureIssue struct {
	Check       string `json:"check"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// PostureSummary is the outcome of one posture cycle.
type PostureSummary struct {
	Compliance string         `json:"compliance"`
	Issues     []PostureIssue `json:"issues,omitempty"`
	// EnforcementPolicy is what the server's config said ("enforce",
	// "block" for a suspended device, or empty from an older server).
	EnforcementPolicy string    `json:"enforcement_policy,omitempty"`
	CheckedAt         time.Time `json:"checked_at"`
}

// summarizePosture reads one cycle's results. Only a check that ran and
// FAILED counts against the device: an error or an unsupported check is not a
// fact about the device, so it is listed (the person may want to know) but
// does not make the device non-compliant, which would block launches for a
// reason that is not theirs to fix. Equally, a cycle that examined nothing is
// not called compliant.
func summarizePosture(results []checks.EngineResult, policy string, at time.Time) PostureSummary {
	out := PostureSummary{EnforcementPolicy: policy, CheckedAt: at}
	var passed, criticalFail, highFail int
	for _, r := range results {
		if r.Result == nil {
			continue
		}
		res := r.Result
		switch {
		case res.Status == checks.StatusPass && !res.Unsupported:
			passed++
			continue
		case res.Unsupported:
			continue
		case res.Status == checks.StatusFail:
			switch r.Severity {
			case "critical":
				criticalFail++
			case "high":
				highFail++
			}
		}
		out.Issues = append(out.Issues, PostureIssue{
			Check:       r.CheckType,
			Severity:    r.Severity,
			Status:      string(res.Status),
			Message:     res.Message,
			Remediation: res.Remediation,
		})
	}
	switch {
	case criticalFail > 0:
		out.Compliance = ComplianceNonCompliant
	case highFail > 0:
		out.Compliance = ComplianceAtRisk
	case passed > 0 && len(out.Issues) == 0:
		out.Compliance = ComplianceCompliant
	default:
		out.Compliance = ComplianceUnknown
	}
	return out
}
