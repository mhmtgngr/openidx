package winservice

import (
	"time"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/ipc"
)

// fillPosture copies the agent's latest posture cycle into the status the
// tray reads. Before the first cycle there is nothing to copy, and the tray
// says nothing about posture rather than something it does not know.
func fillPosture(st *ipc.Status, p *agent.PostureSummary) {
	if p == nil {
		return
	}
	st.ComplianceStatus = p.Compliance
	st.EnforcementPolicy = p.EnforcementPolicy
	if !p.CheckedAt.IsZero() {
		st.LastReportAt = p.CheckedAt.UTC().Format(time.RFC3339)
	}
	for _, i := range p.Issues {
		st.Issues = append(st.Issues, ipc.PostureIssue{
			Check:       i.Check,
			Severity:    i.Severity,
			Status:      i.Status,
			Message:     i.Message,
			Remediation: i.Remediation,
		})
	}
}
