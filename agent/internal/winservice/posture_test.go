package winservice

import (
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/ipc"
)

func TestFillPosture(t *testing.T) {
	var before ipc.Status
	fillPosture(&before, nil)
	if before.ComplianceStatus != "" || before.Issues != nil || before.LastReportAt != "" {
		t.Fatalf("before the first cycle the status says nothing about posture, got %+v", before)
	}

	var st ipc.Status
	fillPosture(&st, &agent.PostureSummary{
		Compliance:        agent.ComplianceNonCompliant,
		EnforcementPolicy: "enforce",
		CheckedAt:         time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
		Issues: []agent.PostureIssue{{Check: "disk_encryption", Severity: "critical", Status: "fail",
			Message: "BitLocker is off on C:", Remediation: "Turn on BitLocker"}},
	})
	if st.ComplianceStatus != "non_compliant" || st.EnforcementPolicy != "enforce" ||
		st.LastReportAt != "2026-10-05T12:00:00Z" {
		t.Fatalf("posture not copied: %+v", st)
	}
	if len(st.Issues) != 1 || st.Issues[0].Remediation != "Turn on BitLocker" {
		t.Fatalf("issue not copied: %+v", st.Issues)
	}
}
