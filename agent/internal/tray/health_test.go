package tray

import (
	"strings"
	"testing"

	"github.com/openidx/openidx/agent/internal/ipc"
)

var bitlocker = ipc.PostureIssue{Check: "disk_encryption", Severity: "critical", Status: "fail",
	Message: "BitLocker is off on C:", Remediation: "Turn on BitLocker in Settings"}

func TestLaunchRefusal(t *testing.T) {
	if r := launchRefusal(nil); r != "" {
		t.Fatalf("no answer from the service is not a reason to refuse: %q", r)
	}
	if r := launchRefusal(&ipc.Status{Enrolled: true}); r != "" {
		t.Fatalf("no posture cycle yet is not a reason to refuse: %q", r)
	}
	if r := launchRefusal(&ipc.Status{ComplianceStatus: "at_risk",
		Issues: []ipc.PostureIssue{{Check: "firewall", Severity: "high", Status: "fail"}}}); r != "" {
		t.Fatalf("a high-severity failure warns but does not refuse: %q", r)
	}
	if r := launchRefusal(&ipc.Status{ComplianceStatus: "unknown",
		Issues: []ipc.PostureIssue{{Check: "disk_encryption", Severity: "critical", Status: "error"}}}); r != "" {
		t.Fatalf("a check that could not run is not the device failing it: %q", r)
	}
	r := launchRefusal(&ipc.Status{ComplianceStatus: "non_compliant", Issues: []ipc.PostureIssue{bitlocker}})
	if r == "" || !strings.Contains(r, "BitLocker is off on C:") {
		t.Fatalf("a critical failure refuses and names it: %q", r)
	}
	r = launchRefusal(&ipc.Status{ComplianceStatus: "compliant", EnforcementPolicy: "block"})
	if !strings.Contains(r, "suspended") {
		t.Fatalf("a suspended device refuses whatever its checks say: %q", r)
	}
}

func TestIssueTitleAndDetail(t *testing.T) {
	if got := issueTitle(bitlocker); got != "⛔ Disk encryption (critical)" {
		t.Fatalf("title: %q", got)
	}
	if got := issueTitle(ipc.PostureIssue{Check: "firewall", Severity: "high", Status: "fail"}); got != "⚠ Firewall (high)" {
		t.Fatalf("title: %q", got)
	}
	if got := issueTitle(ipc.PostureIssue{Check: "custom_check", Severity: "low", Status: "warn"}); got != "⚠ custom_check (low)" {
		t.Fatalf("an unknown check keeps its own name: %q", got)
	}
	d := issueDetail(bitlocker)
	if !strings.Contains(d, "BitLocker is off on C:") || !strings.Contains(d, "How to fix it:\nTurn on BitLocker in Settings") {
		t.Fatalf("detail: %q", d)
	}
	if d := issueDetail(ipc.PostureIssue{Check: "firewall", Status: "error"}); d != "Firewall: error" {
		t.Fatalf("detail without message or remediation: %q", d)
	}
}

func TestPostureNoteAndTransition(t *testing.T) {
	cases := map[string]*ipc.Status{
		"":               {ComplianceStatus: "compliant"},
		"NOT COMPLIANT":  {ComplianceStatus: "non_compliant", Issues: []ipc.PostureIssue{bitlocker}},
		"SUSPENDED":      {ComplianceStatus: "compliant", EnforcementPolicy: "block"},
		"1 health issue": {ComplianceStatus: "at_risk", Issues: []ipc.PostureIssue{{Check: "firewall"}}},
		"2 health issues": {ComplianceStatus: "unknown",
			Issues: []ipc.PostureIssue{{Check: "a"}, {Check: "b"}}},
	}
	for want, st := range cases {
		if got := postureNote(st); got != want {
			t.Fatalf("postureNote(%+v) = %q, want %q", st, got, want)
		}
	}
	ok := &ipc.Status{ComplianceStatus: "compliant"}
	bad := &ipc.Status{ComplianceStatus: "non_compliant", Issues: []ipc.PostureIssue{bitlocker}}
	if !becameBlocked(ok, bad) || !becameBlocked(nil, bad) {
		t.Fatal("entering a refusing state is announced")
	}
	if becameBlocked(bad, bad) || becameBlocked(bad, ok) || becameBlocked(ok, ok) {
		t.Fatal("only the transition into a refusing state is announced")
	}
}
