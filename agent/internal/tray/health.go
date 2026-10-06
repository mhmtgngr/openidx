package tray

import (
	"fmt"
	"strings"

	"github.com/openidx/openidx/agent/internal/ipc"
)

// Local posture enforcement in the tray. The server is the authority on
// what a device may reach; the tray adds what only the device can do: tell
// the person at it which check fails and how to fix it, and refuse to start
// a privileged connection from a device that fails a critical check, instead
// of letting them find out from a refusal (or worse, from nothing).
//
// The refusal is local, so it is not a security boundary on its own: the
// same person can open the console in a browser. It is the device saying
// "not from here, not like this", and it holds for the native launches the
// tray is the only way to start.

// maxHealthSlots bounds the Device health submenu.
const maxHealthSlots = 10

// launchRefusal is why the tray will not start a privileged connection from
// this device right now, or "" when it may. Nothing is refused while the
// service has not answered or has not completed a posture cycle: a refusal
// needs a fact, not the absence of one.
func launchRefusal(st *ipc.Status) string {
	if st == nil {
		return ""
	}
	if st.EnforcementPolicy == "block" {
		return "An administrator has suspended this device, so privileged connections " +
			"cannot be started from it.\n\nContact your administrator."
	}
	if st.ComplianceStatus != "non_compliant" {
		return ""
	}
	var lines []string
	for _, i := range st.Issues {
		if i.Severity == "critical" && i.Status == "fail" {
			lines = append(lines, "• "+issueSummary(i))
		}
	}
	msg := "This device fails a critical security check, so privileged connections " +
		"cannot be started from it until it is fixed."
	if len(lines) > 0 {
		msg += "\n\n" + strings.Join(lines, "\n")
	}
	return msg + "\n\nDevice health in the OpenIDX menu lists what to do."
}

// issueTitle is an issue's line in the Device health submenu.
func issueTitle(i ipc.PostureIssue) string {
	mark := "⚠"
	if i.Severity == "critical" && i.Status == "fail" {
		mark = "⛔"
	}
	return fmt.Sprintf("%s %s (%s)", mark, checkLabel(i.Check), i.Severity)
}

// issueDetail is what clicking an issue shows.
func issueDetail(i ipc.PostureIssue) string {
	msg := issueSummary(i)
	if i.Remediation != "" {
		msg += "\n\nHow to fix it:\n" + i.Remediation
	}
	return msg
}

func issueSummary(i ipc.PostureIssue) string {
	if i.Message == "" {
		return checkLabel(i.Check) + ": " + i.Status
	}
	return checkLabel(i.Check) + ": " + i.Message
}

// checkLabel is a check's name as a person reads it.
func checkLabel(check string) string {
	switch check {
	case "disk_encryption":
		return "Disk encryption"
	case "firewall":
		return "Firewall"
	case "antivirus":
		return "Antivirus"
	case "os_version":
		return "Windows version"
	case "patch_level":
		return "Windows updates"
	case "screen_lock":
		return "Screen lock"
	case "domain_joined":
		return "Domain membership"
	case "process_running":
		return "Required software"
	case "integrity":
		return "Agent integrity"
	case "agent_version":
		return "OpenIDX agent version"
	}
	return check
}

// postureNote is the status line's posture part, or "".
func postureNote(st *ipc.Status) string {
	switch {
	case st == nil:
		return ""
	case st.EnforcementPolicy == "block":
		return "SUSPENDED"
	case st.ComplianceStatus == "non_compliant":
		return "NOT COMPLIANT"
	case len(st.Issues) == 1:
		return "1 health issue"
	case len(st.Issues) > 1:
		return fmt.Sprintf("%d health issues", len(st.Issues))
	}
	return ""
}

// becameBlocked reports a transition into a state that refuses launches, so
// the person is told once when it happens rather than on every status tick.
func becameBlocked(prev, cur *ipc.Status) bool {
	return launchRefusal(cur) != "" && launchRefusal(prev) == ""
}
