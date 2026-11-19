package tray

import (
	"strings"
	"testing"

	"github.com/openidx/openidx/agent/internal/ipc"
)

func TestComposeStatus(t *testing.T) {
	cases := []struct {
		name        string
		signedIn    bool
		serverKnown bool
		st          *ipc.Status
		want        string
	}{
		{"fresh install, no service answer", false, false, nil, "Not enrolled · open your enrollment link"},
		{"service says not enrolled", false, true, &ipc.Status{Enrolled: false}, "Not enrolled · open your enrollment link"},
		{"enrolled, signed out", false, true, &ipc.Status{Enrolled: true}, "device: enrolled · not signed in (only My Connections needs it)"},
		{"enrolled with ziti, signed in", true, true, &ipc.Status{Enrolled: true, ZitiEnrolled: true}, "device: enrolled · ziti · Signed in"},
		{"revoked", true, true, &ipc.Status{Enrolled: true, Revoked: true}, "device: REVOKED by an administrator · Signed in"},
		{"credential refused", false, true, &ipc.Status{Enrolled: true, AuthInvalid: true}, "device: NOT ACCEPTED · enroll it again · not signed in (only My Connections needs it)"},
		{"revoked wins over a refused credential", true, true, &ipc.Status{Enrolled: true, Revoked: true, AuthInvalid: true}, "device: REVOKED by an administrator · Signed in"},
		{"server known, service not answering", true, true, nil, "device: unknown · Signed in"},
		{"enrolled, a critical check fails", true, true, &ipc.Status{Enrolled: true, ComplianceStatus: "non_compliant",
			Issues: []ipc.PostureIssue{{Check: "disk_encryption", Severity: "critical", Status: "fail"}}},
			"device: enrolled · NOT COMPLIANT · Signed in"},
		{"enrolled, suspended", true, true, &ipc.Status{Enrolled: true, EnforcementPolicy: "block"},
			"device: enrolled · SUSPENDED · Signed in"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := composeStatus(tc.signedIn, tc.serverKnown, tc.st); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The device and the person are two independent facts. A device with nobody
// signed in works (the tunnel runs under the device's own identity), so the
// line leads with the device and says "not signed in" as information, in both
// languages, never as the headline.
func TestComposeStatusLeadsWithTheDeviceAndSaysSignedOutAsInformation(t *testing.T) {
	enrolled := &ipc.Status{Enrolled: true, ZitiEnrolled: true}
	for _, tab := range []*strs{&enStrings, &trStrings} {
		old := T
		T = tab
		out := composeStatus(false, true, enrolled)
		T = old
		if !strings.HasPrefix(out, tab.DevEnrolled) {
			t.Errorf("%s: %q does not lead with the device", tab.Lang, out)
		}
		if !strings.HasSuffix(out, tab.SignedOutNote) {
			t.Errorf("%s: %q does not end with the signed-out note", tab.Lang, out)
		}
		if strings.HasPrefix(out, tab.NotSignedIn) {
			t.Errorf("%s: %q leads with 'not signed in' as if it were the fault", tab.Lang, out)
		}
	}
	if enStrings.SignedOutNote == trStrings.SignedOutNote || enStrings.DevEnrolled == trStrings.DevEnrolled {
		t.Error("the device and person parts are not translated")
	}
}
