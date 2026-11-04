package tray

import (
	"testing"

	"github.com/openidx/openidx/agent/internal/ipc"
)

func TestAddDeviceURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://idp.example.com":     "https://idp.example.com/add-device",
		"https://idp.example.com///":  "https://idp.example.com/add-device",
		"  https://idp.example.com/ ": "https://idp.example.com/add-device",
		"":                            "",
	} {
		if got := addDeviceURL(in); got != want {
			t.Errorf("addDeviceURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTheReEnrolmentPromptIsSaidOnce: the person is told when the device
// enters the state, not on every status tick, and a revoked device is never
// offered a re-enrolment (that is the administrator's to undo).
func TestTheReEnrolmentPromptIsSaidOnce(t *testing.T) {
	ok := &ipc.Status{Enrolled: true}
	bad := &ipc.Status{Enrolled: true, AuthInvalid: true}
	revoked := &ipc.Status{Enrolled: true, AuthInvalid: true, Revoked: true}

	cases := []struct {
		name      string
		prev, cur *ipc.Status
		want      bool
	}{
		{"healthy to refused", ok, bad, true},
		{"service first answers refused", nil, bad, true},
		{"still refused", bad, bad, false},
		{"refused to healthy", bad, ok, false},
		{"revoked is not a re-enrolment", ok, revoked, false},
		{"no answer", ok, nil, false},
	}
	for _, tc := range cases {
		if got := becameAuthInvalid(tc.prev, tc.cur); got != tc.want {
			t.Errorf("%s: becameAuthInvalid = %v, want %v", tc.name, got, tc.want)
		}
	}
}
