package tray

import (
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
		{"enrolled, signed out", false, true, &ipc.Status{Enrolled: true}, "Not signed in · device: enrolled"},
		{"enrolled with ziti, signed in", true, true, &ipc.Status{Enrolled: true, ZitiEnrolled: true}, "Signed in · device: enrolled · ziti"},
		{"revoked", true, true, &ipc.Status{Enrolled: true, Revoked: true}, "Signed in · device: REVOKED by an administrator"},
		{"server known, service not answering", true, true, nil, "Signed in · device: unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := composeStatus(tc.signedIn, tc.serverKnown, tc.st); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
