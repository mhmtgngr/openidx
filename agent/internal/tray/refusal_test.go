package tray

import (
	"errors"
	"fmt"
	"testing"

	"github.com/openidx/openidx/agent/internal/desktoppam"
)

func TestRefusalActionFor(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want refusalAction
	}{
		{"stale factor offers a fresh sign-in", fmt.Errorf("%w: x", desktoppam.ErrStepUpRequired), actionSignInFresh},
		{"unapproved entry offers a request", fmt.Errorf("%w: x", desktoppam.ErrApprovalRequired), actionRequestAccess},
		{"an expired session is only told (the refresh signs out)", desktoppam.ErrNotSignedIn, actionTell},
		{"any other refusal is told", &desktoppam.Refusal{Status: 403, Code: "ztna_required_direct_reach"}, actionTell},
		{"a network error is told", errors.New("dial tcp: refused"), actionTell},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := refusalActionFor(tc.err); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
