package oauth

import (
	"reflect"
	"testing"

	"github.com/openidx/openidx/internal/identity"
)

func TestHasEnrolledPushApprover(t *testing.T) {
	cases := []struct {
		name    string
		devices []identity.PushMFADevice
		want    bool
	}{
		{"none", nil, false},
		{"self-enrolled only (no agent link)",
			[]identity.PushMFADevice{{Enabled: true, AgentID: ""}}, false},
		{"enrolled-linked + enabled",
			[]identity.PushMFADevice{{Enabled: true, AgentID: "agent-1"}}, true},
		{"enrolled-linked but disabled",
			[]identity.PushMFADevice{{Enabled: false, AgentID: "agent-1"}}, false},
		{"mixed — one linked enabled",
			[]identity.PushMFADevice{
				{Enabled: true, AgentID: ""},
				{Enabled: true, AgentID: "agent-2"},
			}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasEnrolledPushApprover(tc.devices); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPreferMethod(t *testing.T) {
	cases := []struct {
		name    string
		methods []string
		want    string
		expect  []string
	}{
		{"promote push from middle",
			[]string{"totp", "webauthn", "push", "sms"}, "push",
			[]string{"push", "totp", "webauthn", "sms"}},
		{"already first is unchanged",
			[]string{"push", "totp"}, "push", []string{"push", "totp"}},
		{"absent is unchanged",
			[]string{"totp", "sms"}, "push", []string{"totp", "sms"}},
		{"single element",
			[]string{"push"}, "push", []string{"push"}},
		{"empty", nil, "push", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := preferMethod(tc.methods, tc.want)
			if !reflect.DeepEqual(got, tc.expect) {
				t.Fatalf("got %v, want %v", got, tc.expect)
			}
		})
	}
}
