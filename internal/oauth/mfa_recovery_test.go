package oauth

import (
	"reflect"
	"testing"

	"github.com/openidx/openidx/internal/identity"
)

func TestFilterMethodsByRisk(t *testing.T) {
	anyPrimary := []string{"totp", "push", "webauthn", "sms", "email"}
	cases := []struct {
		name    string
		methods []string
		allowed []string
		want    []string
	}{
		{"medium risk keeps a user's backup codes and admin bypass code",
			[]string{"push", "totp", "email", "backup", "bypass"}, anyPrimary,
			[]string{"push", "totp", "email", "backup", "bypass"}},
		{"high risk drops TOTP and with it the backup codes, but not the bypass code",
			[]string{"push", "totp", "backup", "bypass"}, []string{"webauthn", "push"},
			[]string{"push", "bypass"}},
		{"critical risk still honours an administrator's bypass code",
			[]string{"webauthn", "backup", "bypass"}, []string{"webauthn"},
			[]string{"webauthn", "bypass"}},
		{"a filter that matches nothing leaves the list alone",
			[]string{"email", "backup"}, []string{"webauthn"},
			[]string{"email", "backup"}},
		{"backup codes alone never survive a filter that allows no primary",
			[]string{"sms", "backup"}, []string{"webauthn"},
			[]string{"sms", "backup"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := filterMethodsByRisk(tc.methods, tc.allowed); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("filterMethodsByRisk(%v, %v) = %v, want %v", tc.methods, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestEmailUndeliverable(t *testing.T) {
	cases := map[string]bool{
		"mehmet.gungor@test.local":  true,
		"a@host.localhost":          true,
		"a@example.test":            true,
		"a@example.com":             true,
		"a@sub.example.org":         true,
		"a@foo.invalid":             true,
		"a@openidx.local":           true,
		"":                          true,
		"not-an-address":            true,
		"mehmetgungor@gmail.com":    false,
		"user@corp.example-co.com":  false,
		"USER@COMPANY.COM.TR":       false,
		"someone@localmail.example": true,
	}
	for addr, want := range cases {
		if got := emailUndeliverable(addr); got != want {
			t.Errorf("emailUndeliverable(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestHasEnabledPushDevice(t *testing.T) {
	if hasEnabledPushDevice(nil) {
		t.Error("no devices: push offered")
	}
	if hasEnabledPushDevice([]identity.PushMFADevice{{Enabled: false}}) {
		t.Error("only a switched-off device: push offered")
	}
	if !hasEnabledPushDevice([]identity.PushMFADevice{{Enabled: false}, {Enabled: true}}) {
		t.Error("an enabled device: push not offered")
	}
}
