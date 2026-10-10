package oauth

import (
	"reflect"
	"testing"
	"time"

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

func TestPushOfferable(t *testing.T) {
	now := time.Now()
	window := 30 * 24 * time.Hour
	if identity.AssessPushLiveness(nil, now, window).Offerable() {
		t.Error("no devices: push offered")
	}
	if identity.AssessPushLiveness([]identity.PushMFADevice{{Enabled: false, CreatedAt: now}}, now, window).Offerable() {
		t.Error("only a switched-off device: push offered")
	}
	if !identity.AssessPushLiveness([]identity.PushMFADevice{{Enabled: false}, {Enabled: true, CreatedAt: now}}, now, window).Offerable() {
		t.Error("an enabled device: push not offered")
	}
}

// The admin lockout: push was the only factor, to a phone that no longer
// existed, and the login offered push and nothing else.
func TestPushUnseenFallbacks(t *testing.T) {
	now := time.Now()
	window := 30 * 24 * time.Hour
	old := now.Add(-45 * 24 * time.Hour)
	recent := now.Add(-2 * 24 * time.Hour)
	stalePhone := identity.PushMFADevice{Enabled: true, CreatedAt: old, LastSeenAt: &old}
	freshPhone := identity.PushMFADevice{Enabled: true, CreatedAt: old, LastSeenAt: &recent}
	swept := identity.PushMFADevice{Enabled: false, CreatedAt: old, LastSeenAt: &old, DisabledAt: &now, DisabledReason: identity.PushDisabledStale}

	cases := []struct {
		name       string
		methods    []string
		devices    []identity.PushMFADevice
		want       []string
		wantNotice bool
		disabled   bool
	}{
		{"a phone seen recently changes nothing",
			[]string{"push", "backup"}, []identity.PushMFADevice{freshPhone},
			[]string{"push", "backup"}, false, false},
		{"one fresh phone among stale ones changes nothing",
			[]string{"push"}, []identity.PushMFADevice{stalePhone, freshPhone},
			[]string{"push"}, false, false},
		{"push-only, phone unseen: the bypass code is offered first and push last",
			[]string{"push"}, []identity.PushMFADevice{stalePhone},
			[]string{"bypass", "push"}, true, false},
		{"push-only, phone unseen, backup codes held: backup and bypass before push",
			[]string{"push", "backup"}, []identity.PushMFADevice{stalePhone},
			[]string{"backup", "bypass", "push"}, true, false},
		{"an issued bypass code is not offered twice",
			[]string{"push", "backup", "bypass"}, []identity.PushMFADevice{stalePhone},
			[]string{"backup", "bypass", "push"}, true, false},
		{"another factor the user has: push only moves last, no notice",
			[]string{"push", "totp", "backup"}, []identity.PushMFADevice{stalePhone},
			[]string{"totp", "backup", "push"}, false, false},
		{"every phone disabled by the sweep: still challenged, with the fallbacks",
			nil, []identity.PushMFADevice{swept},
			[]string{"bypass"}, true, true},
		{"a disabled phone beside another factor: nothing to add",
			[]string{"email"}, []identity.PushMFADevice{swept},
			[]string{"email"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			live := identity.AssessPushLiveness(tc.devices, now, window)
			got, notice := pushUnseenFallbacks(tc.methods, live, window)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("methods = %v, want %v", got, tc.want)
			}
			if (notice != nil) != tc.wantNotice {
				t.Fatalf("notice = %+v, want present=%v", notice, tc.wantNotice)
			}
			if notice == nil {
				return
			}
			if notice.Disabled != tc.disabled {
				t.Errorf("notice.Disabled = %v, want %v", notice.Disabled, tc.disabled)
			}
			if notice.StaleDays != 30 {
				t.Errorf("notice.StaleDays = %d, want 30", notice.StaleDays)
			}
			if notice.LastSeenAt == nil || !notice.LastSeenAt.Equal(old) {
				t.Errorf("notice.LastSeenAt = %v, want %v", notice.LastSeenAt, old)
			}
			for _, f := range notice.Fallbacks {
				if f == "push" {
					t.Errorf("push listed as its own fallback: %v", notice.Fallbacks)
				}
			}
		})
	}
}
