package identity

import (
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/sms"
)

// The settings an administrator edits under Settings → SMS reached nothing:
// createOTPChallenge called DefaultOTPConfig() and no other OTPConfig was ever
// constructed. Three numbers on a live admin page were stored, validated,
// clamped and read back, and every code the product sent was six digits valid
// for five minutes regardless.
//
// These pin the path from a stored settings row to the values a challenge is
// minted with.

func TestOTPConfigIsTheDefaultUntilAnAdministratorSaysOtherwise(t *testing.T) {
	s := &Service{}
	got := s.otpConfig()
	if want := DefaultOTPConfig(); got != want {
		t.Fatalf("otpConfig() = %+v, want the defaults %+v", got, want)
	}
}

func TestSetOTPSettingsReachesTheChallengeValues(t *testing.T) {
	s := &Service{}
	s.SetOTPSettings(8, 60, 5)

	got := s.otpConfig()
	if got.CodeLength != 8 {
		t.Errorf("CodeLength = %d, want 8: an administrator asked for eight-digit codes", got.CodeLength)
	}
	if got.ExpirationTime != 60*time.Second {
		t.Errorf("ExpirationTime = %v, want 1m: an administrator asked for a one-minute code", got.ExpirationTime)
	}
	if got.MaxAttempts != 5 {
		t.Errorf("MaxAttempts = %d, want 5", got.MaxAttempts)
	}
}

// The rate limiter is not an administrator's to widen. A settings row carries
// three numbers; the window and the per-hour ceiling are not among them and must
// stay where the product put them.
func TestSetOTPSettingsLeavesTheRateLimitAlone(t *testing.T) {
	s := &Service{}
	s.SetOTPSettings(8, 60, 5)

	def := DefaultOTPConfig()
	got := s.otpConfig()
	if got.RateLimitWindow != def.RateLimitWindow {
		t.Errorf("RateLimitWindow = %v, want %v", got.RateLimitWindow, def.RateLimitWindow)
	}
	if got.MaxCodesPerHour != def.MaxCodesPerHour {
		t.Errorf("MaxCodesPerHour = %d, want %d", got.MaxCodesPerHour, def.MaxCodesPerHour)
	}
}

// A row written before ValidateOTPSettings existed, or by anything that did not
// go through the admin API, can hold zeros. Zero-length codes are not a setting.
func TestSetOTPSettingsIgnoresUnsetValues(t *testing.T) {
	s := &Service{}
	s.SetOTPSettings(0, 0, 0)
	if got, want := s.otpConfig(), DefaultOTPConfig(); got != want {
		t.Fatalf("otpConfig() = %+v, want the defaults %+v", got, want)
	}
}

// The whole path the watcher takes, minus the database read: a stored row is
// clamped and applied. The clamp is the console's, so the two cannot disagree
// about what an acceptable code length is.
func TestAStoredSettingsRowIsClampedThenApplied(t *testing.T) {
	stored := &sms.DBSMSSettings{OTPLength: 99, OTPExpiry: 5, MaxAttempts: 400}
	sms.ValidateOTPSettings(stored)

	s := &Service{}
	s.SetOTPSettings(stored.OTPLength, stored.OTPExpiry, stored.MaxAttempts)

	got := s.otpConfig()
	if got.CodeLength != 6 || got.ExpirationTime != 5*time.Minute || got.MaxAttempts != 3 {
		t.Fatalf("out-of-range settings were applied as %+v; ValidateOTPSettings must pull each back "+
			"to the default before it reaches a challenge", got)
	}
}

// Push MFA's switch had the same shape as the OTP numbers: a field, a default,
// a line in a shipped config file, and no reader. An operator who turned the
// factor off could still enrol a phone and still be challenged through it.
func TestPushMFACanActuallyBeTurnedOff(t *testing.T) {
	off := &Service{cfg: &config.Config{}}
	off.cfg.PushMFA.Enabled = false
	if off.pushMFAEnabled() {
		t.Error("push_mfa.enabled=false and the factor reports itself enabled")
	}

	on := &Service{cfg: &config.Config{}}
	on.cfg.PushMFA.Enabled = true
	if !on.pushMFAEnabled() {
		t.Error("push_mfa.enabled=true and the factor reports itself disabled")
	}

	// The shape most unit tests use: no config at all. Treated as enabled, so
	// the gate refuses only where an operator has actually said to.
	if !(&Service{}).pushMFAEnabled() {
		t.Error("a service built without a config must not be treated as having push MFA turned off")
	}
}

func TestADisabledPushFactorRefusesEnrolmentAndChallenges(t *testing.T) {
	s := &Service{cfg: &config.Config{}}
	s.cfg.PushMFA.Enabled = false

	_, err := s.RegisterPushMFADevice(t.Context(), "user-1",
		&PushMFAEnrollment{Platform: "android", DeviceToken: "tok", DeviceName: "phone"}, "203.0.113.7")
	if err != ErrPushMFADisabled {
		t.Errorf("enrolment error = %v, want %v: a disabled factor must refuse, not enrol", err, ErrPushMFADisabled)
	}

	_, err = s.CreatePushMFAChallenge(t.Context(), &PushMFAChallengeRequest{UserID: "user-1"})
	if err != ErrPushMFADisabled {
		t.Errorf("challenge error = %v, want %v: a user enrolled before the factor was turned off "+
			"must not still be challenged through it", err, ErrPushMFADisabled)
	}
}
