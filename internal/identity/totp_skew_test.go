package identity

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TestTOTPStepOf proves the validator accepts a code from the adjacent 30s
// window (the common clock-drift case) and trims whitespace, while still
// rejecting an unrelated code -- and that it names the step each accepted code
// belongs to, which is what lets the verifiers accept a code once.
func TestTOTPStepOf(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: "test@openidx.local"})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := key.Secret()
	// One clock for the codes and the check, so no case can straddle a step.
	now := time.Now().UTC()
	current := now.Unix() / totpPeriod

	gen := func(at time.Time) string {
		code, err := totp.GenerateCode(secret, at)
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		return code
	}

	tests := []struct {
		name     string
		code     string
		want     bool
		wantStep int64
	}{
		{"current window", gen(now), true, current},
		{"previous window (-30s)", gen(now.Add(-30 * time.Second)), true, current - 1},
		{"next window (+30s)", gen(now.Add(30 * time.Second)), true, current + 1},
		{"whitespace trimmed", "  " + gen(now) + "  ", true, current},
		{"two windows away is rejected", gen(now.Add(-90 * time.Second)), false, 0},
		{"two windows ahead is rejected", gen(now.Add(90 * time.Second)), false, 0},
		{"garbage code rejected", "000000", false, 0},
		{"empty code rejected", "", false, 0},
		{"a seven-digit code is rejected", gen(now) + "0", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step, got := totpStepOf(tt.code, secret, now)
			if got != tt.want {
				t.Fatalf("totpStepOf(%q) = %v, want %v", tt.code, got, tt.want)
			}
			if got && step != tt.wantStep {
				t.Errorf("totpStepOf(%q) named step %d, want %d", tt.code, step, tt.wantStep)
			}
		})
	}
}

// TestTOTPStepOf_WrongSecret ensures a code minted from a different secret
// never validates (no cross-secret acceptance from the skew window).
func TestTOTPStepOf_WrongSecret(t *testing.T) {
	k1, _ := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: "a"})
	k2, _ := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: "b"})
	now := time.Now().UTC()
	code, err := totp.GenerateCodeCustom(k2.Secret(), now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if _, ok := totpStepOf(code, k1.Secret(), now); ok {
		t.Error("code from a different secret must not validate")
	}
}
