package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestGenerateStepUpToken_RoundTrip verifies that a freshly issued step-up
// token verifies under the matching public key and carries the claim shape
// the verifier handler relies on (sub / step_up / reason / iss / iat / exp).
// A regression in any of those fields would silently break the step-up
// re-authentication flow — every claim is read by handleStepUpVerify.
func TestGenerateStepUpToken_RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	const (
		userID = "11111111-1111-1111-1111-111111111111"
		reason = "high-value-transfer"
		issuer = "https://openidx.test"
	)

	before := time.Now()
	tokStr, err := generateStepUpToken(priv, userID, reason, issuer)
	if err != nil {
		t.Fatalf("generateStepUpToken: %v", err)
	}
	after := time.Now()
	if tokStr == "" {
		t.Fatal("generateStepUpToken returned empty token")
	}

	parsed, err := jwt.Parse(tokStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return &priv.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("parsed token reported Valid=false")
	}

	if kid, _ := parsed.Header["kid"].(string); kid != "openidx-key-1" {
		t.Errorf("kid header = %q, want %q", kid, "openidx-key-1")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type = %T, want jwt.MapClaims", parsed.Claims)
	}

	if got, _ := claims["sub"].(string); got != userID {
		t.Errorf("sub = %q, want %q", got, userID)
	}
	if got, _ := claims["reason"].(string); got != reason {
		t.Errorf("reason = %q, want %q", got, reason)
	}
	if got, _ := claims["iss"].(string); got != issuer {
		t.Errorf("iss = %q, want %q", got, issuer)
	}
	if got, _ := claims["step_up"].(bool); !got {
		t.Errorf("step_up = %v, want true", claims["step_up"])
	}

	// exp must be ~5 minutes after iat, and within the [before, after]
	// window we measured around the call. Allow ±1s slack.
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if iat == 0 || exp == 0 {
		t.Fatalf("iat/exp missing: iat=%v exp=%v", claims["iat"], claims["exp"])
	}
	if d := exp - iat; d < 295 || d > 305 {
		t.Errorf("exp - iat = %.0fs, want ~300s (5 min)", d)
	}
	if int64(iat) < before.Add(-time.Second).Unix() || int64(iat) > after.Add(time.Second).Unix() {
		t.Errorf("iat=%v not within call window [%v, %v]", int64(iat), before.Unix(), after.Unix())
	}
}

// TestGenerateStepUpToken_DefaultReason ensures the function passes through
// whatever reason string the caller provides without massaging it. (The
// "default to 'manual'" behavior lives in the handler, not the signer; the
// signer trusts its inputs.)
func TestGenerateStepUpToken_PassesReasonThrough(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	for _, reason := range []string{"manual", "policy-required", "elevated-scope-grant", ""} {
		tokStr, err := generateStepUpToken(priv, "u", reason, "iss")
		if err != nil {
			t.Fatalf("generateStepUpToken(reason=%q): %v", reason, err)
		}
		tok, _, err := jwt.NewParser().ParseUnverified(tokStr, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("ParseUnverified(reason=%q): %v", reason, err)
		}
		got, _ := tok.Claims.(jwt.MapClaims)["reason"].(string)
		if got != reason {
			t.Errorf("reason round-trip: passed %q, got back %q", reason, got)
		}
	}
}

// TestVerifyStepUpFactor_DefaultDenies is the regression guard for the step-up
// rubber-stamp bug: handleStepUpVerify used to complete the challenge and mint a
// step_up token without verifying req.Code at all. verifyStepUpFactor is now the
// gate, and its switch must default-deny — any method that is not an explicitly
// supported, verified factor returns (false, error) so no token is issued.
// The default branch touches no Service fields, so a zero-value Service exercises
// it without a database or identity service.
func TestVerifyStepUpFactor_DefaultDenies(t *testing.T) {
	s := &Service{}
	for _, method := range []string{"", "none", "unknown", "password", "magic-link", "trust-me"} {
		ok, err := s.verifyStepUpFactor(context.Background(), "user-1", method, "any-code", "127.0.0.1", "ua")
		if ok {
			t.Errorf("verifyStepUpFactor(method=%q) returned ok=true; unsupported methods must never verify", method)
		}
		if err == nil {
			t.Errorf("verifyStepUpFactor(method=%q) returned nil error; want an unsupported-method error", method)
		}
	}
}
