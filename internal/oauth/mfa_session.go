package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// The MFA session is the partial-authentication state between a successful
// password step and a verified second factor.
//
// It used to live in hosted_mfa.go, alongside the server-rendered login's own
// second-factor pages. Those pages are gone (there is one login UI now, the
// SPA), but the session itself is not theirs: POST /oauth/login creates one
// and POST /oauth/mfa-verify consumes it, and that is the flow every client
// uses.

// createMFASession stashes the partially-authenticated login in Redis exactly
// the way the JSON path does, so /oauth/mfa-verify, /oauth/mfa-send-otp and the
// hosted pages below all read the same session shape.
func (s *Service) createMFASession(ctx context.Context, userID string, oauthParams map[string]string, riskScore int, fingerprint, location string, methods []string) (string, error) {
	mfaSession := GenerateRandomToken(32)
	mfaData := map[string]string{
		"user_id":     userID,
		"risk_score":  fmt.Sprintf("%d", riskScore),
		"fingerprint": fingerprint,
		"location":    location,
		// The factors this challenge may be completed with, decided ONCE by the
		// risk evaluation. Without pinning them here, a later step could
		// re-derive them from enrollment alone and quietly drop a restriction
		// the risk policy imposed (e.g. "this login needs a phishing-resistant
		// factor"), letting the user finish with a weaker one instead.
		"allowed_methods": strings.Join(methods, ","),
	}
	for k, v := range oauthParams {
		mfaData[k] = v
	}
	payload, err := json.Marshal(mfaData)
	if err != nil {
		return "", err
	}
	if err := s.redis.Client.Set(ctx, "mfa_session:"+mfaSession, string(payload), 5*time.Minute).Err(); err != nil {
		return "", err
	}
	return mfaSession, nil
}

// allowedMFAMethods returns the factor list this challenge was ISSUED for, or
// nil when the session carries none.
//
// Nil means "no list was pinned", not "no method is allowed": the passwordless
// phone flow (passwordless_phone.go) pins a single required_mfa_method instead,
// which is stricter, and a session minted by an older build during a rollout
// has neither. Sessions live five minutes, so that window closes on its own.
func allowedMFAMethods(mfaData map[string]string) []string {
	raw := strings.TrimSpace(mfaData["allowed_methods"])
	if raw == "" {
		return nil
	}
	var out []string
	for _, m := range strings.Split(raw, ",") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// mfaMethodPermitted reports whether method may be used against this challenge.
//
// This is the check the pin above was written for, and until now nothing made
// it. evaluateMFA filters the offerable factors by what the risk policy allows
// (mfa_policy.go: `assessment.AllowedMethods` can restrict a high-risk login to
// phishing-resistant factors alone), createMFASession stores the result, the
// login response offers exactly that list to the console — and every endpoint
// that consumes the session accepted any method the caller named. A caller who
// skipped the console could finish a webauthn-only challenge with an SMS code,
// which is precisely the substitution the filter exists to prevent.
//
// Enforced at all four consumers rather than only at mfa-verify: an excluded
// factor should not be startable either, and a check that lives in one of four
// doors is a check the next change walks around.
func mfaMethodPermitted(mfaData map[string]string, method string) bool {
	allowed := allowedMFAMethods(mfaData)
	if len(allowed) == 0 {
		return true
	}
	for _, m := range allowed {
		if m == method {
			return true
		}
	}
	return false
}
