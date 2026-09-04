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
