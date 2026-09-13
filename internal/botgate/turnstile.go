package botgate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TurnstileVerifier validates Cloudflare Turnstile tokens against the
// siteverify API. Turnstile is the challenge a Cloudflare edge issues; the
// SPA login page renders the widget when the login answers
// challenge_required and resubmits with the token in challenge_token.
//
// It is one ChallengeVerifier; a deployment on another edge plugs in its own
// (hCaptcha and reCAPTCHA speak the same siteverify shape). Failing to reach
// the verifier is a rejected challenge, never an accepted one.
type TurnstileVerifier struct {
	secret   string
	endpoint string
	client   *http.Client
}

const turnstileSiteverify = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// NewTurnstileVerifier returns nil when secret is empty, so callers can pass
// the result straight to New.
func NewTurnstileVerifier(secret string) ChallengeVerifier {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil
	}
	return &TurnstileVerifier{
		secret:   secret,
		endpoint: turnstileSiteverify,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

// Verify posts the token to siteverify. remoteIP is optional and, when the
// edge preserved it, lets Cloudflare bind the token to the solver.
func (v *TurnstileVerifier) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	if token == "" {
		return false, nil
	}
	form := url.Values{"secret": {v.secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return false, fmt.Errorf("turnstile siteverify: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64<<10)).Decode(&out); err != nil {
		return false, err
	}
	return out.Success, nil
}
