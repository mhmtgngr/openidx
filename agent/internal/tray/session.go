package tray

import (
	"context"
	"errors"
	"time"

	"github.com/openidx/openidx/agent/internal/sso"
)

// refreshLead is how long before the access token's expiry the tray renews
// it, so a click on a connection never races the clock.
const refreshLead = 2 * time.Minute

// refreshFunc is sso.RefreshWithClient's shape, swapped in tests.
type refreshFunc func(ctx context.Context, serverURL, refreshToken, clientID string) (*sso.Tokens, error)

// refreshOutcome says what refreshIfDue did with the session.
type refreshOutcome int

const (
	// sessionKept: nothing was due, or a transient failure left the current
	// tokens in place (err says which).
	sessionKept refreshOutcome = iota
	// sessionRefreshed: the returned tokens are new and should be stored.
	sessionRefreshed
	// sessionExpired: the session is over. Either the server rejected the
	// refresh token, or the access token has expired and there is none.
	sessionExpired
)

// refreshIfDue renews t when its access token expires within refreshLead.
//
// The tray never refreshed: it signed in once and used that access token until
// it expired, at which point every PAM call failed while the menu still said
// "Signed in". The decision is kept pure so it can be tested without a tray:
// the caller stores a refreshed session and signs the user out of an expired
// one. A refresh presents the client the session was issued to, which for a
// session stored before that was recorded is the desktop client.
func refreshIfDue(ctx context.Context, serverURL string, t *sso.Tokens, now time.Time, refresh refreshFunc) (*sso.Tokens, refreshOutcome, error) {
	if t == nil || t.AccessToken == "" {
		return t, sessionKept, nil
	}
	if t.ExpiresAt == 0 || now.Add(refreshLead).Unix() < t.ExpiresAt {
		return t, sessionKept, nil
	}
	if t.RefreshToken == "" {
		if now.Unix() >= t.ExpiresAt {
			return t, sessionExpired, errors.New("the access token has expired and there is no refresh token")
		}
		return t, sessionKept, nil
	}
	fresh, err := refresh(ctx, serverURL, t.RefreshToken, t.ClientOr(sso.DesktopClientID))
	if err != nil {
		var te *sso.TokenError
		if errors.As(err, &te) && te.Rejected() {
			return t, sessionExpired, err
		}
		return t, sessionKept, err
	}
	if fresh == nil || fresh.AccessToken == "" {
		return t, sessionKept, errors.New("the token endpoint answered without an access token")
	}
	if fresh.RefreshToken == "" {
		fresh.RefreshToken = t.RefreshToken // the server may omit an unchanged one
	}
	if fresh.ClientID == "" {
		fresh.ClientID = t.ClientOr(sso.DesktopClientID)
	}
	return fresh, sessionRefreshed, nil
}
