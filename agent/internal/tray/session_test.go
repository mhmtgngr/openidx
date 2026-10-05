package tray

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/sso"
)

type fakeRefresher struct {
	calls    int
	clientID string
	answer   *sso.Tokens
	err      error
}

func (f *fakeRefresher) refresh(_ context.Context, _, _, clientID string) (*sso.Tokens, error) {
	f.calls++
	f.clientID = clientID
	return f.answer, f.err
}

func TestAFreshTokenIsLeftAlone(t *testing.T) {
	f := &fakeRefresher{}
	now := time.Unix(1_000_000, 0)
	tok := &sso.Tokens{AccessToken: "at", RefreshToken: "rt", ExpiresAt: now.Add(time.Hour).Unix()}
	got, outcome, err := refreshIfDue(context.Background(), "https://openidx.test", tok, now, f.refresh)
	if err != nil || outcome != sessionKept || got != tok || f.calls != 0 {
		t.Fatalf("got=%v outcome=%v err=%v calls=%d", got, outcome, err, f.calls)
	}
}

func TestATokenAboutToExpireIsRefreshedAsTheIssuingClient(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	f := &fakeRefresher{answer: &sso.Tokens{AccessToken: "at2", ExpiresAt: now.Add(time.Hour).Unix()}}
	tok := &sso.Tokens{AccessToken: "at", RefreshToken: "rt", ExpiresAt: now.Add(time.Minute).Unix(), ClientID: sso.DesktopClientID}
	got, outcome, err := refreshIfDue(context.Background(), "https://openidx.test", tok, now, f.refresh)
	if err != nil || outcome != sessionRefreshed {
		t.Fatalf("outcome=%v err=%v", outcome, err)
	}
	if f.clientID != sso.DesktopClientID {
		t.Fatalf("refresh presented %q", f.clientID)
	}
	if got.AccessToken != "at2" || got.RefreshToken != "rt" || got.ClientID != sso.DesktopClientID {
		t.Fatalf("refreshed tokens must carry the new access token, the kept refresh token and the client: %+v", *got)
	}
}

func TestALegacyTokenRefreshesAsTheDesktopClient(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	f := &fakeRefresher{answer: &sso.Tokens{AccessToken: "at2", RefreshToken: "rt2", ExpiresAt: now.Add(time.Hour).Unix()}}
	tok := &sso.Tokens{AccessToken: "at", RefreshToken: "rt", ExpiresAt: now.Unix()} // no ClientID recorded
	got, outcome, _ := refreshIfDue(context.Background(), "https://openidx.test", tok, now, f.refresh)
	if outcome != sessionRefreshed || f.clientID != sso.DesktopClientID || got.ClientID != sso.DesktopClientID {
		t.Fatalf("outcome=%v presented=%q stored=%q", outcome, f.clientID, got.ClientID)
	}
}

func TestARejectedRefreshEndsTheSession(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	f := &fakeRefresher{err: &sso.TokenError{Status: 400, Body: `{"error":"invalid_grant"}`}}
	tok := &sso.Tokens{AccessToken: "at", RefreshToken: "rt-dead", ExpiresAt: now.Unix()}
	_, outcome, err := refreshIfDue(context.Background(), "https://openidx.test", tok, now, f.refresh)
	if outcome != sessionExpired || err == nil {
		t.Fatalf("a rejected refresh token means the session is over: outcome=%v err=%v", outcome, err)
	}
}

func TestATransientFailureKeepsTheSession(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	f := &fakeRefresher{err: errors.New("dial tcp: connection refused")}
	tok := &sso.Tokens{AccessToken: "at", RefreshToken: "rt", ExpiresAt: now.Unix()}
	got, outcome, err := refreshIfDue(context.Background(), "https://openidx.test", tok, now, f.refresh)
	if outcome != sessionKept || err == nil || got != tok {
		t.Fatalf("a network failure is retried next tick, not treated as sign-out: outcome=%v err=%v", outcome, err)
	}
	f2 := &fakeRefresher{err: &sso.TokenError{Status: 503}}
	_, outcome, _ = refreshIfDue(context.Background(), "https://openidx.test", tok, now, f2.refresh)
	if outcome != sessionKept {
		t.Fatalf("a 503 is not a rejection: outcome=%v", outcome)
	}
}

func TestAnExpiredTokenWithNoRefreshTokenIsOver(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	f := &fakeRefresher{}
	tok := &sso.Tokens{AccessToken: "at", ExpiresAt: now.Add(-time.Second).Unix()}
	_, outcome, _ := refreshIfDue(context.Background(), "https://openidx.test", tok, now, f.refresh)
	if outcome != sessionExpired || f.calls != 0 {
		t.Fatalf("outcome=%v calls=%d", outcome, f.calls)
	}
	soon := &sso.Tokens{AccessToken: "at", ExpiresAt: now.Add(time.Minute).Unix()}
	_, outcome, _ = refreshIfDue(context.Background(), "https://openidx.test", soon, now, f.refresh)
	if outcome != sessionKept {
		t.Fatalf("still valid for a minute with nothing to refresh it: keep it; outcome=%v", outcome)
	}
}
