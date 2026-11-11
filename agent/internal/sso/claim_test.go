package sso

import (
	"errors"
	"testing"

	"github.com/openidx/openidx/agent/internal/transport"
)

type fakeClaimer struct {
	res *transport.ClaimResult
	err error
	got string
}

func (f *fakeClaimer) Claim(at string) (*transport.ClaimResult, error) {
	f.got = at
	return f.res, f.err
}

func TestSignInClaimsUnclaimedDevice(t *testing.T) {
	f := &fakeClaimer{res: &transport.ClaimResult{Claimed: true}}
	msg, err := ClaimAfterSignIn(f, &Tokens{AccessToken: "at"})
	if err != nil || msg != ClaimedMessage || f.got != "at" {
		t.Fatalf("msg=%q err=%v sent=%q", msg, err, f.got)
	}
	f = &fakeClaimer{res: &transport.ClaimResult{Claimed: false}}
	if msg, _ := ClaimAfterSignIn(f, &Tokens{AccessToken: "at"}); msg != "" {
		t.Errorf("an already-owned device says %q, want nothing", msg)
	}
	f = &fakeClaimer{err: transport.ErrClaimOwnedByAnother}
	if msg, err := ClaimAfterSignIn(f, &Tokens{AccessToken: "at"}); msg != ClaimOwnedByAnotherMsg || !errors.Is(err, transport.ErrClaimOwnedByAnother) {
		t.Errorf("owned by another: msg=%q err=%v", msg, err)
	}
	if msg, _ := ClaimAfterSignIn(&fakeClaimer{}, &Tokens{}); msg != "" {
		t.Errorf("no access token still claimed: %q", msg)
	}
}
