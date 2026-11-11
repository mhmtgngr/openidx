package sso

import (
	"errors"

	"github.com/openidx/openidx/agent/internal/transport"
)

// Claimer is what ClaimAfterSignIn needs from the transport client.
type Claimer interface {
	Claim(accessToken string) (*transport.ClaimResult, error)
}

// Messages the tray shows after a sign-in claim attempt.
const (
	ClaimedMessage         = "This device is now yours."
	ClaimOwnedByAnotherMsg = "This device belongs to another person in your organization. An administrator can move it to you."
)

// ClaimAfterSignIn is the last step of the tray's "Sign in" on an enrolled
// device: it asks the server to make the device the signed-in person's
// (claim_mode login). A device enrolled with a fleet token names no one until
// this runs. It returns the message to show, or "" when there is nothing to
// say (the device was already theirs, or the claim could not be made and the
// sign-in itself still stands).
func ClaimAfterSignIn(c Claimer, t *Tokens) (string, error) {
	if c == nil || t == nil || t.AccessToken == "" {
		return "", nil
	}
	res, err := c.Claim(t.AccessToken)
	switch {
	case errors.Is(err, transport.ErrClaimOwnedByAnother):
		return ClaimOwnedByAnotherMsg, err
	case err != nil:
		return "", err
	case res.Claimed:
		return ClaimedMessage, nil
	}
	return "", nil
}
