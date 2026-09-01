package identity

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// TestCreatePhoneCallChallengeRefusesWithoutProvider pins the honesty gate:
// with no call provider wired (the state of every install today —
// SetPhoneCallProvider has no production callers), this path used to store a
// challenge, place no call, and report success. It must refuse instead.
func TestCreatePhoneCallChallengeRefusesWithoutProvider(t *testing.T) {
	s := &Service{} // no provider, and the gate must fire before any DB use
	_, err := s.CreatePhoneCallChallenge(context.Background(), "u1", "+15555550100", "outbound")
	if !errors.Is(err, ErrPhoneCallMFANotConfigured) {
		t.Fatalf("want ErrPhoneCallMFANotConfigured, got %v", err)
	}
}

// TestPhoneCallErrStatus: an unconfigured factor is the installation's
// limitation, not the caller's mistake.
func TestPhoneCallErrStatus(t *testing.T) {
	if got := phoneCallErrStatus(ErrPhoneCallMFANotConfigured); got != http.StatusNotImplemented {
		t.Errorf("unconfigured factor should map to 501, got %d", got)
	}
	if got := phoneCallErrStatus(errors.New("bad input")); got != http.StatusBadRequest {
		t.Errorf("other errors should stay 400, got %d", got)
	}
}
