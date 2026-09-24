package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/openidx/openidx/internal/common/config"
)

// StartPushEnrollment puts the issuer URL in the QR the phone scans. With no
// issuer configured it must refuse, and never fall back to a built-in host: the
// phone would send the enrollment token and the account name to that host.
func TestStartPushEnrollmentRefusesWithoutIssuer(t *testing.T) {
	for _, cfg := range []*config.Config{nil, {OAuthIssuer: ""}} {
		s := &Service{cfg: cfg}
		ticket, err := s.StartPushEnrollment(context.Background(), "user-1")
		if !errors.Is(err, errPushEnrollNoIssuer) {
			t.Fatalf("cfg=%+v: err = %v, want errPushEnrollNoIssuer", cfg, err)
		}
		if ticket != nil {
			t.Fatalf("cfg=%+v: got a ticket without an issuer: %+v", cfg, ticket)
		}
	}
}

// The positive half: with an issuer set, the issuer check passes and the call
// proceeds to the next guard (here, the missing Redis), not to the issuer error.
func TestStartPushEnrollmentPassesIssuerCheckWhenConfigured(t *testing.T) {
	s := &Service{cfg: &config.Config{OAuthIssuer: "https://idp.example.com"}}
	_, err := s.StartPushEnrollment(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected the Redis guard to refuse, got nil error")
	}
	if errors.Is(err, errPushEnrollNoIssuer) {
		t.Fatalf("issuer is configured but got the issuer error: %v", err)
	}
}
