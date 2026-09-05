package identity

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// These tests pin the honesty gate for the SMS and email OTP factors,
// mirroring TestCreatePhoneCallChallengeRefusesWithoutProvider: with no
// delivery channel wired, these paths used to store state, send nothing,
// report success — and write the plaintext OTP code into the logs. They
// must refuse instead, before any DB use (hence the bare &Service{}).

func TestEnrollSMSRefusesWithoutProvider(t *testing.T) {
	s := &Service{}
	_, _, err := s.EnrollSMS(context.Background(), "u1", "5555550100", "+1")
	if !errors.Is(err, ErrSMSMFANotConfigured) {
		t.Fatalf("want ErrSMSMFANotConfigured, got %v", err)
	}
}

func TestCreateSMSChallengeRefusesWithoutProvider(t *testing.T) {
	s := &Service{}
	_, err := s.CreateSMSChallenge(context.Background(), "u1", "203.0.113.7", "ua")
	if !errors.Is(err, ErrSMSMFANotConfigured) {
		t.Fatalf("want ErrSMSMFANotConfigured, got %v", err)
	}
}

func TestEnrollEmailOTPRefusesWithoutEmailService(t *testing.T) {
	s := &Service{}
	_, _, err := s.EnrollEmailOTP(context.Background(), "u1", "user@example.com")
	if !errors.Is(err, ErrEmailOTPMFANotConfigured) {
		t.Fatalf("want ErrEmailOTPMFANotConfigured, got %v", err)
	}
}

func TestCreateEmailOTPChallengeRefusesWithoutEmailService(t *testing.T) {
	s := &Service{}
	_, err := s.CreateEmailOTPChallenge(context.Background(), "u1", "203.0.113.7", "ua")
	if !errors.Is(err, ErrEmailOTPMFANotConfigured) {
		t.Fatalf("want ErrEmailOTPMFANotConfigured, got %v", err)
	}
}

// TestOTPErrStatus: an unconfigured factor is the installation's limitation,
// not the caller's mistake.
func TestOTPErrStatus(t *testing.T) {
	if got := otpErrStatus(ErrSMSMFANotConfigured); got != http.StatusNotImplemented {
		t.Errorf("unconfigured SMS factor should map to 501, got %d", got)
	}
	if got := otpErrStatus(ErrEmailOTPMFANotConfigured); got != http.StatusNotImplemented {
		t.Errorf("unconfigured email factor should map to 501, got %d", got)
	}
	if got := otpErrStatus(errors.New("bad input")); got != http.StatusBadRequest {
		t.Errorf("other errors should stay 400, got %d", got)
	}
}
