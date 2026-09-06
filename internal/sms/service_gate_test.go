package sms

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// A typo'd provider name used to silently become a mock that "delivers"
// nothing. It must be a configuration error the operator sees immediately.
func TestNewServiceRejectsUnknownProvider(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Provider = "twillio" // typo of twilio

	_, err := NewService(cfg, zap.NewNop())
	if err == nil {
		t.Fatal("want error for unknown provider, got nil")
	}
	if !strings.Contains(err.Error(), "twillio") {
		t.Fatalf("error should name the bad provider, got: %v", err)
	}
}

// Disabled sending used to return nil, which let MFA flows report
// "code sent" for a code that went nowhere. It must refuse.
func TestSendRefusesWhenDisabled(t *testing.T) {
	cfg := DefaultConfig() // Provider: mock, Enabled: false
	cfg.AllowMock = true   // development posture; see TestMockIsNotAProviderOutsideDevelopment
	svc, err := NewService(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	if err := svc.SendOTP(context.Background(), "+15555550100", "123456"); !errors.Is(err, ErrSMSSendingDisabled) {
		t.Fatalf("SendOTP: want ErrSMSSendingDisabled, got %v", err)
	}
	if err := svc.SendMessage(context.Background(), "+15555550100", "hi"); !errors.Is(err, ErrSMSSendingDisabled) {
		t.Fatalf("SendMessage: want ErrSMSSendingDisabled, got %v", err)
	}
}

// The explicit mock provider stays available for development.
func TestExplicitMockStillWorksWhenEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true // Provider stays "mock"
	cfg.AllowMock = true

	svc, err := NewService(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.SendOTP(context.Background(), "+15555550100", "123456"); err != nil {
		t.Fatalf("enabled mock SendOTP should succeed, got %v", err)
	}
}

// A mock IS a provider as far as NewService was concerned, and "mock" is the
// DEFAULT provider — so an operator who set only SMS_ENABLED=true got a
// service, SetSMSProvider was called with it, and the not-configured gate in
// internal/identity/otp.go never fired. The result was an SMS factor a user
// could enrol into, that answered "Verification code sent to your phone", and
// that delivered nothing.
//
// Outside development the mock must be treated as "not configured", which is
// what it is.
func TestMockIsNotAProviderOutsideDevelopment(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	// AllowMock deliberately left false — this is the production posture, and
	// it is the DEFAULT of the struct, so forgetting to set it fails safe.

	svc, err := NewService(cfg, zap.NewNop())
	if !errors.Is(err, ErrMockProviderNotAllowed) {
		t.Fatalf("NewService with the mock provider outside development: err = %v, want ErrMockProviderNotAllowed", err)
	}
	if svc != nil {
		t.Fatal("a refused configuration must not yield a service; a non-nil one would be assigned through the SMSProvider interface and defeat the not-configured gate")
	}
}
