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

	svc, err := NewService(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.SendOTP(context.Background(), "+15555550100", "123456"); err != nil {
		t.Fatalf("enabled mock SendOTP should succeed, got %v", err)
	}
}
