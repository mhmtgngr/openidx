package oauth

import (
	"testing"

	"github.com/openidx/openidx/internal/common/config"
)

func TestDeviceTrustGateBlocks(t *testing.T) {
	cases := []struct {
		name      string
		enabled   bool
		browzerID string
		clientID  string
		trusted   bool
		wantBlock bool
	}{
		{"feature off", false, "browzer-client", "browzer-client", false, false},
		{"clientless + untrusted", true, "browzer-client", "browzer-client", false, true},
		{"clientless + trusted", true, "browzer-client", "browzer-client", true, false},
		{"other client untrusted", true, "browzer-client", "admin-console", false, false},
		{"empty client", true, "browzer-client", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{config: &config.Config{
				RequireDeviceTrustForClientless: tc.enabled,
				BrowZerClientID:                 tc.browzerID,
			}}
			if got := s.deviceTrustGateBlocks(tc.clientID, tc.trusted); got != tc.wantBlock {
				t.Fatalf("deviceTrustGateBlocks(%q,%v)=%v want %v", tc.clientID, tc.trusted, got, tc.wantBlock)
			}
		})
	}
}
