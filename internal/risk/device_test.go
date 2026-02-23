// Package risk provides unit tests for device fingerprinting
package risk

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestComputeFingerprint tests the device fingerprint generation
func TestComputeFingerprint(t *testing.T) {
	config := DefaultFingerprintingConfig()
	fingerprinter := NewDeviceFingerprinter(nil, nil, config, zap.NewNop())

	tests := []struct {
		name     string
		req      DeviceFingerprintRequest
		checkLen bool // Check if fingerprint has consistent length
	}{
		{
			name: "full desktop fingerprint",
			req: DeviceFingerprintRequest{
				UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				ScreenRes:  "1920x1080",
				Timezone:   "America/New_York",
				Language:   "en-US",
				Platform:   "Win32",
			},
			checkLen: true,
		},
		{
			name: "mobile device",
			req: DeviceFingerprintRequest{
				UserAgent:  "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
				ScreenRes:  "390x844",
				Timezone:   "America/Los_Angeles",
				Language:   "en-US",
				Platform:   "iPhone",
			},
			checkLen: true,
		},
		{
			name: "minimal fingerprint",
			req: DeviceFingerprintRequest{
				UserAgent: "Mozilla/5.0",
				ScreenRes: "unknown",
				Timezone:  "UTC",
				Language:  "en",
				Platform:  "",
			},
			checkLen: true,
		},
		{
			name: "with canvas hash",
			req: DeviceFingerprintRequest{
				UserAgent:  "Mozilla/5.0",
				ScreenRes:  "1920x1080",
				Timezone:   "Europe/London",
				Language:   "en-GB",
				Platform:   "MacIntel",
				CanvasHash: "abc123def456",
			},
			checkLen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := fingerprinter.ComputeFingerprint(tt.req)

			if fp == "" {
				t.Error("Fingerprint should not be empty")
			}

			if tt.checkLen && len(fp) != 64 { // SHA256 hex = 64 chars
				t.Errorf("Fingerprint length = %d, want 64 (SHA256 hex)", len(fp))
			}

			// Verify it's a valid hex string
			for _, c := range fp {
				if !isHexDigit(c) {
					t.Errorf("Fingerprint contains invalid character: %c", c)
					break
				}
			}
		})
	}
}

// TestComputeFingerprint_Consistency tests that identical inputs produce identical fingerprints
func TestComputeFingerprint_Consistency(t *testing.T) {
	config := DefaultFingerprintingConfig()
	fingerprinter := NewDeviceFingerprinter(nil, nil, config, zap.NewNop())

	req := DeviceFingerprintRequest{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		ScreenRes: "1920x1080",
		Timezone:  "America/New_York",
		Language:  "en-US",
		Platform:  "Win32",
	}

	fp1 := fingerprinter.ComputeFingerprint(req)
	fp2 := fingerprinter.ComputeFingerprint(req)

	if fp1 != fp2 {
		t.Errorf("Identical inputs should produce identical fingerprints: %s != %s", fp1, fp2)
	}
}

// TestComputeFingerprint_Difference tests that different inputs produce different fingerprints
func TestComputeFingerprint_Difference(t *testing.T) {
	config := DefaultFingerprintingConfig()
	fingerprinter := NewDeviceFingerprinter(nil, nil, config, zap.NewNop())

	baseReq := DeviceFingerprintRequest{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		ScreenRes: "1920x1080",
		Timezone:  "America/New_York",
		Language:  "en-US",
		Platform:  "Win32",
	}

	variations := []struct {
		name     string
		modifier func(DeviceFingerprintRequest) DeviceFingerprintRequest
	}{
		{
			name: "different user agent",
			modifier: func(r DeviceFingerprintRequest) DeviceFingerprintRequest {
				r.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
				return r
			},
		},
		{
			name: "different screen resolution",
			modifier: func(r DeviceFingerprintRequest) DeviceFingerprintRequest {
				r.ScreenRes = "2560x1440"
				return r
			},
		},
		{
			name: "different timezone",
			modifier: func(r DeviceFingerprintRequest) DeviceFingerprintRequest {
				r.Timezone = "Europe/London"
				return r
			},
		},
		{
			name: "different language",
			modifier: func(r DeviceFingerprintRequest) DeviceFingerprintRequest {
				r.Language = "fr-FR"
				return r
			},
		},
		{
			name: "different platform",
			modifier: func(r DeviceFingerprintRequest) DeviceFingerprintRequest {
				r.Platform = "MacIntel"
				return r
			},
		},
	}

	baseFP := fingerprinter.ComputeFingerprint(baseReq)

	for _, tt := range variations {
		t.Run(tt.name, func(t *testing.T) {
			modifiedReq := tt.modifier(baseReq)
			modifiedFP := fingerprinter.ComputeFingerprint(modifiedReq)

			if modifiedFP == baseFP {
				t.Errorf("Different inputs should produce different fingerprints")
			}
		})
	}
}

// TestCalculateTrustLevel tests trust level determination based on seen count
func TestCalculateTrustLevel(t *testing.T) {
	config := DefaultFingerprintingConfig()
	config.TrustedThreshold = 5
	fingerprinter := NewDeviceFingerprinter(nil, nil, config, zap.NewNop())

	tests := []struct {
		name         string
		seenCount    int
		expected     TrustLevel
	}{
		{
			name:      "first time seen",
			seenCount: 1,
			expected:  TrustLevelUnknown,
		},
		{
			name:      "seen twice",
			seenCount: 2,
			expected:  TrustLevelKnown,
		},
		{
			name:      "seen 4 times",
			seenCount: 4,
			expected:  TrustLevelKnown,
		},
		{
			name:      "exactly at threshold",
			seenCount: 5,
			expected:  TrustLevelTrusted,
		},
		{
			name:      "above threshold",
			seenCount: 10,
			expected:  TrustLevelTrusted,
		},
		{
			name:      "zero seen count",
			seenCount: 0,
			expected:  TrustLevelUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fingerprinter.calculateTrustLevel(tt.seenCount)
			if result != tt.expected {
				t.Errorf("calculateTrustLevel(%d) = %v, want %v",
					tt.seenCount, result, tt.expected)
			}
		})
	}
}

// TestGenerateDeviceName tests device name generation from user agent
func TestGenerateDeviceName(t *testing.T) {
	config := DefaultFingerprintingConfig()
	fingerprinter := NewDeviceFingerprinter(nil, nil, config, zap.NewNop())

	tests := []struct {
		userAgent string
		expected  string // Should contain these key parts
	}{
		{
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expected:  "Chrome on Windows",
		},
		{
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expected:  "Chrome on macOS",
		},
		{
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			expected:  "Firefox on Windows",
		},
		{
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			expected:  "Safari on macOS",
		},
		{
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
			expected:  "Safari on iPhone",
		},
		{
			userAgent: "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
			expected:  "Chrome on Android",
		},
		{
			userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expected:  "Chrome on Linux",
		},
		{
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			expected:  "Edge on Windows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.userAgent[:30], func(t *testing.T) {
			result := fingerprinter.generateDeviceName(tt.userAgent)
			if !strings.Contains(result, tt.expected) {
				t.Errorf("generateDeviceName() = %s, should contain %s", result, tt.expected)
			}
		})
	}
}

// TestNormalizeUserAgent tests user agent normalization
func TestNormalizeUserAgent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string // Should contain this
	}{
		{
			name:     "chrome with version",
			input:    "Chrome/120.0.6099.144",
			expected: "chrome",
		},
		{
			name:     "windows nt version",
			input:    "Windows NT 10.0",
			expected: "windows nt",
		},
		{
			name:     "mac os x version",
			input:    "Mac OS X 10_15_7",
			expected: "mac os x",
		},
		{
			name:     "android version",
			input:    "Android 11",
			expected: "android",
		},
		{
			name:     "case normalization",
			input:    "MOZILLA/5.0 (WINDOWS NT 10.0)",
			expected: "mozilla/5.0 (windows nt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeUserAgent(tt.input)
			if !strings.Contains(result, tt.expected) {
				t.Errorf("normalizeUserAgent() = %s, should contain %s", result, tt.expected)
			}
		})
	}
}

// TestNormalizeScreenRes tests screen resolution normalization
func TestNormalizeScreenRes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "full HD",
			input:    "1920x1080",
			expected: "fhd",
		},
		{
			name:     "QHD",
			input:    "2560x1440",
			expected: "qhd",
		},
		{
			name:     "4K",
			input:    "3840x2160",
			expected: "4k",
		},
		{
			name:     "laptop HD",
			input:    "1366x768",
			expected: "laptop-hd",
		},
		{
			name:     "HD",
			input:    "1280x720",
			expected: "hd",
		},
		{
			name:     "unknown",
			input:    "unknown",
			expected: "unknown",
		},
		{
			name:     "empty",
			input:    "",
			expected: "unknown",
		},
		{
			name:     "macbook resolution",
			input:    "1440x900",
			expected: "macbook",
		},
		{
			name:     "mobile variant",
			input:    "mobile-390x844",
			expected: "mobile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeScreenRes(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeScreenRes(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestNormalizeTimezone tests timezone normalization
func TestNormalizeTimezone(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "UTC",
			input:    "UTC",
			expected: "utc",
		},
		{
			name:     "GMT",
			input:    "GMT",
			expected: "utc",
		},
		{
			name:     "America region",
			input:    "America/New_York",
			expected: "america",
		},
		{
			name:     "Europe region",
			input:    "Europe/London",
			expected: "europe",
		},
		{
			name:     "Asia region",
			input:    "Asia/Tokyo",
			expected: "asia",
		},
		{
			name:     "case and space",
			input:    "  America/Los_Angeles  ",
			expected: "america",
		},
		{
			name:     "empty",
			input:    "",
			expected: "utc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeTimezone(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeTimezone(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestDeviceFingerprintRequest tests the fingerprint request structure
func TestDeviceFingerprintRequest(t *testing.T) {
	req := DeviceFingerprintRequest{
		UserAgent:  "Mozilla/5.0",
		ScreenRes:  "1920x1080",
		Timezone:   "America/New_York",
		Language:   "en-US",
		Platform:   "Win32",
		CanvasHash: "abc123",
		WebGLHash:  "def456",
		AudioHash:  "ghi789",
	}

	// Verify all fields are populated
	if req.UserAgent == "" {
		t.Error("UserAgent should not be empty")
	}
	if req.ScreenRes == "" {
		t.Error("ScreenRes should not be empty")
	}
	if req.Timezone == "" {
		t.Error("Timezone should not be empty")
	}
	if req.Language == "" {
		t.Error("Language should not be empty")
	}
	// Platform can be empty for some devices
	if req.CanvasHash == "" {
		t.Error("CanvasHash should not be empty in this test")
	}
}

// TestTrustLevel_String tests the string representation of trust levels
func TestTrustLevel_String(t *testing.T) {
	tests := []struct {
		level    TrustLevel
		expected string
	}{
		{TrustLevelTrusted, "trusted"},
		{TrustLevelKnown, "known"},
		{TrustLevelUnknown, "unknown"},
		{TrustLevelSuspicious, "suspicious"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := string(tt.level)
			if result != tt.expected {
				t.Errorf("TrustLevel string = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestFingerprintingConfig tests the fingerprinting configuration
func TestFingerprintingConfig(t *testing.T) {
	config := DefaultFingerprintingConfig()

	if config.CacheTTL != 24*time.Hour {
		t.Errorf("Default CacheTTL = %v, want 24h", config.CacheTTL)
	}

	if config.TrustedThreshold != 5 {
		t.Errorf("Default TrustedThreshold = %d, want 5", config.TrustedThreshold)
	}

	if config.Salt == "" {
		t.Error("Salt should not be empty")
	}

	if !config.UseCanvasFingerprint {
		t.Error("UseCanvasFingerprint should be enabled by default")
	}

	if !config.UseWebGLFingerprint {
		t.Error("UseWebGLFingerprint should be enabled by default")
	}

	if config.UseAudioFingerprint {
		t.Error("UseAudioFingerprint should be disabled by default due to UX concerns")
	}
}

// Helper function to check if a character is a valid hex digit
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
