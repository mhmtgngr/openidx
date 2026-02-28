// Package audit provides tests for audit service configuration
package audit

import (
	"testing"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultStreamConfig(t *testing.T) {
	cfg := DefaultStreamConfig()

	assert.NotNil(t, cfg)
	assert.Nil(t, cfg.AllowedOrigins, "Default should be nil for same-origin policy")
	assert.True(t, cfg.EnableSecurityLogging, "Security logging should be enabled by default")
	assert.Equal(t, 1024*64, cfg.MaxMessageSize, "Default message size should be 64KB")
	assert.Equal(t, 10, cfg.WriteTimeout, "Default write timeout should be 10 seconds")
	assert.Equal(t, 60, cfg.ReadTimeout, "Default read timeout should be 60 seconds")
	assert.Equal(t, 30, cfg.PingInterval, "Default ping interval should be 30 seconds")
	assert.Equal(t, 60, cfg.PongTimeout, "Default pong timeout should be 60 seconds")
}

func TestStreamConfigFromAppConfig(t *testing.T) {
	tests := []struct {
		name             string
		auditStreamOrigins string
		expectedOrigins  []string
		expectNil        bool
	}{
		{
			name:             "empty config returns same-origin (nil)",
			auditStreamOrigins: "",
			expectNil:        true,
		},
		{
			name:             "wildcard origin",
			auditStreamOrigins: "*",
			expectedOrigins:  []string{"*"},
		},
		{
			name:             "single origin",
			auditStreamOrigins: "https://example.com",
			expectedOrigins:  []string{"https://example.com"},
		},
		{
			name:             "multiple origins comma-separated",
			auditStreamOrigins: "https://example.com,https://app.example.com,http://localhost:3000",
			expectedOrigins:  []string{"https://example.com", "https://app.example.com", "http://localhost:3000"},
		},
		{
			name:             "origins with spaces",
			auditStreamOrigins: "https://example.com, https://app.example.com , http://localhost:3000",
			expectedOrigins:  []string{"https://example.com", "https://app.example.com", "http://localhost:3000"},
		},
		{
			name:             "wildcard subdomain",
			auditStreamOrigins: "*.example.com",
			expectedOrigins:  []string{"*.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				AuditStreamAllowedOrigins: tt.auditStreamOrigins,
			}

			streamCfg := StreamConfigFromAppConfig(cfg)
			assert.NotNil(t, streamCfg)

			if tt.expectNil {
				assert.Nil(t, streamCfg.AllowedOrigins)
			} else {
				assert.Equal(t, tt.expectedOrigins, streamCfg.AllowedOrigins)
			}
		})
	}
}

func TestNormalizeOrigin(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase conversion",
			input:    "HTTP://EXAMPLE.COM",
			expected: "http://example.com",
		},
		{
			name:     "trim whitespace",
			input:    "  http://example.com  ",
			expected: "http://example.com",
		},
		{
			name:     "remove default HTTP port",
			input:    "http://example.com:80",
			expected: "http://example.com",
		},
		{
			name:     "remove default HTTPS port",
			input:    "https://example.com:443",
			expected: "https://example.com",
		},
		{
			name:     "keep non-default port",
			input:    "https://example.com:8443",
			expected: "https://example.com:8443",
		},
		{
			name:     "keep path and query",
			input:    "https://example.com/path?query=value",
			expected: "https://example.com/path?query=value",
		},
		{
			name:     "already normalized",
			input:    "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "http with non-default port",
			input:    "http://localhost:3000",
			expected: "http://localhost:3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeOrigin(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsOriginAllowed(t *testing.T) {
	tests := []struct {
		name          string
		origin        string
		allowedOrigins []string
		expected      bool
	}{
		{
			name:          "empty allowed list denies all (except empty origin)",
			origin:        "https://example.com",
			allowedOrigins: []string{},
			expected:      false,
		},
		{
			name:          "nil allowed list denies all",
			origin:        "https://example.com",
			allowedOrigins: nil,
			expected:      false,
		},
		{
			name:          "wildcard allows all",
			origin:        "https://example.com",
			allowedOrigins: []string{"*"},
			expected:      true,
		},
		{
			name:          "exact match allowed",
			origin:        "https://example.com",
			allowedOrigins: []string{"https://example.com"},
			expected:      true,
		},
		{
			name:          "case insensitive match",
			origin:        "HTTPS://EXAMPLE.COM",
			allowedOrigins: []string{"https://example.com"},
			expected:      true,
		},
		{
			name:          "port normalized for match",
			origin:        "https://example.com:443",
			allowedOrigins: []string{"https://example.com"},
			expected:      true,
		},
		{
			name:          "subdomain wildcard match",
			origin:        "https://app.example.com",
			allowedOrigins: []string{"*.example.com"},
			expected:      true,
		},
		{
			name:          "nested subdomain wildcard match",
			origin:        "https://api.v1.example.com",
			allowedOrigins: []string{"*.example.com"},
			expected:      true,
		},
		{
			name:          "bare domain not matched by wildcard subdomain",
			origin:        "https://example.com",
			allowedOrigins: []string{"*.example.com"},
			expected:      false,
		},
		{
			name:          "different subdomain not matched",
			origin:        "https://evil.com",
			allowedOrigins: []string{"*.example.com"},
			expected:      false,
		},
		{
			name:          "prevention of example.com.evil.com",
			origin:        "https://example.com.evil.com",
			allowedOrigins: []string{"*.example.com"},
			expected:      false,
		},
		{
			name:          "multiple allowed origins - match first",
			origin:        "https://example.com",
			allowedOrigins: []string{"https://example.com", "https://app.example.com"},
			expected:      true,
		},
		{
			name:          "multiple allowed origins - match second",
			origin:        "https://app.example.com",
			allowedOrigins: []string{"https://example.com", "https://app.example.com"},
			expected:      true,
		},
		{
			name:          "multiple allowed origins - no match",
			origin:        "https://evil.com",
			allowedOrigins: []string{"https://example.com", "https://app.example.com"},
			expected:      false,
		},
		{
			name:          "localhost with port",
			origin:        "http://localhost:3000",
			allowedOrigins: []string{"http://localhost:3000"},
			expected:      true,
		},
		{
			name:          "127.0.0.1 with port",
			origin:        "http://127.0.0.1:5173",
			allowedOrigins: []string{"http://127.0.0.1:5173"},
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsOriginAllowed(tt.origin, tt.allowedOrigins)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateOriginForProduction(t *testing.T) {
	tests := []struct {
		name        string
		origins     []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty list is valid",
			origins:     []string{},
			expectError: false,
		},
		{
			name:        "valid production origins",
			origins:     []string{"https://example.com", "https://app.example.com"},
			expectError: false,
		},
		{
			name:        "wildcard is not allowed in production",
			origins:     []string{"*"},
			expectError: true,
			errorMsg:    "wildcard origin is not allowed in production",
		},
		{
			name:        "localhost is not allowed in production",
			origins:     []string{"http://localhost:3000"},
			expectError: true,
			errorMsg:    "localhost origins are not allowed in production",
		},
		{
			name:        "127.0.0.1 is not allowed in production",
			origins:     []string{"http://127.0.0.1:3000"},
			expectError: true,
			errorMsg:    "localhost origins are not allowed in production",
		},
		{
			name:        "origin without protocol is invalid",
			origins:     []string{"example.com"},
			expectError: true,
			errorMsg:    "must start with http:// or https://",
		},
		{
			name:        "FTP protocol is invalid",
			origins:     []string{"ftp://example.com"},
			expectError: true,
			errorMsg:    "must start with http:// or https://",
		},
		{
			name:        "mixed valid and invalid origins",
			origins:     []string{"https://example.com", "*"},
			expectError: true,
			errorMsg:    "wildcard origin is not allowed in production",
		},
		{
			name:        "origins with whitespace are trimmed",
			origins:     []string{" https://example.com "},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOriginForProduction(tt.origins)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOriginValidationError(t *testing.T) {
	err := &OriginValidationError{
		Origin:      "http://evil.com",
		Reason:      "not in allowed list",
		Remediation: "add origin to configuration",
	}

	expectedError := "invalid origin 'http://evil.com': not in allowed list; add origin to configuration"
	assert.Equal(t, expectedError, err.Error())
}

func TestOriginValidationError_NoRemediation(t *testing.T) {
	err := &OriginValidationError{
		Origin:      "*",
		Reason:      "wildcard not allowed",
		Remediation: "",
	}

	expectedError := "invalid origin '*': wildcard not allowed"
	assert.Equal(t, expectedError, err.Error())
}

func TestStreamConfig_Integration(t *testing.T) {
	// Test that StreamConfig properly integrates with app config
	appCfg := &config.Config{
		AuditStreamAllowedOrigins: "https://example.com,*.app.example.com,http://localhost:3000",
	}

	streamCfg := StreamConfigFromAppConfig(appCfg)

	assert.NotNil(t, streamCfg)
	assert.Equal(t, []string{"https://example.com", "*.app.example.com", "http://localhost:3000"}, streamCfg.AllowedOrigins)
	assert.True(t, streamCfg.EnableSecurityLogging)
	assert.Equal(t, 1024*64, streamCfg.MaxMessageSize)
}

// Benchmark tests
func BenchmarkNormalizeOrigin(b *testing.B) {
	origins := []string{
		"https://example.com",
		"HTTP://EXAMPLE.COM:443",
		"  http://localhost:3000  ",
		"https://app.example.com/path?query=value",
	}

	for i := 0; i < b.N; i++ {
		for _, origin := range origins {
			NormalizeOrigin(origin)
		}
	}
}

func BenchmarkIsOriginAllowed(b *testing.B) {
	allowedOrigins := []string{"https://example.com", "*.app.example.com", "http://localhost:3000"}
	testOrigins := []string{
		"https://example.com",
		"https://app.example.com",
		"https://evil.com",
	}

	for i := 0; i < b.N; i++ {
		for _, origin := range testOrigins {
			IsOriginAllowed(origin, allowedOrigins)
		}
	}
}
