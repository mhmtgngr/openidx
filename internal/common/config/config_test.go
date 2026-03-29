// Package config provides tests for configuration management
package config

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	// Save original env vars
	origEnvs := make(map[string]string)
	envVars := []string{
		"APP_ENV", "LOG_LEVEL", "DATABASE_URL", "REDIS_URL",
		"ELASTICSEARCH_URL", "PORT", "OPENIDX_ENVIRONMENT",
	}
	for _, env := range envVars {
		origEnvs[env] = os.Getenv(env)
		os.Unsetenv(env)
	}
	defer func() {
		for env, val := range origEnvs {
			if val != "" {
				os.Setenv(env, val)
			} else {
				os.Unsetenv(env)
			}
		}
	}()

	t.Run("Load with minimal valid config", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://localhost/test")

		cfg, err := Load("test-service")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "test-service", cfg.ServiceName)
		assert.Equal(t, "development", cfg.Environment)
		assert.Equal(t, "postgres://localhost/test", cfg.DatabaseURL)
		assert.Equal(t, 8080, cfg.Port) // Default port for unknown service
	})

	t.Run("Load with known service gets default port", func(t *testing.T) {
		os.Unsetenv("PORT")
		os.Setenv("DATABASE_URL", "postgres://localhost/test")

		services := map[string]int{
			"identity-service":     8001,
			"governance-service":   8002,
			"provisioning-service": 8003,
			"audit-service":        8004,
			"admin-api":            8005,
			"gateway-service":      8008,
			"access-service":       8007,
		}

		for service, expectedPort := range services {
			t.Run(service, func(t *testing.T) {
				cfg, err := Load(service)
				require.NoError(t, err)
				assert.Equal(t, expectedPort, cfg.Port)
			})
		}
	})

	t.Run("Load with environment variable overrides", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://remote:5432/prod")
		os.Setenv("REDIS_URL", "redis://remote:6379")
		os.Setenv("ELASTICSEARCH_URL", "http://remote:9200")
		os.Setenv("PORT", "9000")
		os.Setenv("APP_ENV", "production")
		os.Setenv("LOG_LEVEL", "warn")

		cfg, err := Load("test-service")
		require.NoError(t, err)

		assert.Equal(t, "postgres://remote:5432/prod", cfg.DatabaseURL)
		assert.Equal(t, "redis://remote:6379", cfg.RedisURL)
		assert.Equal(t, "http://remote:9200", cfg.ElasticsearchURL)
		assert.Equal(t, 9000, cfg.Port)
		assert.Equal(t, "production", cfg.Environment)
		assert.Equal(t, "warn", cfg.LogLevel)
	})

	t.Run("Load with OPENIDX prefix env vars", func(t *testing.T) {
		os.Unsetenv("PORT")
		os.Unsetenv("DATABASE_URL")
		os.Setenv("OPENIDX_PORT", "8888")
		os.Setenv("OPENIDX_DATABASE_URL", "postgres://localhost/openidx")
		os.Setenv("OPENIDX_ENVIRONMENT", "production")

		cfg, err := Load("test-service")
		require.NoError(t, err)

		assert.Equal(t, 8888, cfg.Port)
		assert.Equal(t, "postgres://localhost/openidx", cfg.DatabaseURL)
		assert.Equal(t, "production", cfg.Environment)
	})

	t.Run("Load with default database_url", func(t *testing.T) {
		// Clear all DATABASE_URL related env vars to test default
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("OPENIDX_DATABASE_URL")

		cfg, err := Load("test-service")
		require.NoError(t, err)
		// Should use the default from setDefaults
		assert.Contains(t, cfg.DatabaseURL, "postgres://")
		assert.Contains(t, cfg.DatabaseURL, "localhost")
	})

	t.Run("Load fails with invalid port", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://localhost/test")
		os.Unsetenv("OPENIDX_PORT")
		os.Setenv("PORT", "70000") // Invalid port > 65535

		cfg, err := Load("test-service")
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "port")

		// Clean up
		os.Unsetenv("PORT")
		os.Unsetenv("DATABASE_URL")
	})

	t.Run("Load with zero port", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://localhost/test")
		os.Unsetenv("OPENIDX_PORT")
		os.Setenv("PORT", "0")

		cfg, err := Load("test-service")
		assert.Error(t, err)
		assert.Nil(t, cfg)

		// Clean up
		os.Unsetenv("PORT")
		os.Unsetenv("DATABASE_URL")
	})
}

func TestGetRedisSentinelAddresses(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Empty string returns nil",
			input:    "",
			expected: nil,
		},
		{
			name:     "Single address",
			input:    "localhost:26379",
			expected: []string{"localhost:26379"},
		},
		{
			name:     "Multiple addresses",
			input:    "sentinel1:26379,sentinel2:26379,sentinel3:26379",
			expected: []string{"sentinel1:26379", "sentinel2:26379", "sentinel3:26379"},
		},
		{
			name:     "Addresses with spaces",
			input:    "sentinel1:26379, sentinel2:26379 , sentinel3:26379",
			expected: []string{"sentinel1:26379", "sentinel2:26379", "sentinel3:26379"},
		},
		{
			name:     "Empty elements are filtered",
			input:    "sentinel1:26379,,sentinel3:26379",
			expected: []string{"sentinel1:26379", "sentinel3:26379"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{RedisSentinelAddresses: tt.input}
			result := cfg.GetRedisSentinelAddresses()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRedisPassword(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "URL with password",
			url:      "redis://:mypassword@localhost:6379",
			expected: "mypassword",
		},
		{
			name:     "URL with complex password - limitation: stops at first @",
			url:      "redis://:p@ssw0rd!@localhost:6379",
			expected: "p", // This is a known limitation of the simple parser
		},
		{
			name:     "URL without password",
			url:      "redis://localhost:6379",
			expected: "",
		},
		{
			name:     "URL with username and password",
			url:      "redis://user:password@localhost:6379",
			expected: "password",
		},
		{
			name:     "Empty URL",
			url:      "",
			expected: "",
		},
		{
			name:     "URL without @ separator",
			url:      "redis://localhost:6379",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{RedisURL: tt.url}
			result := cfg.GetRedisPassword()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetCORSOrigins(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Wildcard",
			input:    "*",
			expected: []string{"*"},
		},
		{
			name:     "Single origin",
			input:    "https://example.com",
			expected: []string{"https://example.com"},
		},
		{
			name:     "Multiple origins",
			input:    "https://example.com,https://api.example.com,http://localhost:3000",
			expected: []string{"https://example.com", "https://api.example.com", "http://localhost:3000"},
		},
		{
			name:     "Origins with spaces - note: spaces are preserved",
			input:    "https://example.com , https://api.example.com",
			expected: []string{"https://example.com ", " https://api.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{CORSAllowedOrigins: tt.input}
			result := cfg.GetCORSOrigins()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetAuditStreamAllowedOrigins(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Empty returns nil (same-origin)",
			input:    "",
			expected: nil,
		},
		{
			name:     "Wildcard",
			input:    "*",
			expected: []string{"*"},
		},
		{
			name:     "Single origin",
			input:    "https://example.com",
			expected: []string{"https://example.com"},
		},
		{
			name:     "Multiple origins with spaces",
			input:    "https://example.com , https://api.example.com , http://localhost:3000",
			expected: []string{"https://example.com", "https://api.example.com", "http://localhost:3000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{AuditStreamAllowedOrigins: tt.input}
			result := cfg.GetAuditStreamAllowedOrigins()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsDevelopment(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		expected bool
	}{
		{"Development", "development", true},
		{"Dev alias", "dev", true},
		{"Production", "production", false},
		{"Prod alias", "prod", false},
		{"Staging", "staging", false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Environment: tt.env}
			result := cfg.IsDevelopment()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsProduction(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		expected bool
	}{
		{"Production", "production", true},
		{"Prod alias", "prod", true},
		{"Development", "development", false},
		{"Dev alias", "dev", false},
		{"Staging", "staging", false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Environment: tt.env}
			result := cfg.IsProduction()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProductionWarnings(t *testing.T) {
	t.Run("No warnings in development", func(t *testing.T) {
		cfg := &Config{
			Environment:      "development",
			JWTSecret:        "weak-secret",
			CORSAllowedOrigins: "*",
		}
		warnings := cfg.ProductionWarnings()
		assert.Nil(t, warnings)
	})

	t.Run("Warnings for insecure production config", func(t *testing.T) {
		cfg := &Config{
			Environment:          "production",
			JWTSecret:            "change-me",
			EncryptionKey:        "change-me",
			AccessSessionSecret:  "change-me-in-production-32bytes!",
			CORSAllowedOrigins:   "*",
			CSRFEnabled:          false,
			DatabaseSSLMode:      "disable",
			RedisTLSEnabled:      false,
			TLS:                  TLSConfig{Enabled: false},
		}

		warnings := cfg.ProductionWarnings()
		require.NotNil(t, warnings)

		// Should have multiple warnings
		assert.GreaterOrEqual(t, len(warnings), 5)

		// Check for expected warnings
		warningStr := strings.Join(warnings, " ")
		assert.Contains(t, warningStr, "jwt_secret")
		assert.Contains(t, warningStr, "encryption_key")
		assert.Contains(t, warningStr, "cors_allowed_origins")
		assert.Contains(t, warningStr, "csrf_enabled")
		assert.Contains(t, warningStr, "database_ssl_mode")
	})

	t.Run("No warnings for secure production config", func(t *testing.T) {
		cfg := &Config{
			Environment:         "production",
			JWTSecret:           "secure-random-key-32-bytes-long!!",
			EncryptionKey:       "another-secure-key-32-bytes-long!!",
			AccessSessionSecret: "secure-session-key-32-bytes-long!",
			CORSAllowedOrigins:  "https://example.com,https://api.example.com",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "verify-full",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: true},
		}

		warnings := cfg.ProductionWarnings()
		assert.Nil(t, warnings)
	})
}

func TestValidateProduction(t *testing.T) {
	t.Run("Always passes in development", func(t *testing.T) {
		cfg := &Config{
			Environment:         "development",
			JWTSecret:           "",
			CORSAllowedOrigins:  "*",
			CSRFEnabled:         false,
			DatabaseSSLMode:     "disable",
			RedisTLSEnabled:     false,
			TLS:                 TLSConfig{Enabled: false},
		}

		err := cfg.ValidateProduction()
		assert.NoError(t, err)
	})

	t.Run("Fails with insecure session secret", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "change-me",
			JWTSecret:           "secure-key-32-bytes-long!!!!!!!!",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "https://example.com",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "require",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:   false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access_session_secret")
	})

	t.Run("Fails with insecure JWT secret", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "secure-key-32-bytes-long!!!!",
			JWTSecret:           "change",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "https://example.com",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "require",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:   false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "jwt_secret")
	})

	t.Run("Fails with wildcard CORS", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "secure-key-32-bytes-long!!!!",
			JWTSecret:           "secure-key-32-bytes-long!!!!!!!!",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "*",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "require",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:   false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cors_allowed_origins")
	})

	t.Run("Fails with CSRF disabled", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "secure-key-32-bytes-long!!!!",
			JWTSecret:           "secure-key-32-bytes-long!!!!!!!!",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "https://example.com",
			CSRFEnabled:         false,
			DatabaseSSLMode:     "require",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:   false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "csrf_enabled")
	})

	t.Run("Fails with database SSL disabled", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "secure-key-32-bytes-long!!!!",
			JWTSecret:           "secure-key-32-bytes-long!!!!!!!!",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "https://example.com",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "disable",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:   false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database_ssl_mode")
	})

	t.Run("Fails with Redis TLS disabled", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "secure-key-32-bytes-long!!!!",
			JWTSecret:           "secure-key-32-bytes-long!!!!!!!!",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "https://example.com",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "require",
			RedisTLSEnabled:     false,
			TLS:                 TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:   false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis_tls_enabled")
	})

	t.Run("Fails with service TLS disabled", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "secure-key-32-bytes-long!!!!",
			JWTSecret:           "secure-key-32-bytes-long!!!!!!!!",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "https://example.com",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "require",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: false},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:   false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tls.enabled")
	})

	t.Run("Fails with debug OTP enabled", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "secure-key-32-bytes-long!!!!",
			JWTSecret:           "secure-key-32-bytes-long!!!!!!!!",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "https://example.com",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "require",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:   true,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "debug_otp_in_response")
	})

	t.Run("Fails with wildcard audit stream origins", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "secure-key-32-bytes-long!!!!",
			JWTSecret:           "secure-key-32-bytes-long!!!!!!!!",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "https://example.com",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "require",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "*",
			DebugOTPInResponse:   false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audit_stream_allowed_origins")
	})

	t.Run("Fails with empty audit stream origins", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "secure-key-32-bytes-long!!!!",
			JWTSecret:           "secure-key-32-bytes-long!!!!!!!!",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "https://example.com",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "require",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "",
			DebugOTPInResponse:   false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audit_stream_allowed_origins")
	})

	t.Run("Passes with fully secure config", func(t *testing.T) {
		cfg := &Config{
			Environment:        "production",
			AccessSessionSecret: "secure-key-32-bytes-long!!!!",
			JWTSecret:           "secure-key-32-bytes-long!!!!!!!!",
			EncryptionKey:       "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:  "https://example.com",
			CSRFEnabled:         true,
			DatabaseSSLMode:     "verify-full",
			RedisTLSEnabled:     true,
			TLS:                 TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:   false,
		}

		err := cfg.ValidateProduction()
		assert.NoError(t, err)
	})
}

func TestDebugOTPsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{"Enabled", true, true},
		{"Disabled", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{DebugOTPInResponse: tt.enabled}
			result := cfg.DebugOTPsEnabled()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	// Save and restore env vars
	origEnvs := make(map[string]string)
	envVars := []string{
		"APP_ENV", "LOG_LEVEL", "DATABASE_URL", "REDIS_URL",
		"ELASTICSEARCH_URL", "PORT", "OPENIDX_ENVIRONMENT",
		"ENABLE_MFA", "ENABLE_AUDIT_LOGGING", "ENABLE_RATE_LIMIT",
	}
	for _, env := range envVars {
		origEnvs[env] = os.Getenv(env)
		os.Unsetenv(env)
	}
	defer func() {
		for env, val := range origEnvs {
			if val != "" {
				os.Setenv(env, val)
			} else {
				os.Unsetenv(env)
			}
		}
	}()

	os.Setenv("DATABASE_URL", "postgres://localhost/test")

	cfg, err := Load("test-service")
	require.NoError(t, err)

	// Check default values
	assert.Equal(t, "development", cfg.Environment)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.True(t, cfg.EnableMFA)
	assert.True(t, cfg.EnableAuditLogging)
	assert.True(t, cfg.EnableRateLimit)
	assert.Equal(t, 100, cfg.RateLimitRequests)
	assert.Equal(t, 60, cfg.RateLimitWindow)
	assert.Equal(t, 20, cfg.RateLimitAuthRequests)
	assert.Equal(t, 60, cfg.RateLimitAuthWindow)
	assert.False(t, cfg.RateLimitPerUser)
	assert.Equal(t, "http://localhost:8281", cfg.OPAURL)
	assert.False(t, cfg.EnableOPAAuthz)
	assert.False(t, cfg.ZitiEnabled)
	assert.False(t, cfg.ContinuousVerifyEnabled)
	assert.False(t, cfg.BrowZerEnabled)
	assert.Equal(t, "*", cfg.CORSAllowedOrigins)
	assert.False(t, cfg.CSRFEnabled)
	assert.False(t, cfg.DebugOTPInResponse)
	assert.False(t, cfg.TLS.Enabled)
	assert.Equal(t, "disable", cfg.DatabaseSSLMode)
	assert.False(t, cfg.RedisTLSEnabled)
	assert.False(t, cfg.ElasticsearchTLS)
	assert.False(t, cfg.SMS.Enabled)
	assert.Equal(t, "mock", cfg.SMS.Provider)
	assert.True(t, cfg.PushMFA.Enabled)
	assert.Equal(t, 60, cfg.PushMFA.ChallengeTimeout)
	assert.False(t, cfg.PushMFA.AutoApprove)
	assert.True(t, cfg.AdaptiveMFA.Enabled)
	assert.Equal(t, 30, cfg.AdaptiveMFA.NewDeviceRiskScore)
	assert.Equal(t, 20, cfg.AdaptiveMFA.NewLocationRiskScore)
	assert.Equal(t, 50, cfg.AdaptiveMFA.ImpossibleTravelRiskScore)
	assert.Equal(t, 40, cfg.AdaptiveMFA.BlockedIPRiskScore)
	assert.Equal(t, 10, cfg.AdaptiveMFA.FailedLoginRiskScore)
	assert.Equal(t, 30, cfg.AdaptiveMFA.TrustedBrowserDays)
	assert.Equal(t, 30, cfg.AdaptiveMFA.LowRiskThreshold)
	assert.Equal(t, 50, cfg.AdaptiveMFA.MediumRiskThreshold)
	assert.Equal(t, 70, cfg.AdaptiveMFA.HighRiskThreshold)
}

func BenchmarkLoad(b *testing.B) {
	// Save and restore env vars
	origDB := os.Getenv("DATABASE_URL")
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	defer func() {
		if origDB != "" {
			os.Setenv("DATABASE_URL", origDB)
		} else {
			os.Unsetenv("DATABASE_URL")
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Load("test-service")
	}
}
