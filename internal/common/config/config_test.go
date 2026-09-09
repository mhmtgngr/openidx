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

	t.Run("AccessAPIRequireAuth defaults false and parses from env", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://localhost/test")
		os.Unsetenv("ACCESS_API_REQUIRE_AUTH")

		cfg, err := Load("test-service")
		require.NoError(t, err)
		assert.False(t, cfg.AccessAPIRequireAuth, "must default off so local dev is unchanged")

		os.Setenv("ACCESS_API_REQUIRE_AUTH", "true")
		cfg, err = Load("test-service")
		require.NoError(t, err)
		assert.True(t, cfg.AccessAPIRequireAuth, "ACCESS_API_REQUIRE_AUTH=true must force hard auth on the data API")

		os.Unsetenv("ACCESS_API_REQUIRE_AUTH")
		os.Unsetenv("DATABASE_URL")
	})

	t.Run("AdminAPIRequireAuth defaults false and parses from env", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://localhost/test")
		os.Unsetenv("ADMIN_API_REQUIRE_AUTH")

		cfg, err := Load("test-service")
		require.NoError(t, err)
		assert.False(t, cfg.AdminAPIRequireAuth, "must default off so local dev is unchanged")

		os.Setenv("ADMIN_API_REQUIRE_AUTH", "true")
		cfg, err = Load("test-service")
		require.NoError(t, err)
		assert.True(t, cfg.AdminAPIRequireAuth, "ADMIN_API_REQUIRE_AUTH=true must force hard auth on the admin surface")

		os.Unsetenv("ADMIN_API_REQUIRE_AUTH")
		os.Unsetenv("DATABASE_URL")
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

// TestSecureByDefaultSettings pins down the secure-by-default posture
// the P2.1 sweep adopted: csrf_enabled flips from false to true and the
// two TLS skip-verify escape hatches stay false. A future change that
// silently flips any of these to "more permissive" should fail loudly
// here rather than on a production deploy.
func TestSecureByDefaultSettings(t *testing.T) {
	// Save and clear interfering env vars so the assertions read
	// defaults, not whatever the runner happens to export.
	envVars := []string{
		"APP_ENV", "DATABASE_URL", "PORT", "OPENIDX_ENVIRONMENT",
		"CSRF_ENABLED", "REDIS_TLS_SKIP_VERIFY", "ZITI_INSECURE_SKIP_VERIFY",
		"DEBUG_OTP_IN_RESPONSE",
	}
	saved := make(map[string]string)
	for _, e := range envVars {
		saved[e] = os.Getenv(e)
		os.Unsetenv(e)
	}
	defer func() {
		for e, v := range saved {
			if v != "" {
				os.Setenv(e, v)
			} else {
				os.Unsetenv(e)
			}
		}
	}()

	os.Setenv("DATABASE_URL", "postgres://localhost/test")

	cfg, err := Load("test-service")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.True(t, cfg.CSRFEnabled, "csrf_enabled default = false; secure-by-default requires true")
	assert.False(t, cfg.RedisTLSSkipVerify, "redis_tls_skip_verify default flipped to true")
	assert.False(t, cfg.ZitiInsecureSkipVerify, "ziti_insecure_skip_verify default flipped to true")
	assert.False(t, cfg.DebugOTPInResponse, "debug_otp_in_response default flipped to true")
}

func TestAPISIXEdgeEnvBindings(t *testing.T) {
	envVars := []string{
		"DATABASE_URL", "APISIX_EDGE_ENABLED", "APISIX_ADMIN_URL",
		"APISIX_ADMIN_KEY", "APISIX_BOOTSTRAPPER_NODE",
	}
	saved := make(map[string]string)
	for _, e := range envVars {
		saved[e] = os.Getenv(e)
		os.Unsetenv(e)
	}
	defer func() {
		for e, v := range saved {
			if v != "" {
				os.Setenv(e, v)
			} else {
				os.Unsetenv(e)
			}
		}
	}()

	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("APISIX_EDGE_ENABLED", "true")
	os.Setenv("APISIX_ADMIN_URL", "http://apisix.example.com:9180")
	os.Setenv("APISIX_ADMIN_KEY", "super-secret-key")
	os.Setenv("APISIX_BOOTSTRAPPER_NODE", "10.0.0.1:8445")

	cfg, err := Load("test-service")
	require.NoError(t, err)

	assert.True(t, cfg.APISIXEdgeEnabled)
	assert.Equal(t, "http://apisix.example.com:9180", cfg.APISIXAdminURL)
	assert.Equal(t, "super-secret-key", cfg.APISIXAdminKey)
	assert.Equal(t, "10.0.0.1:8445", cfg.APISIXBootstrapperNode)
}

func TestRequireDeviceTrustForClientlessBinding(t *testing.T) {
	saved := os.Getenv("OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS")
	dburl := os.Getenv("DATABASE_URL")
	defer func() {
		if saved != "" {
			os.Setenv("OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS", saved)
		} else {
			os.Unsetenv("OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS")
		}
		if dburl != "" {
			os.Setenv("DATABASE_URL", dburl)
		} else {
			os.Unsetenv("DATABASE_URL")
		}
	}()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")

	os.Unsetenv("OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS")
	cfg, err := Load("test-service")
	require.NoError(t, err)
	assert.False(t, cfg.RequireDeviceTrustForClientless, "default must be false")

	os.Setenv("OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS", "true")
	cfg, err = Load("test-service")
	require.NoError(t, err)
	assert.True(t, cfg.RequireDeviceTrustForClientless)
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
			Environment:        "development",
			CORSAllowedOrigins: "*",
		}
		warnings := cfg.ProductionWarnings()
		assert.Nil(t, warnings)
	})

	t.Run("Warnings for insecure production config", func(t *testing.T) {
		cfg := &Config{
			Environment:         "production",
			EncryptionKey:       "change-me",
			AccessSessionSecret: "change-me-in-production-32bytes!",
			CORSAllowedOrigins:  "*",
			CSRFEnabled:         false,
			DatabaseSSLMode:     "disable",
			RedisTLSEnabled:     false,
			TLS:                 TLSConfig{Enabled: false},
		}

		warnings := cfg.ProductionWarnings()
		require.NotNil(t, warnings)

		// Should have multiple warnings
		assert.GreaterOrEqual(t, len(warnings), 5)

		// Check for expected warnings
		warningStr := strings.Join(warnings, " ")
		assert.Contains(t, warningStr, "encryption_key")
		assert.Contains(t, warningStr, "cors_allowed_origins")
		assert.Contains(t, warningStr, "csrf_enabled")
		assert.Contains(t, warningStr, "database_ssl_mode")
	})

	t.Run("No warnings for secure production config", func(t *testing.T) {
		cfg := &Config{
			Environment:         "production",
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

// productionBaseline is a config that PASSES ValidateProduction, so a case
// below can change one field and know the error it gets is about that field.
// Written once rather than copied per case: the cases added after it care about
// two settings each, and repeating fifteen unrelated ones around them hides
// which two.
func productionBaseline() *Config {
	return &Config{
		Environment:               "production",
		AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
		EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
		CORSAllowedOrigins:        "https://example.com",
		CSRFEnabled:               true,
		DatabaseSSLMode:           "require",
		RedisTLSEnabled:           true,
		TLS:                       TLSConfig{Enabled: true},
		AuditStreamAllowedOrigins: "https://example.com",
		DebugOTPInResponse:        false,
		VaultKEK:                  "vault-kek-32-bytes-long!!!!!!!!!",
		AuditChainSecret:          "audit-chain-secret-32-bytes!!!!!",
	}
}

func TestValidateProduction(t *testing.T) {
	t.Run("Always passes in development", func(t *testing.T) {
		cfg := &Config{
			Environment:        "development",
			CORSAllowedOrigins: "*",
			CSRFEnabled:        false,
			DatabaseSSLMode:    "disable",
			RedisTLSEnabled:    false,
			TLS:                TLSConfig{Enabled: false},
		}

		err := cfg.ValidateProduction()
		assert.NoError(t, err)
	})

	t.Run("Fails with insecure session secret", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "change-me",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access_session_secret")
	})

	t.Run("Fails with wildcard CORS", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "*",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cors_allowed_origins")
	})

	t.Run("Fails with CSRF disabled", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               false,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "csrf_enabled")
	})

	// PAM_REQUIRE_ZTNA=enforce is a promise with a half that is configuration
	// rather than code. Refusing a direct target hop is the process's decision;
	// the connect URL being overlay-only is the deployment's, and the setting
	// that expresses it is GUACAMOLE_ZITI_PUBLIC_URL. These two cases are the
	// ways an install can read "enforce" and leave that second leg open.
	t.Run("Fails when ZTNA is enforced with no overlay broker address", func(t *testing.T) {
		cfg := productionBaseline()
		cfg.PAMRequireZTNA = "enforce"
		cfg.GuacamolePublicURL = "https://guacamole.example.com"
		cfg.GuacamoleZitiPublicURL = ""

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "guacamole_ziti_public_url is empty")
	})

	t.Run("Fails when the overlay broker is published at the direct broker's address", func(t *testing.T) {
		cfg := productionBaseline()
		cfg.PAMRequireZTNA = "enforce"
		cfg.GuacamolePublicURL = "https://guacamole.example.com"
		cfg.GuacamoleZitiPublicURL = "https://guacamole.example.com"

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "equals guacamole_public_url")
	})

	t.Run("Passes when the overlay broker has its own address", func(t *testing.T) {
		cfg := productionBaseline()
		cfg.PAMRequireZTNA = "enforce"
		cfg.GuacamolePublicURL = "https://guacamole.example.com"
		cfg.GuacamoleZitiPublicURL = "https://guacamole.ziti"

		assert.NoError(t, cfg.ValidateProduction())
	})

	// And the gate is off by default, so an install that has not asked for this
	// is not held to it.
	t.Run("Says nothing about brokers when ZTNA is not enforced", func(t *testing.T) {
		cfg := productionBaseline()
		cfg.PAMRequireZTNA = "observe"
		cfg.GuacamoleZitiPublicURL = ""

		assert.NoError(t, cfg.ValidateProduction())
	})

	t.Run("Fails with database SSL disabled", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "disable",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database_ssl_mode")
	})

	t.Run("Fails with Redis TLS disabled", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           false,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis_tls_enabled")
	})

	t.Run("Fails with service TLS disabled", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: false},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tls.enabled")
	})

	t.Run("Fails with debug OTP enabled", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        true,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "debug_otp_in_response")
	})

	t.Run("Fails with wildcard audit stream origins", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "*",
			DebugOTPInResponse:        false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audit_stream_allowed_origins")
	})

	t.Run("Fails with empty audit stream origins", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "",
			DebugOTPInResponse:        false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audit_stream_allowed_origins")
	})

	t.Run("Fails when redis_tls_skip_verify is true", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			RedisTLSSkipVerify:        true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis_tls_skip_verify")
	})

	t.Run("Fails when ziti_insecure_skip_verify is true", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
			ZitiInsecureSkipVerify:    true,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ziti_insecure_skip_verify")
	})

	t.Run("Fails when Ziti enabled with default admin password", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
			ZitiEnabled:               true,
			ZitiAdminPassword:         defaultZitiAdminPassword,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ziti_admin_password")
	})

	t.Run("Fails when Guacamole configured with default admin password", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
			GuacamoleURL:              "http://guacamole:8080",
			GuacamoleAdminPassword:    defaultGuacamoleAdminPassword,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "guacamole_admin_password")
	})

	t.Run("Passes when Ziti disabled even with default password", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "verify-full",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
			VaultKEK:                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			AuditChainSecret:          "audit-chain-key-32-bytes-long!!!",
			ZitiEnabled:               false,
			ZitiAdminPassword:         defaultZitiAdminPassword,
		}

		err := cfg.ValidateProduction()
		assert.NoError(t, err)
	})

	t.Run("Passes with fully secure config", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "verify-full",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
			VaultKEK:                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			AuditChainSecret:          "audit-chain-key-32-bytes-long!!!",
		}

		err := cfg.ValidateProduction()
		assert.NoError(t, err)
	})

	// The product publishes, in four places, that it keeps a tamper-evident
	// HMAC hash-chain audit log. Without this secret the sealer does not run
	// and every audit row is unchained -- editable in the database with nothing
	// to show for it -- while the evidence package still makes the claim. A
	// documented control that is silently off is worse than an absent one.
	t.Run("Fails when the audit chain has no secret", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "verify-full",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			VaultKEK:                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audit_chain_secret")

		// And a placeholder is not a secret.
		cfg.AuditChainSecret = "CHANGE_ME_audit_chain_secret"
		err = cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audit_chain_secret")
	})

	// The effective sslmode is what pgx connects with — DATABASE_URL wins over
	// the standalone field, so a URL carrying sslmode=disable must be caught even
	// when database_ssl_mode says 'require' (the drift this fix closes).
	t.Run("Fails when DATABASE_URL sslmode=disable despite field=require", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseURL:               "postgres://u:p@db:5432/openidx?sslmode=disable",
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "sslmode")
	})

	t.Run("Passes when DATABASE_URL sslmode=require despite field=disable", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseURL:               "postgres://u:p@db:5432/openidx?sslmode=require",
			DatabaseSSLMode:           "disable",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
			VaultKEK:                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			AuditChainSecret:          "audit-chain-key-32-bytes-long!!!",
		}

		err := cfg.ValidateProduction()
		assert.NoError(t, err)
	})

	t.Run("Fails without an explicit vault KEK", func(t *testing.T) {
		cfg := &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "require",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
			// VaultKEK / VaultKEKs intentionally unset -> must fail in production.
		}

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "vault_kek")
	})
}

func TestValidateProduction_Elasticsearch(t *testing.T) {
	// Base is the "fully secure config" that ValidateProduction accepts as nil,
	// so these cases isolate the Elasticsearch credential rule.
	base := func() *Config {
		return &Config{
			Environment:               "production",
			AccessSessionSecret:       "secure-key-32-bytes-long!!!!",
			EncryptionKey:             "secure-key-32-bytes-long!!!!!!!!",
			CORSAllowedOrigins:        "https://example.com",
			CSRFEnabled:               true,
			DatabaseSSLMode:           "verify-full",
			RedisTLSEnabled:           true,
			TLS:                       TLSConfig{Enabled: true},
			AuditStreamAllowedOrigins: "https://example.com",
			DebugOTPInResponse:        false,
			VaultKEK:                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			AuditChainSecret:          "audit-chain-key-32-bytes-long!!!",
		}
	}

	t.Run("Passes when elasticsearch_url is unset", func(t *testing.T) {
		cfg := base()
		cfg.ElasticsearchURL = ""

		err := cfg.ValidateProduction()
		assert.NoError(t, err)
	})

	t.Run("Fails when elasticsearch_url is set but credentials are missing", func(t *testing.T) {
		cfg := base()
		cfg.ElasticsearchURL = "http://es:9200"

		err := cfg.ValidateProduction()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "elasticsearch")
	})

	t.Run("Passes when elasticsearch_url and credentials are set", func(t *testing.T) {
		cfg := base()
		cfg.ElasticsearchURL = "http://es:9200"
		cfg.ElasticsearchUsername = "elastic"
		cfg.ElasticsearchPassword = "x"

		err := cfg.ValidateProduction()
		assert.NoError(t, err)
	})
}

func TestEffectiveDatabaseSSLMode(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		field string
		want  string
	}{
		{"URL query form wins", "postgres://u:p@h/db?sslmode=verify-full", "disable", "verify-full"},
		{"URL disable wins over field", "postgres://u:p@h/db?sslmode=disable", "require", "disable"},
		{"DSN form", "host=h user=u dbname=db sslmode=require", "disable", "require"},
		{"empty URL falls back to field", "", "verify-ca", "verify-ca"},
		{"URL without sslmode falls back to field", "postgres://u:p@h/db", "require", "require"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{DatabaseURL: tt.url, DatabaseSSLMode: tt.field}
			assert.Equal(t, tt.want, c.effectiveDatabaseSSLMode())
		})
	}
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
	assert.True(t, cfg.EnableRateLimit)
	assert.Equal(t, 100, cfg.RateLimitRequests)
	assert.Equal(t, 60, cfg.RateLimitWindow)
	assert.Equal(t, 20, cfg.RateLimitAuthRequests)
	assert.Equal(t, 60, cfg.RateLimitAuthWindow)
	assert.False(t, cfg.RateLimitPerUser)
	assert.Equal(t, "http://localhost:8281", cfg.OPAURL)
	assert.False(t, cfg.EnableOPAAuthz)
	assert.False(t, cfg.ZitiEnabled)
	assert.True(t, cfg.ZitiReconcilerEnabled)
	assert.False(t, cfg.ContinuousVerifyEnabled)
	assert.False(t, cfg.BrowZerEnabled)
	assert.False(t, cfg.APISIXEdgeEnabled)
	assert.Equal(t, "http://127.0.0.1:9180", cfg.APISIXAdminURL)
	assert.Equal(t, "127.0.0.1:8445", cfg.APISIXBootstrapperNode)
	assert.Equal(t, "*", cfg.CORSAllowedOrigins)
	// Secure-by-default after P2.1: CSRF is on by default and the
	// dev-loop escape hatches (DebugOTPInResponse, skip-verify) are off.
	assert.True(t, cfg.CSRFEnabled)
	assert.False(t, cfg.DebugOTPInResponse)
	assert.False(t, cfg.RedisTLSSkipVerify)
	assert.False(t, cfg.ZitiInsecureSkipVerify)
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

func TestZitiReconcilerFlagDefaultsTrue(t *testing.T) {
	os.Unsetenv("ZITI_RECONCILER")
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	defer os.Unsetenv("DATABASE_URL")
	c, err := Load("test-service")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.ZitiReconcilerEnabled {
		t.Fatalf("ZitiReconcilerEnabled should default to true")
	}
}

func TestZitiReconcilerFlagCanBeDisabled(t *testing.T) {
	os.Setenv("ZITI_RECONCILER", "false")
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	defer os.Unsetenv("ZITI_RECONCILER")
	defer os.Unsetenv("DATABASE_URL")
	c, err := Load("test-service")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ZitiReconcilerEnabled {
		t.Fatalf("ZITI_RECONCILER=false should disable the reconciler")
	}
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

func TestListenAddrDefaultsToAllInterfaces(t *testing.T) {
	c := &Config{Port: 8001}
	if got := c.ListenAddr(); got != ":8001" {
		t.Errorf("ListenAddr() = %q, want \":8001\"", got)
	}
}

func TestListenAddrHonorsBindAddr(t *testing.T) {
	c := &Config{Port: 8001, BindAddr: "127.0.0.1"}
	if got := c.ListenAddr(); got != "127.0.0.1:8001" {
		t.Errorf("ListenAddr() = %q, want \"127.0.0.1:8001\"", got)
	}
}

// ValidateDarkModeBind must fail closed: a dark tier with a public bind is a
// false "overlay-only" posture, so startup must refuse it; loopback (and the
// no-dark default) must pass.
func TestValidateDarkModeBind(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"no dark tier, empty bind (default) is fine", Config{}, false},
		{"no dark tier, public bind is fine", Config{BindAddr: "0.0.0.0"}, false},
		{"dark tier1 + loopback is fine", Config{DarkModeTier1: true, BindAddr: "127.0.0.1"}, false},
		{"dark tier2 + ::1 is fine", Config{DarkModeTier2: true, BindAddr: "::1"}, false},
		{"dark tier1 + empty bind (all ifaces) fails", Config{DarkModeTier1: true}, true},
		{"dark tier1 + 0.0.0.0 fails", Config{DarkModeTier1: true, BindAddr: "0.0.0.0"}, true},
		{"dark tier2 + public ip fails", Config{DarkModeTier2: true, BindAddr: "192.168.1.5"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.ValidateDarkModeBind()
			if (err != nil) != c.wantErr {
				t.Errorf("ValidateDarkModeBind() err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestAccessAssignmentEnforceDefaultsOff(t *testing.T) {
	t.Setenv("ACCESS_ASSIGNMENT_ENFORCE", "")
	cfg, err := Load("test")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AccessAssignmentEnforce {
		t.Error("ACCESS_ASSIGNMENT_ENFORCE must default to false: the first deploy reports, it does not remove access")
	}

	t.Setenv("ACCESS_ASSIGNMENT_ENFORCE", "true")
	cfg, err = Load("test")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.AccessAssignmentEnforce {
		t.Error("ACCESS_ASSIGNMENT_ENFORCE=true must enable enforcement")
	}
}

// ValidateProduction checked secrets, TLS, CORS, CSRF and default passwords
// thoroughly, and not one enforcement flag. These two are the ones where the
// unsafe value is unambiguously wrong in production rather than a staging
// choice, so they are errors; the rest are reported by ReportModeGates.
func TestValidateProductionRejectsDevBypassAndMockSMS(t *testing.T) {
	base := func() *Config {
		c := &Config{Environment: "production"}
		c.AccessSessionSecret = "0123456789abcdef0123456789abcdef"
		c.EncryptionKey = "0123456789abcdef0123456789abcdef"
		c.VaultKEK = "0123456789abcdef0123456789abcdef"
		c.CORSAllowedOrigins = "https://console.example.test"
		return c
	}

	t.Run("dev admin bypass", func(t *testing.T) {
		c := base()
		c.DevAdminBypass = true
		err := c.ValidateProduction()
		if err == nil || !strings.Contains(err.Error(), "dev_admin_bypass") {
			t.Fatalf("DEV_ADMIN_BYPASS=true in production must be refused, got: %v", err)
		}
	})

	t.Run("mock SMS with SMS enabled", func(t *testing.T) {
		c := base()
		c.SMS.Enabled = true
		c.SMS.Provider = "mock"
		err := c.ValidateProduction()
		if err == nil || !strings.Contains(err.Error(), "mock") {
			t.Fatalf("an enabled mock SMS provider in production must be refused, got: %v", err)
		}
	})

	t.Run("mock SMS with SMS disabled is fine", func(t *testing.T) {
		c := base()
		c.SMS.Provider = "mock" // not enabled: nothing claims to send
		if err := c.ValidateProduction(); err != nil && strings.Contains(err.Error(), "mock") {
			t.Fatalf("a mock provider with SMS disabled sends nothing and claims nothing: %v", err)
		}
	})
}

// TestProductionRefusesALoopbackVendorDomain.
//
// access_proxy_domain is the host of every temporary vendor-access link. It
// defaults to "localhost", and the issuing code's own fallback for an empty
// value used to be browzer.localtest.me — a wildcard DNS service that resolves
// to 127.0.0.1 by design. Either way the link was issued, looked right in the
// console, and opened the RECIPIENT'S machine. The link is mailed out before
// anybody discovers that, which is why this is a boot refusal and not a warning.
func TestProductionRefusesALoopbackVendorDomain(t *testing.T) {
	base := func() *Config {
		c := &Config{Environment: "production"}
		c.AccessSessionSecret = "0123456789abcdef0123456789abcdef"
		c.EncryptionKey = "0123456789abcdef0123456789abcdef"
		c.VaultKEK = "0123456789abcdef0123456789abcdef"
		c.CORSAllowedOrigins = "https://console.example.test"
		return c
	}

	for _, domain := range []string{
		"localhost",            // the in-code default: nobody set this
		"LocalHost:8443",       // case and port do not change where it points
		"api.localhost",        // the RFC 6761 special-use suffix
		"browzer.localtest.me", // the fallback this replaced
		"localtest.me",
		"anything.nip.io", // the other wildcard-to-loopback service
		"127.0.0.1",
		"127.0.0.53", // the whole /8 is loopback, not just .1
		"[::1]",
		"::1",
		"0.0.0.0",          // a bind address is not a reachable name
		"::ffff:127.0.0.1", // the same loopback written as mapped IPv6
	} {
		t.Run(domain, func(t *testing.T) {
			c := base()
			c.AccessProxyDomain = domain
			err := c.ValidateProduction()
			if err == nil || !strings.Contains(err.Error(), "access_proxy_domain") {
				t.Fatalf("access_proxy_domain=%q must be refused in production: a vendor link "+
					"built from it opens the recipient's own machine. got: %v", domain, err)
			}
		})
	}

	// Deliberately permitted. This check names values that CANNOT work for an
	// outside party; it does not audit whether a real name is reachable, which
	// is a deployment fact this process cannot see.
	for _, domain := range []string{
		"", // refused at issuance instead — see tempAccessURL
		"access.example.com",
		"vendor-access.internal", // split-horizon DNS is a legitimate choice
		"198.51.100.7",
		"2001:db8::1",
	} {
		t.Run("allows "+domain, func(t *testing.T) {
			c := base()
			c.AccessProxyDomain = domain
			if err := c.ValidateProduction(); err != nil &&
				strings.Contains(err.Error(), "access_proxy_domain") {
				t.Fatalf("access_proxy_domain=%q must be allowed: %v", domain, err)
			}
		})
	}

	// Development is where a loopback value is the RIGHT one: the person opening
	// the link is at the same machine.
	dev := base()
	dev.Environment = "development"
	dev.AccessProxyDomain = "localhost"
	if err := dev.ValidateProduction(); err != nil {
		t.Fatalf("development must tolerate a loopback access_proxy_domain: %v", err)
	}
}

// The report-mode list is what makes "every authorization control is off" a
// visible fact rather than something an operator has to reconstruct from seven
// environment variables. An install with every gate open must list every gate.
func TestReportModeGatesNamesEveryOpenControl(t *testing.T) {
	c := &Config{} // every gate at its zero/default value: all report-mode
	open := c.ReportModeGates()
	for _, want := range []string{
		"ACCESS_ASSIGNMENT_ENFORCE",
		"ABAC_ENFORCE",
		"STEPUP_GATE",
		"ENABLE_OPA_AUTHZ",
		"PAM_SESSION_RISK_GATE",
		"POSTURE_DEVICE_TRUST_GATE",
		"ACCESS_API_REQUIRE_AUTH",
		"ADMIN_API_REQUIRE_AUTH",
	} {
		found := false
		for _, line := range open {
			if strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ReportModeGates() does not mention %s; an operator reading it would think that control is enforcing", want)
		}
	}

	// And a fully-enforcing install must report nothing, or the list is noise
	// nobody will read.
	full := &Config{
		AccessAssignmentEnforce: true,
		ABACEnforce:             "enforce",
		StepUpGate:              "enforce",
		EnableOPAAuthz:          true,
		PAMSessionRiskGate:      "enforce",
		PostureDeviceTrustGate:  "enforce",
		PAMRequireZTNA:          "enforce",
		AccessAPIRequireAuth:    true,
		AdminAPIRequireAuth:     true,
	}
	if got := full.ReportModeGates(); len(got) != 0 {
		t.Errorf("a fully-enforcing install still reports open gates: %v", got)
	}
}
