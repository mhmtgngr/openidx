// Package gateway provides configuration tests for the gateway service
package gateway

import (
	"os"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	t.Run("Returns default configuration values", func(t *testing.T) {
		cfg := DefaultConfig()

		assert.Equal(t, 8500, cfg.Port)
		assert.NotEmpty(t, cfg.Services)
		assert.Equal(t, "http://localhost:8501", cfg.Services["identity"])
		assert.Equal(t, "http://localhost:8502", cfg.Services["oauth"])
		assert.Equal(t, "http://localhost:8503", cfg.Services["governance"])
		assert.Equal(t, "http://localhost:8504", cfg.Services["audit"])
		assert.Equal(t, "http://localhost:8505", cfg.Services["admin"])
		assert.Equal(t, "http://localhost:8506", cfg.Services["risk"])
		assert.NotEmpty(t, cfg.JWKSURL)
		assert.True(t, cfg.EnableRateLimit)
		assert.Equal(t, 100, cfg.RateLimitConfig.RequestsPerMinute)
		assert.Equal(t, 20, cfg.RateLimitConfig.AuthRequestsPerMinute)
		assert.Equal(t, 60, cfg.RateLimitConfig.WindowSeconds)
		assert.Equal(t, 10, cfg.RateLimitConfig.BurstSize)
		assert.NotEmpty(t, cfg.AllowedOrigins)
		assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
		assert.Equal(t, 30*time.Second, cfg.ShutdownTimeout)
	})
}

func TestLoadConfig(t *testing.T) {
	t.Run("Loads default config when no env vars set", func(t *testing.T) {
		// Unset any existing env vars
		unsetEnvVars := []string{
			"GATEWAY_PORT", "OAUTH_JWKS_URL", "IDENTITY_SERVICE_URL",
			"OAUTH_SERVICE_URL", "CORS_ALLOWED_ORIGINS", "ENABLE_RATE_LIMIT",
		}
		for _, env := range unsetEnvVars {
			os.Unsetenv(env)
		}

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, 8500, cfg.Port)
	})

	t.Run("Overrides port from environment", func(t *testing.T) {
		os.Setenv("GATEWAY_PORT", "9000")
		defer os.Unsetenv("GATEWAY_PORT")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, 9000, cfg.Port)
	})

	t.Run("Overrides JWKS URL from environment", func(t *testing.T) {
		os.Setenv("OAUTH_JWKS_URL", "http://custom-jwks:8080/jwks.json")
		defer os.Unsetenv("OAUTH_JWKS_URL")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, "http://custom-jwks:8080/jwks.json", cfg.JWKSURL)
	})

	t.Run("Overrides service URLs from environment", func(t *testing.T) {
		os.Setenv("IDENTITY_SERVICE_URL", "http://identity-prod:8001")
		os.Setenv("OAUTH_SERVICE_URL", "http://oauth-prod:8002")
		defer os.Unsetenv("IDENTITY_SERVICE_URL")
		defer os.Unsetenv("OAUTH_SERVICE_URL")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, "http://identity-prod:8001", cfg.Services["identity"])
		assert.Equal(t, "http://oauth-prod:8002", cfg.Services["oauth"])
	})

	t.Run("Overrides CORS origins from environment", func(t *testing.T) {
		os.Setenv("CORS_ALLOWED_ORIGINS", "https://example.com,https://app.example.com")
		defer os.Unsetenv("CORS_ALLOWED_ORIGINS")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, []string{"https://example.com", "https://app.example.com"}, cfg.AllowedOrigins)
	})

	t.Run("Overrides rate limit enabled from environment", func(t *testing.T) {
		os.Setenv("ENABLE_RATE_LIMIT", "false")
		defer os.Unsetenv("ENABLE_RATE_LIMIT")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.False(t, cfg.EnableRateLimit)
	})

	t.Run("Handles rate limit enabled as 1", func(t *testing.T) {
		os.Setenv("ENABLE_RATE_LIMIT", "1")
		defer os.Unsetenv("ENABLE_RATE_LIMIT")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.True(t, cfg.EnableRateLimit)
	})

	t.Run("Handles invalid port gracefully", func(t *testing.T) {
		os.Setenv("GATEWAY_PORT", "invalid")
		defer os.Unsetenv("GATEWAY_PORT")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, 8500, cfg.Port) // Should keep default
	})
}

func TestLoadConfigWithViper(t *testing.T) {
	t.Run("Loads config from viper", func(t *testing.T) {
		v := viper.New()
		v.Set("port", 8600)
		v.Set("jwks_url", "http://viper-jwks:8080/jwks.json")
		v.Set("enable_rate_limit", false)
		v.Set("rate_limit.requests_per_minute", 200)
		v.Set("rate_limit.auth_requests_per_minute", 50)
		v.Set("rate_limit.window_seconds", 120)
		v.Set("rate_limit.burst_size", 20)
		v.Set("allowed_origins", []string{"https://example.com"})
		v.Set("request_timeout", "45s")

		cfg, err := LoadConfigWithViper(v)
		require.NoError(t, err)

		assert.Equal(t, 8600, cfg.Port)
		assert.Equal(t, "http://viper-jwks:8080/jwks.json", cfg.JWKSURL)
		assert.False(t, cfg.EnableRateLimit)
		assert.Equal(t, 200, cfg.RateLimitConfig.RequestsPerMinute)
		assert.Equal(t, 50, cfg.RateLimitConfig.AuthRequestsPerMinute)
		assert.Equal(t, 120, cfg.RateLimitConfig.WindowSeconds)
		assert.Equal(t, 20, cfg.RateLimitConfig.BurstSize)
		assert.Equal(t, []string{"https://example.com"}, cfg.AllowedOrigins)
		assert.Equal(t, 45*time.Second, cfg.RequestTimeout)
	})

	t.Run("Loads services from viper", func(t *testing.T) {
		v := viper.New()
		v.Set("services.identity", "http://identity:8001")
		v.Set("services.oauth", "http://oauth:8002")

		cfg, err := LoadConfigWithViper(v)
		require.NoError(t, err)

		assert.Equal(t, "http://identity:8001", cfg.Services["identity"])
		assert.Equal(t, "http://oauth:8002", cfg.Services["oauth"])
	})

	t.Run("Uses defaults for unset viper values", func(t *testing.T) {
		v := viper.New()

		cfg, err := LoadConfigWithViper(v)
		require.NoError(t, err)

		assert.Equal(t, 8500, cfg.Port)
		assert.True(t, cfg.EnableRateLimit)
	})
}

func TestConfig_GetServiceURL(t *testing.T) {
	t.Run("Returns URL for existing service", func(t *testing.T) {
		cfg := DefaultConfig()
		url, err := cfg.GetServiceURL("identity")
		require.NoError(t, err)
		assert.Equal(t, "http://localhost:8501", url)
	})

	t.Run("Returns error for unknown service", func(t *testing.T) {
		cfg := DefaultConfig()
		url, err := cfg.GetServiceURL("unknown")
		assert.Error(t, err)
		assert.Empty(t, url)
		assert.Contains(t, err.Error(), "unknown")
	})
}

func TestConfig_GetJWTConfig(t *testing.T) {
	t.Run("Returns JWT config when JWKS URL is set", func(t *testing.T) {
		cfg := DefaultConfig()
		jwksURL, enabled := cfg.GetJWTConfig()
		assert.NotEmpty(t, jwksURL)
		assert.True(t, enabled)
	})

	t.Run("Returns disabled when JWKS URL is empty", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.JWKSURL = ""
		jwksURL, enabled := cfg.GetJWTConfig()
		assert.Empty(t, jwksURL)
		assert.False(t, enabled)
	})
}

func TestConfig_GetRateLimitConfig(t *testing.T) {
	t.Run("Returns rate limit config", func(t *testing.T) {
		cfg := DefaultConfig()
		rlCfg := cfg.GetRateLimitConfig()
		assert.Equal(t, 100, rlCfg.RequestsPerMinute)
		assert.Equal(t, 20, rlCfg.AuthRequestsPerMinute)
		assert.Equal(t, 60, rlCfg.WindowSeconds)
		assert.Equal(t, 10, rlCfg.BurstSize)
	})
}

func TestConfig_IsRateLimitEnabled(t *testing.T) {
	t.Run("Returns true when enabled", func(t *testing.T) {
		cfg := DefaultConfig()
		assert.True(t, cfg.IsRateLimitEnabled())
	})

	t.Run("Returns false when disabled", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.EnableRateLimit = false
		assert.False(t, cfg.IsRateLimitEnabled())
	})
}

func TestConfig_GetAllowedOrigins(t *testing.T) {
	t.Run("Returns configured origins", func(t *testing.T) {
		cfg := DefaultConfig()
		origins := cfg.GetAllowedOrigins()
		assert.NotEmpty(t, origins)
		assert.Contains(t, origins, "http://localhost:3000")
	})

	t.Run("Returns wildcard when no origins configured", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.AllowedOrigins = []string{}
		origins := cfg.GetAllowedOrigins()
		assert.Equal(t, []string{"*"}, origins)
	})
}
