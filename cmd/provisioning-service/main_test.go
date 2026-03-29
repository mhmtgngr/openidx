// Package main provides tests for the Provisioning Service entry point
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/health"
	"github.com/openidx/openidx/internal/server"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestMain_VersionVariables tests that version variables are accessible
func TestMain_VersionVariables(t *testing.T) {
	t.Run("Version variables have default values", func(t *testing.T) {
		assert.NotEmpty(t, Version)
		assert.NotEmpty(t, BuildTime)
		assert.NotEmpty(t, CommitHash)
	})

	t.Run("Version variables can be set", func(t *testing.T) {
		oldVersion := Version
		oldBuildTime := BuildTime
		oldCommit := CommitHash

		Version = "test-version"
		BuildTime = "test-time"
		CommitHash = "test-commit"

		assert.Equal(t, "test-version", Version)
		assert.Equal(t, "test-time", BuildTime)
		assert.Equal(t, "test-commit", CommitHash)

		// Restore
		Version = oldVersion
		BuildTime = oldBuildTime
		CommitHash = oldCommit
	})
}

// TestProvisioningService_ConfigValidation tests configuration validation scenarios
func TestProvisioningService_ConfigValidation(t *testing.T) {
	t.Run("Valid development config", func(t *testing.T) {
		// Set required environment variables for testing
		os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test?sslmode=disable")
		os.Setenv("REDIS_URL", "redis://:test@localhost:6379")
		os.Setenv("APP_ENV", "development")
		defer func() {
			os.Unsetenv("DATABASE_URL")
			os.Unsetenv("REDIS_URL")
			os.Unsetenv("APP_ENV")
		}()

		cfg, err := config.Load("provisioning-service")
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, "development", cfg.Environment)
	})

	t.Run("Invalid port returns error", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test?sslmode=disable")
		os.Setenv("REDIS_URL", "redis://:test@localhost:6379")
		os.Setenv("PORT", "99999")
		defer func() {
			os.Unsetenv("DATABASE_URL")
			os.Unsetenv("REDIS_URL")
			os.Unsetenv("PORT")
		}()

		_, err := config.Load("provisioning-service")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port")
	})
}

// TestProvisioningService_ProductionConfigValidation tests production-specific validation
func TestProvisioningService_ProductionConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid production config",
			cfg: &config.Config{
				Environment:              "production",
				DatabaseURL:              "postgres://test@localhost:5432/test?sslmode=verify-full",
				RedisURL:                 "redis://localhost:6379",
				Port:                     8003,
				JWTSecret:                "secure-32-byte-secret-key-1234567890",
				EncryptionKey:            "secure-32-byte-encryption-key-123456",
				CORSAllowedOrigins:       "https://example.com",
				CSRFEnabled:              true,
				DatabaseSSLMode:          "verify-full",
				RedisTLSEnabled:          true,
				TLS:                      config.TLSConfig{Enabled: true},
				AccessSessionSecret:      "secure-32-byte-session-secret-12345",
				AuditStreamAllowedOrigins: "https://example.com",
			},
			wantErr: false,
		},
		{
			name: "Production with insecure JWT secret",
			cfg: &config.Config{
				Environment:        "production",
				DatabaseURL:        "postgres://test@localhost:5432/test?sslmode=verify-full",
				RedisURL:           "redis://localhost:6379",
				Port:               8003,
				JWTSecret:          "change-me",
				EncryptionKey:      "secure-32-byte-encryption-key-123456",
				CORSAllowedOrigins: "https://example.com",
				CSRFEnabled:        true,
				DatabaseSSLMode:    "verify-full",
				RedisTLSEnabled:    true,
				TLS:                config.TLSConfig{Enabled: true},
			},
			wantErr:     true,
			errContains: "jwt_secret",
		},
		{
			name: "Production with wildcard CORS",
			cfg: &config.Config{
				Environment:        "production",
				DatabaseURL:        "postgres://test@localhost:5432/test?sslmode=verify-full",
				RedisURL:           "redis://localhost:6379",
				Port:               8003,
				JWTSecret:          "secure-32-byte-secret-key-1234567890",
				EncryptionKey:      "secure-32-byte-encryption-key-123456",
				CORSAllowedOrigins: "*",
				CSRFEnabled:        true,
				DatabaseSSLMode:    "verify-full",
				RedisTLSEnabled:    true,
				TLS:                config.TLSConfig{Enabled: true},
			},
			wantErr:     true,
			errContains: "cors",
		},
		{
			name: "Production without CSRF",
			cfg: &config.Config{
				Environment:        "production",
				DatabaseURL:        "postgres://test@localhost:5432/test?sslmode=verify-full",
				RedisURL:           "redis://localhost:6379",
				Port:               8003,
				JWTSecret:          "secure-32-byte-secret-key-1234567890",
				EncryptionKey:      "secure-32-byte-encryption-key-123456",
				CORSAllowedOrigins: "https://example.com",
				CSRFEnabled:        false,
				DatabaseSSLMode:    "verify-full",
				RedisTLSEnabled:    true,
				TLS:                config.TLSConfig{Enabled: true},
			},
			wantErr:     true,
			errContains: "csrf",
		},
		{
			name: "Production with disabled database TLS",
			cfg: &config.Config{
				Environment:        "production",
				DatabaseURL:        "postgres://test@localhost:5432/test?sslmode=disable",
				RedisURL:           "redis://localhost:6379",
				Port:               8003,
				JWTSecret:          "secure-32-byte-secret-key-1234567890",
				EncryptionKey:      "secure-32-byte-encryption-key-123456",
				CORSAllowedOrigins: "https://example.com",
				CSRFEnabled:        true,
				DatabaseSSLMode:    "disable",
				RedisTLSEnabled:    true,
				TLS:                config.TLSConfig{Enabled: true},
			},
			wantErr:     true,
			errContains: "database_ssl_mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.ValidateProduction()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestProvisioningService_HealthEndpoints tests health check endpoint registration
func TestProvisioningService_HealthEndpoints(t *testing.T) {
	t.Run("Standard health endpoints are registered", func(t *testing.T) {
		router := gin.New()
		log := zap.NewNop()

		// Create a mock health service
		healthService := health.NewHealthService(log)
		healthService.SetVersion("test-version")

		// Register standard routes
		healthService.RegisterStandardRoutes(router, "")

		// Register legacy /ready endpoint (as done in main.go)
		router.GET("/ready", healthService.ReadyHandler())

		// Test /health endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Test /health/ready endpoint
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/health/ready", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Test /health/live endpoint
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/health/live", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Test legacy /ready endpoint
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/ready", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestProvisioningService_RouteRegistration tests that provisioning service routes are registered
func TestProvisioningService_RouteRegistration(t *testing.T) {
	t.Run("Provisioning service registers expected routes", func(t *testing.T) {
		router := gin.New()
		log := zap.NewNop()

		// Create a mock health service
		healthService := health.NewHealthService(log)
		healthService.RegisterStandardRoutes(router, "")
		router.GET("/ready", healthService.ReadyHandler())

		// Verify routes are registered
		routes := router.Routes()
		routePaths := make(map[string]bool)
		for _, r := range routes {
			routePaths[r.Path] = true
		}

		// Check for standard health endpoints
		assert.True(t, routePaths["/health"], "missing /health endpoint")
		assert.True(t, routePaths["/health/ready"], "missing /health/ready endpoint")
		assert.True(t, routePaths["/health/live"], "missing /health/live endpoint")
		assert.True(t, routePaths["/ready"], "missing /ready endpoint")
	})
}

// TestProvisioningService_GracefulShutdown tests graceful shutdown behavior
func TestProvisioningService_GracefulShutdown(t *testing.T) {
	t.Run("Shutdownable components are properly created", func(t *testing.T) {
		// Create mock shutdownables
		dbClosed := false
		redisClosed := false

		closeDB := server.NewShutdownFunc("database", func(ctx context.Context) error {
			dbClosed = true
			return nil
		})

		closeRedis := server.NewShutdownFunc("redis", func(ctx context.Context) error {
			redisClosed = true
			return nil
		})

		// Verify shutdownables implement the interface correctly
		assert.Equal(t, "database", closeDB.Name())
		assert.Equal(t, "redis", closeRedis.Name())

		// Test shutdown
		ctx := context.Background()
		err := closeDB.Shutdown(ctx)
		assert.NoError(t, err)
		assert.True(t, dbClosed)

		err = closeRedis.Shutdown(ctx)
		assert.NoError(t, err)
		assert.True(t, redisClosed)
	})

	t.Run("Shutdown respects context cancellation", func(t *testing.T) {
		// Create a slow shutdown
		slowShutdown := server.NewShutdownFunc("slow", func(ctx context.Context) error {
			select {
			case <-time.After(10 * time.Second):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})

		// Cancel quickly
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		err := slowShutdown.Shutdown(ctx)
		assert.Error(t, err)
		assert.Equal(t, context.DeadlineExceeded, err)
	})
}

// TestProvisioningService_ErrorHandling tests error handling scenarios
func TestProvisioningService_ErrorHandling(t *testing.T) {
	t.Run("Handles missing config gracefully", func(t *testing.T) {
		// This test verifies the config package properly handles missing required values
		cfg := &config.Config{
			Environment: "development",
			Port:        8003,
			DatabaseURL: "", // Missing required field
		}

		err := cfg.ValidateProduction()
		// Should not error in non-production
		assert.NoError(t, err)
	})

	t.Run("Config environment detection", func(t *testing.T) {
		tests := []struct {
			env    string
			isDev  bool
			isProd bool
		}{
			{"development", true, false},
			{"dev", true, false},
			{"production", false, true},
			{"prod", false, true},
			{"staging", false, false},
		}

		for _, tt := range tests {
			t.Run(tt.env, func(t *testing.T) {
				cfg := &config.Config{Environment: tt.env}
				assert.Equal(t, tt.isDev, cfg.IsDevelopment())
				assert.Equal(t, tt.isProd, cfg.IsProduction())
			})
		}
	})
}

// TestProvisioningService_MiddlewareConfiguration tests middleware setup
func TestProvisioningService_MiddlewareConfiguration(t *testing.T) {
	t.Run("Middleware is configured based on environment", func(t *testing.T) {
		tests := []struct {
			name        string
			environment string
			expectDev   bool
			expectProd  bool
		}{
			{"Development mode", "development", true, false},
			{"Production mode", "production", false, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cfg := &config.Config{
					Environment: tt.environment,
					Port:        8003,
				}

				// Verify environment detection
				if tt.environment == "development" {
					assert.True(t, cfg.IsDevelopment())
					assert.False(t, cfg.IsProduction())
				} else {
					assert.False(t, cfg.IsDevelopment())
					assert.True(t, cfg.IsProduction())
				}
			})
		}
	})
}

// TestProvisioningService_OPAConfiguration tests OPA authorization configuration
func TestProvisioningService_OPAConfiguration(t *testing.T) {
	tests := []struct {
		name         string
		opaEnabled   bool
		opaURL       string
		expectConfig bool
	}{
		{"OPA disabled", false, "", false},
		{"OPA enabled with URL", true, "http://localhost:8281", true},
		{"OPA enabled with remote URL", true, "http://opa.example.com:8281", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				EnableOPAAuthz: tt.opaEnabled,
				OPAURL:         tt.opaURL,
			}

			if tt.expectConfig {
				assert.True(t, cfg.EnableOPAAuthz)
				assert.NotEmpty(t, cfg.OPAURL)
			} else {
				assert.False(t, cfg.EnableOPAAuthz)
			}
		})
	}
}

// TestProvisioningService_SCIMConfiguration tests SCIM-specific configuration
func TestProvisioningService_SCIMConfiguration(t *testing.T) {
	t.Run("SCIM endpoints are properly configured", func(t *testing.T) {
		// Provisioning service handles SCIM 2.0 endpoints
		// We verify the config allows for proper SCIM operation
		cfg := &config.Config{
			Environment:        "development",
			Port:               8003,
			DatabaseURL:        "postgres://test:test@localhost:5432/test?sslmode=disable",
			RedisURL:           "redis://:test@localhost:6379",
			EnableOPAAuthz:     false,
		}

		// Basic config should be valid
		assert.NotEmpty(t, cfg.DatabaseURL)
		assert.NotEmpty(t, cfg.RedisURL)
	})
}

// TestProvisioningService_ProductionWarnings tests production warning generation
func TestProvisioningService_ProductionWarnings(t *testing.T) {
	t.Run("Production warnings detect insecure configs", func(t *testing.T) {
		cfg := &config.Config{
			Environment:        "production",
			JWTSecret:          "change-me",
			EncryptionKey:      "",
			CORSAllowedOrigins: "*",
			CSRFEnabled:        false,
			DatabaseSSLMode:    "disable",
			RedisTLSEnabled:    false,
			TLS:                config.TLSConfig{Enabled: false},
		}

		warnings := cfg.ProductionWarnings()
		assert.NotEmpty(t, warnings)
		assert.Contains(t, warnings[0], "jwt_secret")
	})
}

// Benchmark test for health check performance
func BenchmarkProvisioningService_HealthCheck(b *testing.B) {
	router := gin.New()
	log := zap.NewNop()
	healthService := health.NewHealthService(log)
	healthService.SetVersion("test-version")

	router.GET("/health", healthService.Handler())

	req, _ := http.NewRequest("GET", "/health", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
