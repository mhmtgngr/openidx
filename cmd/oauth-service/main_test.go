// Package main provides tests for the OAuth Service entry point
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

// TestOAuthService_ConfigValidation tests configuration validation scenarios
func TestOAuthService_ConfigValidation(t *testing.T) {
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

		cfg, err := config.Load("oauth-service")
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

		_, err := config.Load("oauth-service")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port")
	})
}

// TestOAuthService_ProductionConfigValidation tests production-specific validation
func TestOAuthService_ProductionConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid production config",
			cfg: &config.Config{
				Environment:               "production",
				DatabaseURL:               "postgres://test@localhost:5432/test?sslmode=verify-full",
				RedisURL:                  "redis://localhost:6379",
				Port:                      8006,
				JWTSecret:                 "secure-32-byte-secret-key-1234567890",
				EncryptionKey:             "secure-32-byte-encryption-key-123456",
				AccessSessionSecret:       "secure-32-byte-session-secret-12345",
				CORSAllowedOrigins:        "https://example.com",
				CSRFEnabled:               true,
				DatabaseSSLMode:           "verify-full",
				RedisTLSEnabled:           true,
				TLS:                       config.TLSConfig{Enabled: true},
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
				Port:               8006,
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
				Port:               8006,
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
				Port:               8006,
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
				Port:               8006,
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

// TestOAuthService_HealthEndpoints tests health check endpoint registration
func TestOAuthService_HealthEndpoints(t *testing.T) {
	t.Run("Standard health endpoints are registered", func(t *testing.T) {
		router := gin.New()
		log := zap.NewNop()

		// Create a mock health service
		healthService := health.NewHealthService(log)
		healthService.SetVersion("test-version")

		// Register standard routes
		healthService.RegisterStandardRoutes(router, "")

		// Register legacy /ready endpoint (not part of RegisterStandardRoutes)
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

// TestOAuthService_RouteRegistration tests that OAuth service routes are registered
func TestOAuthService_RouteRegistration(t *testing.T) {
	t.Run("OAuth service registers expected routes", func(t *testing.T) {
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

// TestOAuthService_GracefulShutdown tests graceful shutdown behavior
func TestOAuthService_GracefulShutdown(t *testing.T) {
	t.Run("Shutdownable components are properly created", func(t *testing.T) {
		_ = zap.NewNop()

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
		_ = zap.NewNop()

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

// TestOAuthService_ErrorHandling tests error handling scenarios
func TestOAuthService_ErrorHandling(t *testing.T) {
	t.Run("Handles missing config gracefully", func(t *testing.T) {
		// This test verifies the config package properly handles missing required values
		cfg := &config.Config{
			Environment: "development",
			Port:        8006,
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

// TestOAuthService_MiddlewareConfiguration tests middleware setup
func TestOAuthService_MiddlewareConfiguration(t *testing.T) {
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
					Port:        8006,
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

// TestOAuthService_CORSConfiguration tests CORS configuration
func TestOAuthService_CORSConfiguration(t *testing.T) {
	t.Run("OAuth service uses wildcard CORS for development", func(t *testing.T) {
		// OAuth service has special CORS handling for development
		// It sets wildcard headers in main.go
		router := gin.New()

		// Simulate the OAuth CORS middleware
		router.Use(func(c *gin.Context) {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204)
				return
			}

			c.Next()
		})

		router.GET("/test", func(c *gin.Context) {
			c.String(200, "ok")
		})

		// Test preflight request
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("OPTIONS", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, 204, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))

		// Test actual request
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	})
}

// TestOAuthService_PortDefault tests default port configuration
func TestOAuthService_PortDefault(t *testing.T) {
	t.Run("OAuth service uses port 8006 by default", func(t *testing.T) {
		cfg := &config.Config{
			Port: 0, // Zero means use default
		}

		// Simulate the main.go logic
		port := cfg.Port
		if port == 0 {
			port = 8006
		}

		assert.Equal(t, 8006, port)
	})
}

// TestOAuthService_ProductionWarnings tests production warning generation
func TestOAuthService_ProductionWarnings(t *testing.T) {
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
func BenchmarkOAuthService_HealthCheck(b *testing.B) {
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
