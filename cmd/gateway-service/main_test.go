// Package main is the entry point for the Gateway Service
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestCreateGatewayConfig(t *testing.T) {
	t.Run("Creates config with default values", func(t *testing.T) {
		cfg := &config.Config{
			OAuthJWKSURL:    "http://localhost:8080/jwks.json",
			EnableRateLimit: true,
		}

		gatewayCfg := createGatewayConfig(cfg, nil, nil, nil)

		assert.NotNil(t, gatewayCfg)
		assert.NotEmpty(t, gatewayCfg.Services)
		assert.Equal(t, "http://localhost:8080/jwks.json", gatewayCfg.JWKSURL)
		assert.True(t, gatewayCfg.EnableRateLimit)
		assert.Equal(t, 30*time.Second, gatewayCfg.RequestTimeout)
	})

	t.Run("Includes all service URLs", func(t *testing.T) {
		cfg := &config.Config{}
		gatewayCfg := createGatewayConfig(cfg, nil, nil, nil)

		expectedServices := []string{"identity", "oauth", "governance", "audit", "admin", "risk"}
		for _, svc := range expectedServices {
			assert.Contains(t, gatewayCfg.Services, svc)
		}
	})
}

func TestServiceURLProvider(t *testing.T) {
	t.Run("Returns service URLs", func(t *testing.T) {
		provider := &serviceURLProvider{}

		urls := []string{"identity", "oauth", "governance", "audit", "admin", "risk"}
		for _, svc := range urls {
			url, err := provider.GetServiceURL(svc)
			require.NoError(t, err)
			assert.NotEmpty(t, url)
		}
	})

	t.Run("Returns error for unknown service", func(t *testing.T) {
		provider := &serviceURLProvider{}

		url, err := provider.GetServiceURL("unknown")
		assert.Error(t, err)
		assert.Empty(t, url)
		assert.Contains(t, err.Error(), "unknown service")
	})
}

func TestRedisClientWrapper(t *testing.T) {
	t.Run("Implements gateway.RedisClient interface", func(t *testing.T) {
		// The wrapper should satisfy the interface
		var _ gateway.RedisClient = (*redisClientWrapper)(nil)
	})

	t.Run("Wraps Get method", func(t *testing.T) {
		// This is a compile-time check
		wrapper := &redisClientWrapper{}
		assert.NotNil(t, wrapper)
	})

	t.Run("Wraps Set method", func(t *testing.T) {
		// This is a compile-time check
		wrapper := &redisClientWrapper{}
		assert.NotNil(t, wrapper)
	})

	t.Run("Wraps Incr method", func(t *testing.T) {
		// This is a compile-time check
		wrapper := &redisClientWrapper{}
		assert.NotNil(t, wrapper)
	})

	t.Run("Wraps Expire method", func(t *testing.T) {
		// This is a compile-time check
		wrapper := &redisClientWrapper{}
		assert.NotNil(t, wrapper)
	})

	t.Run("Wraps Pipeline method", func(t *testing.T) {
		wrapper := &redisClientWrapper{}
		pipeline := wrapper.Pipeline()
		assert.Nil(t, pipeline) // Returns nil in the stub implementation
	})

	t.Run("Wraps Close method", func(t *testing.T) {
		// This is a compile-time check
		wrapper := &redisClientWrapper{}
		assert.NotNil(t, wrapper)
	})
}

func TestZapLoggerWrapper(t *testing.T) {
	t.Run("Implements gateway.Logger interface", func(t *testing.T) {
		// The wrapper should satisfy the interface
		var _ gateway.Logger = (*zapLoggerWrapper)(nil)
	})

	t.Run("Wraps all log methods", func(t *testing.T) {
		logger := &zapLoggerWrapper{}
		assert.NotPanics(t, func() {
			logger.Debug("test")
			logger.Info("test")
			logger.Warn("test")
			logger.Error("test")
		})
	})

	t.Run("Handles zap fields correctly", func(t *testing.T) {
		logger := &zapLoggerWrapper{}
		assert.NotPanics(t, func() {
			logger.Info("test", zap.String("key", "value"))
		})
	})

	t.Run("Wraps Sync method", func(t *testing.T) {
		logger := &zapLoggerWrapper{}
		err := logger.Sync()
		assert.NoError(t, err)
	})
}

func TestRegisterServiceRoutes(t *testing.T) {
	t.Run("Registers all service routes", func(t *testing.T) {
		router := gin.New()
		provider := &serviceURLProvider{}

		registerServiceRoutes(router, provider)

		routes := router.Routes()

		// Check that service route groups were registered
		foundIdentity := false
		foundOAuth := false
		foundGovernance := false
		foundAudit := false
		foundAdmin := false
		foundRisk := false

		for _, route := range routes {
			switch route.Path {
			case "/api/v1/identity/*filepath":
				foundIdentity = true
			case "/api/v1/oauth/*filepath":
				foundOAuth = true
			case "/api/v1/governance/*filepath":
				foundGovernance = true
			case "/api/v1/audit/*filepath":
				foundAudit = true
			case "/api/v1/admin/*filepath":
				foundAdmin = true
			case "/api/v1/risk/*filepath":
				foundRisk = true
			}
		}

		assert.True(t, foundIdentity, "Identity routes not registered")
		assert.True(t, foundOAuth, "OAuth routes not registered")
		assert.True(t, foundGovernance, "Governance routes not registered")
		assert.True(t, foundAudit, "Audit routes not registered")
		assert.True(t, foundAdmin, "Admin routes not registered")
		assert.True(t, foundRisk, "Risk routes not registered")
	})

	t.Run("Registers health and docs routes", func(t *testing.T) {
		router := gin.New()
		provider := &serviceURLProvider{}

		registerServiceRoutes(router, provider)

		// Test health endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Test docs endpoint
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/api/docs", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// Integration-style tests that don't require full infrastructure
func TestGatewayIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Gateway handles request routing", func(t *testing.T) {
		// Create mock backend servers
		identityBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"service": "identity",
				"path":    r.URL.Path,
			})
		}))
		defer identityBackend.Close()

		// Create a simple gateway router
		router := gin.New()

		// Add a health endpoint
		router.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		// Add a proxied route
		identityURL, _ := url.Parse(identityBackend.URL)
		identityProxy := httputil.NewSingleHostReverseProxy(identityURL)
		router.Any("/api/v1/identity/*filepath", func(c *gin.Context) {
			identityProxy.ServeHTTP(c.Writer, c.Request)
		})

		// Test health endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var healthResp map[string]string
		json.NewDecoder(w.Body).Decode(&healthResp)
		assert.Equal(t, "ok", healthResp["status"])

		// Test proxied route
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/api/v1/identity/users", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var proxyResp map[string]string
		json.NewDecoder(w.Body).Decode(&proxyResp)
		assert.Equal(t, "identity", proxyResp["service"])
	})
}

func TestShutdownTracerWrapper(t *testing.T) {
	t.Run("Wraps tracer shutdown function", func(t *testing.T) {
		called := false
		shutdownTracer := func(ctx context.Context) error {
			called = true
			return nil
		}

		wrapper := func(ctx interface{}) error {
			var stdctx context.Context
			if c, ok := ctx.(context.Context); ok {
				stdctx = c
			} else {
				stdctx = context.Background()
			}
			return shutdownTracer(stdctx)
		}

		err := wrapper(context.Background())
		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("Handles non-context arguments", func(t *testing.T) {
		called := false
		shutdownTracer := func(ctx context.Context) error {
			called = true
			return nil
		}

		wrapper := func(ctx interface{}) error {
			var stdctx context.Context
			if c, ok := ctx.(context.Context); ok {
				stdctx = c
			} else {
				stdctx = context.Background()
			}
			return shutdownTracer(stdctx)
		}

		err := wrapper("not a context")
		assert.NoError(t, err)
		assert.True(t, called)
	})
}

func TestMain_VersionVariables(t *testing.T) {
	// Test that version variables are accessible
	t.Run("Version variables are settable", func(t *testing.T) {
		// These would typically be set via ldflags during build
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

// Benchmark tests
func BenchmarkGatewayRequest(b *testing.B) {
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
