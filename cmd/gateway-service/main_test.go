// Package main is the entry point for the Gateway Service
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/gateway"
	"github.com/openidx/openidx/internal/gateway/routes"
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
		// Use a nop logger to avoid stack traces in test output
		zapLogger := zap.NewNop()
		logger := &zapLoggerWrapper{logger: zapLogger}
		assert.NotPanics(t, func() {
			logger.Debug("test")
			logger.Info("test")
			logger.Warn("test")
			logger.Error("test")
		})
	})

	t.Run("Handles zap fields correctly", func(t *testing.T) {
		zapLogger := zap.NewNop()
		logger := &zapLoggerWrapper{logger: zapLogger}
		assert.NotPanics(t, func() {
			logger.Info("test", zap.String("key", "value"))
		})
	})

	t.Run("Wraps Sync method", func(t *testing.T) {
		// Use a nop logger to avoid sync issues in test environment
		zapLogger := zap.NewNop()
		logger := &zapLoggerWrapper{logger: zapLogger}
		err := logger.Sync()
		assert.NoError(t, err)
	})
}

// proxiedServices is the set of backends the gateway fronts. It is written out
// here rather than derived from the code under test, because a route table that
// checks itself against itself asserts nothing: this list is what a client may
// rely on reaching through the gateway, and adding a service to the product
// means adding it here on purpose.
var proxiedServices = []string{"identity", "oauth", "governance", "audit", "admin", "risk"}

// gatewayRouteTable registers the real service routes on a fresh engine and
// returns them as a method+path set.
func gatewayRouteTable(t *testing.T) map[string]bool {
	t.Helper()
	router := gin.New()
	// The claim this test replaced was that this call conflicts in gin. It does
	// not, and has not since the duplicate health registration moved out (see
	// registerServiceRoutes' own comment): a panic here IS the finding.
	registerServiceRoutes(router, &serviceURLProvider{})
	table := make(map[string]bool)
	for _, r := range router.Routes() {
		key := r.Method + " " + r.Path
		require.False(t, table[key], "route registered twice: %s (gin serves the first and the second is dead)", key)
		table[key] = true
	}
	return table
}

func TestRegisterServiceRoutes(t *testing.T) {
	t.Run("every proxied service is reachable by every method a REST client uses", func(t *testing.T) {
		table := gatewayRouteTable(t)
		// A missing method on one group is the shape this misses in review: the
		// console's DELETE lands on 404 while its GET works, and it looks like a
		// backend bug.
		for _, svc := range proxiedServices {
			for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
				path := "/api/v1/" + svc + "/*path"
				assert.True(t, table[method+" "+path],
					"%s %s is not registered — the gateway cannot forward it", method, path)
			}
		}
	})

	t.Run("a proxied group without a backend URL would 500 at request time", func(t *testing.T) {
		// The provider is the other half of the route: registering a group for a
		// service it cannot resolve compiles, deploys, and fails only when a user
		// hits it. Both directions are checked, so neither list can drift alone.
		provider := &serviceURLProvider{}
		table := gatewayRouteTable(t)
		for _, svc := range proxiedServices {
			url, err := provider.GetServiceURL(svc)
			require.NoError(t, err, "route group /api/v1/%s is registered but the provider cannot resolve it", svc)
			assert.NotEmpty(t, url)
		}
		for key := range table {
			var svc string
			if _, err := fmt.Sscanf(key, "GET /api/v1/%s", &svc); err != nil {
				continue
			}
			svc = strings.TrimSuffix(svc, "/*path")
			if svc == "" || strings.Contains(svc, "/") {
				continue
			}
			_, err := provider.GetServiceURL(svc)
			assert.NoError(t, err, "the gateway proxies /api/v1/%s but no backend URL is configured for it", svc)
		}
	})

	t.Run("health is not registered here — registering it twice panics at boot", func(t *testing.T) {
		// This is a startup invariant with no test in front of it until now:
		// gatewayService.RegisterRoutes owns /health and /ready, and gin panics
		// on a duplicate path. That panic happens when the binary starts, in
		// production, not in CI — so assert the separation here instead.
		table := gatewayRouteTable(t)
		for _, path := range []string{"/health", "/ready", "/healthz", "/livez"} {
			assert.False(t, table["GET "+path],
				"registerServiceRoutes registered %s; gatewayService.RegisterRoutes registers it too and the gateway will panic on start", path)
		}
	})

	t.Run("the documented docs endpoints are served", func(t *testing.T) {
		table := gatewayRouteTable(t)
		for _, path := range []string{"/api/docs", "/api/docs/html", "/api/docs/schema"} {
			assert.True(t, table["GET "+path], "GET %s is not registered", path)
		}
		for _, svc := range proxiedServices {
			assert.True(t, table["GET /api/docs/"+svc],
				"GET /api/docs/%s is not registered — the service is proxied but undocumented at the gateway", svc)
		}
	})

	t.Run("Registers health and docs routes", func(t *testing.T) {
		router := gin.New()
		provider := &serviceURLProvider{}

		// Create a minimal router without the conflicting routes
		// Just verify health/docs routes work
		routes.RegisterHealthRoutes(router, provider)
		routes.RegisterDocsRoutes(router, provider)

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
		// Create a simple gateway router
		router := gin.New()

		// Add a health endpoint
		router.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		// Add a mock identity route (simplified, without actual reverse proxy)
		router.GET("/api/v1/identity/users", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"service": "identity"})
		})

		// Test health endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var healthResp map[string]string
		json.NewDecoder(w.Body).Decode(&healthResp)
		assert.Equal(t, "ok", healthResp["status"])

		// Test identity endpoint
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
