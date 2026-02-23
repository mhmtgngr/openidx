// Package integration provides gateway integration tests
// These tests require the actual services to be running or use test servers
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/gateway"
	"github.com/openidx/openidx/internal/gateway/middleware"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// testLogger implements gateway.Logger
type testLogger struct{}

func (t *testLogger) Debug(msg string, fields ...interface{}) {}
func (t *testLogger) Info(msg string, fields ...interface{})  {}
func (t *testLogger) Warn(msg string, fields ...interface{})  {}
func (t *testLogger) Error(msg string, fields ...interface{}) {}
func (t *testLogger) Fatal(msg string, fields ...interface{}) {}
func (t *testLogger) Sync() error                             { return nil }

// testRedisClient wraps miniredis for testing
type testRedisClient struct {
	mini   *miniredis.Miniredis
	client *redis.Client
}

func newTestRedisClient(t *testing.T) *testRedisClient {
	s, err := miniredis.Run()
	require.NoError(t, err)

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	return &testRedisClient{
		mini:   s,
		client: client,
	}
}

func (t *testRedisClient) Get(ctx interface{}, key string) *gateway.RedisStringCmd {
	var stdctx context.Context
	if ctx, ok := ctx.(context.Context); ok {
		stdctx = ctx
	} else {
		stdctx = context.Background()
	}
	val, err := t.client.Get(stdctx, key).Result()
	return &gateway.RedisStringCmd{Val: val, Err: err}
}

func (t *testRedisClient) Set(ctx interface{}, key string, value interface{}, expiration time.Duration) *gateway.RedisStatusCmd {
	var stdctx context.Context
	if ctx, ok := ctx.(context.Context); ok {
		stdctx = ctx
	} else {
		stdctx = context.Background()
	}
	err := t.client.Set(stdctx, key, value, expiration).Err()
	return &gateway.RedisStatusCmd{Val: "OK", Err: err}
}

func (t *testRedisClient) Incr(ctx interface{}, key string) *gateway.RedisIntCmd {
	var stdctx context.Context
	if ctx, ok := ctx.(context.Context); ok {
		stdctx = ctx
	} else {
		stdctx = context.Background()
	}
	val, err := t.client.Incr(stdctx, key).Result()
	return &gateway.RedisIntCmd{Val: val, Err: err}
}

func (t *testRedisClient) Expire(ctx interface{}, key string, expiration time.Duration) *gateway.RedisBoolCmd {
	var stdctx context.Context
	if ctx, ok := ctx.(context.Context); ok {
		stdctx = ctx
	} else {
		stdctx = context.Background()
	}
	val, err := t.client.Expire(stdctx, key, expiration).Result()
	return &gateway.RedisBoolCmd{Val: val, Err: err}
}

func (t *testRedisClient) Pipeline() gateway.RedisPipeline {
	return &testPipeline{
		client: t.client,
		mini:   t.mini,
	}
}

func (t *testRedisClient) Close() error {
	t.mini.Close()
	return t.client.Close()
}

func (t *testRedisClient) GetRedisClient() *redis.Client {
	return t.client
}

type testPipeline struct {
	client *redis.Client
	mini   *miniredis.Miniredis
}

func (t *testPipeline) Exec() ([]interface{}, error) {
	cmds, err := t.client.Pipeline().Exec(context.Background())
	if err != nil {
		return nil, err
	}
	result := make([]interface{}, len(cmds))
	for i, cmd := range cmds {
		result[i] = cmd
	}
	return result, nil
}

// Integration tests
func TestGatewayIntegration_ServiceCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Creates gateway service with valid config", func(t *testing.T) {
		logger := &testLogger{}
		gatewayCfg := gateway.Config{
			Services: map[string]string{
				"identity":   "http://localhost:8501",
				"oauth":      "http://localhost:8502",
				"governance": "http://localhost:8503",
			},
			Logger: logger,
		}

		gatewaySvc, err := gateway.NewService(gatewayCfg)
		require.NoError(t, err)
		assert.NotNil(t, gatewaySvc)

		router := gin.New()
		gatewaySvc.RegisterRoutes(router)

		// Verify utility routes are registered
		routes := router.Routes()
		assert.NotEmpty(t, routes)

		// Test health endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var healthResp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&healthResp)
		assert.Equal(t, "ok", healthResp["status"])
		assert.Equal(t, "gateway", healthResp["service"])
	})

	t.Run("Fails to create gateway with nil logger", func(t *testing.T) {
		gatewayCfg := gateway.Config{
			Logger: nil,
		}

		_, err := gateway.NewService(gatewayCfg)
		assert.Error(t, err)
	})
}

func TestGatewayIntegration_RateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Enforces rate limits", func(t *testing.T) {
		redisClient := newTestRedisClient(t)
		defer redisClient.Close()

		logger := &testLogger{}
		gatewayCfg := gateway.Config{
			Logger:          logger,
			EnableRateLimit: true,
			RateLimitConfig: gateway.RateLimitConfig{
				RequestsPerMinute: 3,
				WindowSeconds:     60,
			},
		}

		rateLimiter := middleware.NewRateLimitMiddleware(redisClient.GetRedisClient(), logger, gatewayCfg.RateLimitConfig)

		router := gin.New()
		router.Use(rateLimiter.RateLimit("test-service"))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// Make requests within limit
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code, "Request %d should succeed", i+1)
		}

		// Next request should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("Different IPs have separate limits", func(t *testing.T) {
		redisClient := newTestRedisClient(t)
		defer redisClient.Close()

		logger := &testLogger{}
		gatewayCfg := gateway.Config{
			Logger:          logger,
			EnableRateLimit: true,
			RateLimitConfig: gateway.RateLimitConfig{
				RequestsPerMinute: 2,
				WindowSeconds:     60,
			},
		}

		rateLimiter := middleware.NewRateLimitMiddleware(redisClient.GetRedisClient(), logger, gatewayCfg.RateLimitConfig)

		router := gin.New()
		router.Use(rateLimiter.RateLimit("test-service"))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// IP1 uses up its limit
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "10.0.0.1:9999"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// IP1 should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:9999"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// IP2 should still be able to make requests
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.2:9999"
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)
	})
}

func TestGatewayIntegration_CorrelationID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Generates correlation ID when not provided", func(t *testing.T) {
		logger := &testLogger{}
		gatewayCfg := gateway.Config{
			Logger: logger,
		}

		gatewaySvc, err := gateway.NewService(gatewayCfg)
		require.NoError(t, err)

		router := gin.New()
		gatewaySvc.RegisterRoutes(router)

		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// Make request without correlation ID
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		// Check response has correlation ID
		correlationID := w.Header().Get("X-Correlation-ID")
		assert.NotEmpty(t, correlationID)
	})

	t.Run("Uses provided correlation ID", func(t *testing.T) {
		logger := &testLogger{}
		gatewayCfg := gateway.Config{
			Logger: logger,
		}

		gatewaySvc, err := gateway.NewService(gatewayCfg)
		require.NoError(t, err)

		router := gin.New()
		gatewaySvc.RegisterRoutes(router)

		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// Make request with correlation ID
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Correlation-ID", "test-correlation-123")
		router.ServeHTTP(w, req)

		// Check response has correlation ID
		correlationID := w.Header().Get("X-Correlation-ID")
		assert.Equal(t, "test-correlation-123", correlationID)
	})
}

func TestGatewayIntegration_HealthChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Gateway health endpoints work", func(t *testing.T) {
		logger := &testLogger{}
		gatewayCfg := gateway.Config{
			Logger: logger,
		}

		gatewaySvc, err := gateway.NewService(gatewayCfg)
		require.NoError(t, err)

		router := gin.New()
		gatewaySvc.RegisterRoutes(router)

		// Test /health
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var healthResp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&healthResp)
		assert.Equal(t, "ok", healthResp["status"])
		assert.Equal(t, "gateway", healthResp["service"])

		// Test /ready (legacy)
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/ready", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var readyResp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&readyResp)
		assert.Equal(t, "ready", readyResp["status"])
	})
}

// testServiceURLProvider provides URLs for mock backend servers
type testServiceURLProvider struct {
	servers map[string]*mockBackendServer
}

func newTestServiceURLProvider() *testServiceURLProvider {
	return &testServiceURLProvider{
		servers: make(map[string]*mockBackendServer),
	}
}

func (p *testServiceURLProvider) AddService(name string, server *mockBackendServer) {
	p.servers[name] = server
}

func (p *testServiceURLProvider) GetServiceURL(serviceName string) (string, error) {
	if server, ok := p.servers[serviceName]; ok {
		return server.URL(), nil
	}
	return "", fmt.Errorf("service %s not found", serviceName)
}

func (p *testServiceURLProvider) CloseAll() {
	for _, server := range p.servers {
		server.Close()
	}
}

// mockBackendServer creates a test backend server
type mockBackendServer struct {
	server     *httptest.Server
	serviceURL string
	requests   []mockRequest
}

type mockRequest struct {
	Method    string
	Path      string
	Headers   http.Header
	Body      string
	Response  interface{}
	Status    int
	delay     time.Duration
}

func newMockBackendServer(serviceName string) *mockBackendServer {
	server := &mockBackendServer{
		requests: make([]mockRequest, 0),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Record request
		server.requests = append(server.requests, mockRequest{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: r.Header.Clone(),
		})

		// Return response
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend-Service", serviceName)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"service": serviceName,
			"path":    r.URL.Path,
			"method":  r.Method,
		})
	})

	server.server = httptest.NewServer(mux)
	server.serviceURL = server.server.URL

	return server
}

func (m *mockBackendServer) Close() {
	m.server.Close()
}

func (m *mockBackendServer) URL() string {
	return m.serviceURL
}

func (m *mockBackendServer) GetRequestCount() int {
	return len(m.requests)
}

func (m *mockBackendServer) GetLastRequest() mockRequest {
	if len(m.requests) == 0 {
		return mockRequest{}
	}
	return m.requests[len(m.requests)-1]
}

func (m *mockBackendServer) Reset() {
	m.requests = make([]mockRequest, 0)
}
