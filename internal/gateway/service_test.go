// Package gateway provides service tests for the gateway
package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestNewService(t *testing.T) {
	t.Run("Creates service with valid config", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)
		assert.NotNil(t, svc)
	})

	t.Run("Fails with nil logger", func(t *testing.T) {
		cfg := Config{}
		svc, err := NewService(cfg)
		assert.Error(t, err)
		assert.Nil(t, svc)
		assert.Contains(t, err.Error(), "logger")
	})
}

func TestService_Name(t *testing.T) {
	t.Run("Returns service name", func(t *testing.T) {
		svc := &Service{}
		assert.Equal(t, "gateway-service", svc.Name())
	})
}

func TestService_RegisterRoutes(t *testing.T) {
	t.Run("Registers utility routes", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		router := gin.New()
		svc.RegisterRoutes(router)

		// Test health endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "gateway")
	})

	t.Run("Registers ready endpoint", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		router := gin.New()
		svc.RegisterRoutes(router)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/ready", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ready")
	})

	t.Run("Ready endpoint returns 503 when Redis unavailable", func(t *testing.T) {
		logger := zap.NewNop()
		mockRedis := &mockRedisClient{getError: errors.New("redis unavailable")}

		cfg := Config{
			Logger:           &zapLoggerWrapper{logger: logger},
			Redis:            mockRedis,
			EnableRateLimit:  true,
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		router := gin.New()
		svc.RegisterRoutes(router)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/ready", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Contains(t, w.Body.String(), "not_ready")
	})
}

func TestService_Shutdown(t *testing.T) {
	t.Run("Shutdown succeeds", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = svc.Shutdown(ctx)
		assert.NoError(t, err)
	})

	t.Run("Shutdown is idempotent", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = svc.Shutdown(ctx)
		require.NoError(t, err)

		// Second shutdown should also succeed
		err = svc.Shutdown(ctx)
		assert.NoError(t, err)
	})
}

func TestService_HealthCheck(t *testing.T) {
	t.Run("Returns healthy when not shutting down", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger:          &zapLoggerWrapper{logger: logger},
			EnableRateLimit: false,
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = svc.HealthCheck(ctx)
		assert.NoError(t, err)
	})

	t.Run("Returns error when shutting down", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger:          &zapLoggerWrapper{logger: logger},
			EnableRateLimit: false,
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		// Trigger shutdown
		svc.shutdownMutex.Lock()
		svc.isShuttingDown = true
		svc.shutdownMutex.Unlock()

		ctx := context.Background()
		err = svc.HealthCheck(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "shutting down")
	})

	t.Run("Checks Redis when rate limit enabled", func(t *testing.T) {
		logger := zap.NewNop()
		mockRedis := &mockRedisClient{}

		cfg := Config{
			Logger:           &zapLoggerWrapper{logger: logger},
			Redis:            mockRedis,
			EnableRateLimit:  true,
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = svc.HealthCheck(ctx)
		assert.NoError(t, err)
	})

	t.Run("Returns error when Redis health check fails", func(t *testing.T) {
		logger := zap.NewNop()
		mockRedis := &mockRedisClient{getError: errors.New("connection failed")}

		cfg := Config{
			Logger:           &zapLoggerWrapper{logger: logger},
			Redis:            mockRedis,
			EnableRateLimit:  true,
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		err = svc.HealthCheck(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis")
	})
}

func TestService_AggregateHealth(t *testing.T) {
	t.Run("Returns health for all services", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
			Services: map[string]string{
				"identity":   "http://localhost:8501",
				"oauth":      "http://localhost:8502",
				"governance": "http://localhost:8503",
				"audit":      "http://localhost:8504",
				"admin":      "http://localhost:8505",
				"risk":       "http://localhost:8506",
			},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		health := svc.AggregateHealth(ctx)

		// Should have entries for all services
		assert.Contains(t, health, "identity")
		assert.Contains(t, health, "oauth")
		assert.Contains(t, health, "governance")
		assert.Contains(t, health, "audit")
		assert.Contains(t, health, "admin")
		assert.Contains(t, health, "risk")

		// All services should have URLs populated
		for serviceName, h := range health {
			assert.NotEmpty(t, h.URL, "Service %s should have a URL", serviceName)
		}
	})

	t.Run("Handles services with missing URLs", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
			Services: map[string]string{
				// Missing some services
				"identity": "http://localhost:8501",
			},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		ctx := context.Background()
		health := svc.AggregateHealth(ctx)

		// Should have entries for all services
		assert.Contains(t, health, "identity")

		// Missing services should have error
		for serviceName, h := range health {
			if serviceName != "identity" {
				assert.False(t, h.Healthy, "Service %s should not be healthy without URL", serviceName)
				assert.NotEmpty(t, h.Error, "Service %s should have an error", serviceName)
			}
		}
	})
}

func TestService_GetServiceURL(t *testing.T) {
	t.Run("Returns service URL from config", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
			Services: map[string]string{
				"identity": "http://custom-identity:8001",
			},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		url, err := svc.GetServiceURL("identity")
		require.NoError(t, err)
		assert.Equal(t, "http://custom-identity:8001", url)
	})

	t.Run("Returns error for unknown service", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		url, err := svc.GetServiceURL("unknown")
		assert.Error(t, err)
		assert.Empty(t, url)
	})
}

func TestService_CorrelationIDMiddleware(t *testing.T) {
	t.Run("Generates correlation ID when not provided", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		router := gin.New()
		router.Use(svc.correlationIDMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.NotEmpty(t, w.Header().Get("X-Correlation-ID"))
	})

	t.Run("Uses provided correlation ID", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger: &zapLoggerWrapper{logger: logger},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		router := gin.New()
		router.Use(svc.correlationIDMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Correlation-ID", "test-correlation-id")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "test-correlation-id", w.Header().Get("X-Correlation-ID"))
	})
}

func TestService_CorsMiddleware(t *testing.T) {
	t.Run("Allows all origins with wildcard", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger:         &zapLoggerWrapper{logger: logger},
			AllowedOrigins: []string{"*"},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		router := gin.New()
		router.Use(svc.corsMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("Handles OPTIONS preflight", func(t *testing.T) {
		logger := zap.NewNop()
		cfg := Config{
			Logger:         &zapLoggerWrapper{logger: logger},
			AllowedOrigins: []string{"*"},
		}

		svc, err := NewService(cfg)
		require.NoError(t, err)

		router := gin.New()
		router.Use(svc.corsMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		router.ServeHTTP(w, req)

		assert.Equal(t, 204, w.Code)
		assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))
	})
}

// Mock implementations

type mockRedisClient struct {
	getError error
}

func (m *mockRedisClient) Get(ctx interface{}, key string) *RedisStringCmd {
	return &RedisStringCmd{Err: m.getError}
}

func (m *mockRedisClient) Set(ctx interface{}, key string, value interface{}, expiration time.Duration) *RedisStatusCmd {
	return &RedisStatusCmd{Err: nil}
}

func (m *mockRedisClient) Incr(ctx interface{}, key string) *RedisIntCmd {
	return &RedisIntCmd{Err: nil}
}

func (m *mockRedisClient) Expire(ctx interface{}, key string, expiration time.Duration) *RedisBoolCmd {
	return &RedisBoolCmd{Err: nil}
}

func (m *mockRedisClient) Pipeline() RedisPipeline {
	return &mockPipeline{}
}

func (m *mockRedisClient) Close() error {
	return nil
}

type mockPipeline struct{}

func (m *mockPipeline) Exec() ([]interface{}, error) {
	return nil, nil
}

type zapLoggerWrapper struct {
	logger *zap.Logger
}

func (w *zapLoggerWrapper) Debug(msg string, fields ...interface{}) {}
func (w *zapLoggerWrapper) Info(msg string, fields ...interface{})  {}
func (w *zapLoggerWrapper) Warn(msg string, fields ...interface{})  {}
func (w *zapLoggerWrapper) Error(msg string, fields ...interface{}) {}
func (w *zapLoggerWrapper) Fatal(msg string, fields ...interface{}) {}
func (w *zapLoggerWrapper) Sync() error                             { return nil }
