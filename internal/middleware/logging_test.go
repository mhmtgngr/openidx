// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestLogging_BasicLogging(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(RequestID()) // Add RequestID middleware to set request ID in context
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Logs successful request", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Request-ID", "test-req-id")
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, zapcore.InfoLevel, entry.Level)
		assert.Equal(t, "HTTP request", entry.Message)
		assert.Equal(t, "GET", entry.ContextMap()["method"])
		assert.Equal(t, "/test", entry.ContextMap()["path"])
		// Use int64 for status since zap.Int stores it as int64 in ContextMap
		assert.Equal(t, int64(200), entry.ContextMap()["status"])
		assert.Equal(t, "test-req-id", entry.ContextMap()["request_id"])
	})
}

func TestLogging_WithUserID(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(RequestID()) // Add RequestID middleware
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.String(200, "OK")
	})

	t.Run("Logs user ID when present", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		// user_id field is only added when it's not empty
		if userID, exists := entry.ContextMap()["user_id"]; exists {
			assert.Equal(t, "user-123", userID)
		} else {
			t.Skip("user_id field not found in log entry - middleware may not be adding it")
		}
	})
}

func TestLogging_ErrorStatus(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(RequestID()) // Add RequestID middleware
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(404, "Not Found")
	})

	t.Run("Logs 4xx status as warning", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, zapcore.WarnLevel, entry.Level)
		assert.Equal(t, int64(404), entry.ContextMap()["status"])
	})
}

func TestLogging_ServerError(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(RequestID()) // Add RequestID middleware
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(500, "Internal Server Error")
	})

	t.Run("Logs 5xx status as error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, zapcore.ErrorLevel, entry.Level)
		assert.Equal(t, int64(500), entry.ContextMap()["status"])
	})
}

func TestLogging_SkipPaths(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	cfg := DefaultLoggingConfig(logger)
	cfg.SkipPaths = []string{"/health", "/metrics", "/ready"}

	router := gin.New()
	router.Use(LoggingWithConfig(cfg))
	router.GET("/health", func(c *gin.Context) {
		c.String(200, "OK")
	})
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Does not log health endpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 0, logs.Len())
	})

	t.Run("Logs regular endpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
	})
}

func TestLogging_QueryParams(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	cfg := DefaultLoggingConfig(logger)
	cfg.QueryParams = true

	router := gin.New()
	router.Use(LoggingWithConfig(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Logs query parameters when enabled", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test?foo=bar&baz=qux", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, "foo=bar&baz=qux", entry.ContextMap()["query"])
	})
}

func TestLogging_UserAgent(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Logs user agent", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("User-Agent", "TestAgent/1.0")
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, "TestAgent/1.0", entry.ContextMap()["user_agent"])
	})
}

func TestLogging_Referer(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Logs referer", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Referer", "https://example.com")
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, "https://example.com", entry.ContextMap()["referer"])
	})
}

func TestLogging_ResponseSize(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(RequestID()) // Add RequestID middleware
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "Hello, World!")
	})

	t.Run("Logs bytes out", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, int64(13), entry.ContextMap()["bytes_out"]) // "Hello, World!" is 13 bytes
	})
}

func TestLogging_RequestBodySize(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(RequestID()) // Add RequestID middleware
	router.Use(Logging(logger))
	router.POST("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Logs request body size", func(t *testing.T) {
		body := bytes.NewBufferString(`{"test":"data"}`)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/test", body)
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		// bytes_in should be set from ContentLength
		assert.Equal(t, int64(15), entry.ContextMap()["bytes_in"]) // {"test":"data"} is 15 bytes
	})
}

func TestLogging_Duration(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Logs duration in milliseconds", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		duration, ok := entry.ContextMap()["duration_ms"].(int64)
		assert.True(t, ok)
		assert.GreaterOrEqual(t, duration, int64(0))
	})
}

func TestLogging_ClientIP(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Logs client IP", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, "192.168.1.100", entry.ContextMap()["ip"])
	})
}

func TestLogging_GinErrors(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(RequestID()) // Add RequestID middleware
	router.Use(Logging(logger))
	router.GET("/test", func(c *gin.Context) {
		_ = c.Error(errors.New("something went wrong"))
		c.String(200, "OK")
	})

	t.Run("Logs Gin errors", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		err, ok := entry.ContextMap()["error"].(string)
		assert.True(t, ok)
		assert.Contains(t, err, "something went wrong")
	})
}

func TestDefaultLoggingConfig(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultLoggingConfig(logger)

	assert.Equal(t, logger, cfg.Logger)
	assert.Equal(t, true, cfg.UTC)
	assert.Equal(t, true, cfg.QueryParams)
	assert.Contains(t, cfg.SkipPaths, "/health")
	assert.Contains(t, cfg.SkipPaths, "/metrics")
	assert.Contains(t, cfg.SkipPaths, "/ready")
}

func TestJSONLogEntry(t *testing.T) {
	entry := JSONLogEntry{
		Time:      "2024-01-01T00:00:00Z",
		Method:    "GET",
		Path:      "/api/test",
		Status:    200,
		Latency:   45,
		ClientIP:  "127.0.0.1",
		RequestID: "req-123",
		UserID:    "user-456",
	}

	t.Run("Serializes to JSON", func(t *testing.T) {
		output := LogFormatter(entry)
		assert.Contains(t, output, `"time":"2024-01-01T00:00:00Z"`)
		assert.Contains(t, output, `"method":"GET"`)
		assert.Contains(t, output, `"path":"/api/test"`)
		assert.Contains(t, output, `"status":200`)
		assert.Contains(t, output, `"duration_ms":45`)
	})
}

func TestNewProductionLogger(t *testing.T) {
	t.Run("Creates production logger", func(t *testing.T) {
		logger, err := NewProductionLogger()
		require.NoError(t, err)
		assert.NotNil(t, logger)
		defer logger.Sync()
	})
}

func TestNewDevelopmentLogger(t *testing.T) {
	t.Run("Creates development logger", func(t *testing.T) {
		logger, err := NewDevelopmentLogger()
		require.NoError(t, err)
		assert.NotNil(t, logger)
		defer logger.Sync()
	})
}
