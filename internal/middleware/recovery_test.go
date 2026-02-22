// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestRecovery_BasicPanicRecovery(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(Recovery(logger))
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})
	router.GET("/ok", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Recovers from panic", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)

		// Should not crash the test
		assert.NotPanics(t, func() {
			router.ServeHTTP(w, req)
		})

		assert.Equal(t, 500, w.Code)
	})

	t.Run("Logs panic with correlation", func(t *testing.T) {
		logs.TakeAll() // Clear previous logs

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)
		req.Header.Set("X-Request-ID", "test-correlation-id")
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, zapcore.ErrorLevel, entry.Level)
		assert.Equal(t, "Panic recovered", entry.Message)
		assert.Equal(t, "test-correlation-id", entry.ContextMap()["correlation_id"])
		assert.Equal(t, "test panic", entry.ContextMap()["panic"])
	})

	t.Run("Normal requests work fine", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/ok", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})
}

func TestRecovery_WithRequestID(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(RequestID(), Recovery(logger))
	router.GET("/panic", func(c *gin.Context) {
		panic("something bad")
	})

	t.Run("Uses request ID as correlation ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)
		req.Header.Set("X-Request-ID", "req-abc-123")
		router.ServeHTTP(w, req)

		assert.Equal(t, 500, w.Code)

		// Check logs
		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, "req-abc-123", entry.ContextMap()["correlation_id"])

		// Check response
		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "req-abc-123", resp.CorrelationID)
	})
}

func TestRecovery_WithUserID(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(Recovery(logger))
	router.GET("/panic", func(c *gin.Context) {
		c.Set("user_id", "user-123")
		panic("user context panic")
	})

	t.Run("Logs user ID when present", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]
		assert.Equal(t, "user-123", entry.ContextMap()["user_id"])
	})
}

func TestRecovery_StackTrace(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	cfg := DefaultRecoveryConfig(logger)
	cfg.StackTrace = true

	router := gin.New()
	router.Use(RecoveryWithConfig(cfg))
	router.GET("/panic", func(c *gin.Context) {
		panic("stack trace test")
	})

	t.Run("Logs stack trace when enabled", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]

		stackTrace, ok := entry.ContextMap()["stack_trace"].(string)
		assert.True(t, ok)
		assert.NotEmpty(t, stackTrace)
		assert.Contains(t, stackTrace, "stack trace test")
	})
}

func TestRecovery_ReturnStackTrace(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	cfg := DefaultRecoveryConfig(logger)
	cfg.ReturnStackTrace = true

	router := gin.New()
	router.Use(RecoveryWithConfig(cfg))
	router.GET("/panic", func(c *gin.Context) {
		panic("visible stack trace")
	})

	t.Run("Returns stack trace in response when enabled", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)
		req.Header.Set("Accept", "application/json")
		router.ServeHTTP(w, req)

		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.StackTrace)
		assert.Contains(t, resp.StackTrace, "visible stack trace")
	})
}

func TestRecovery_JSONResponse(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(Recovery(logger))
	router.GET("/panic", func(c *gin.Context) {
		panic("json response test")
	})

	t.Run("Returns JSON error response", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)
		req.Header.Set("Accept", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, "internal server error", resp.Error)
		assert.NotEmpty(t, resp.CorrelationID)
		assert.NotEmpty(t, resp.Timestamp)
		assert.Empty(t, resp.StackTrace) // Stack trace not returned by default
	})
}

func TestRecovery_NonJSONResponse(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(Recovery(logger))
	router.GET("/panic", func(c *gin.Context) {
		panic("non-json test")
	})

	t.Run("Returns plain response for non-JSON requests", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)
		req.Header.Set("Accept", "text/html")
		router.ServeHTTP(w, req)

		assert.Equal(t, 500, w.Code)
		assert.Equal(t, "req-abc-123", w.Header().Get("X-Correlation-ID"))
	})
}

func TestRecovery_LogsRequestDetails(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(Recovery(logger))
	router.GET("/panic", func(c *gin.Context) {
		panic("detailed logging test")
	})

	t.Run("Logs method, path, query, IP, user agent", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic?foo=bar", nil)
		req.Header.Set("User-Agent", "TestAgent/1.0")
		req.RemoteAddr = "10.0.0.1:12345"
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, logs.Len())
		entry := logs.All()[0]

		assert.Equal(t, "GET", entry.ContextMap()["method"])
		assert.Equal(t, "/panic", entry.ContextMap()["path"])
		assert.Equal(t, "foo=bar", entry.ContextMap()["query"])
		assert.Equal(t, "10.0.0.1", entry.ContextMap()["ip"])
		assert.Equal(t, "TestAgent/1.0", entry.ContextMap()["user_agent"])
	})
}

func TestCapturePanic(t *testing.T) {
	router := gin.New()
	router.GET("/panic", func(c *gin.Context) {
		panic("capture test")
	})

	t.Run("Captures panic details", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)
		req.Header.Set("X-Request-ID", "capture-req-id")
		req.RemoteAddr = "192.168.1.1:9999"

		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Simulate panic
		defer func() {
			if err := recover(); err != nil {
				report := CapturePanic(c, err)

				assert.Equal(t, "capture-req-id", report.CorrelationID)
				assert.Equal(t, "capture test", report.Panic)
				assert.Equal(t, "GET", report.Method)
				assert.Equal(t, "/panic", report.Path)
				assert.Equal(t, "192.168.1.1", report.ClientIP)
				assert.NotEmpty(t, report.StackTrace)
			}
		}()

		panic("capture test")
	})
}

func TestRecovery_GeneratesCorrelationID(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(Recovery(logger)) // No RequestID middleware
	router.GET("/panic", func(c *gin.Context) {
		panic("no request id test")
	})

	t.Run("Generates correlation ID when not present", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)
		router.ServeHTTP(w, req)

		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.CorrelationID)
		assert.Equal(t, 36, len(resp.CorrelationID)) // UUID length
	})
}

func TestRecoveryWithWriter(t *testing.T) {
	observedZapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedZapCore)

	router := gin.New()
	router.Use(RecoveryWithWriter(logger, true))
	router.GET("/panic", func(c *gin.Context) {
		panic("writer test")
	})

	t.Run("RecoveryWithWriter works", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/panic", nil)
		req.Header.Set("Accept", "application/json")

		assert.NotPanics(t, func() {
			router.ServeHTTP(w, req)
		})

		assert.Equal(t, 500, w.Code)

		var resp ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.StackTrace) // ReturnStackTrace=true
	})
}

func TestSanitizeErrorMessage(t *testing.T) {
	t.Run("Truncates long messages", func(t *testing.T) {
		longMsg := strings.Repeat("a", 1000)
		result := sanitizeErrorMessage(longMsg)
		assert.LessOrEqual(t, len(result), 503) // 500 + "..."
		assert.True(t, strings.HasSuffix(result, "..."))
	})

	t.Run("Keeps short messages", func(t *testing.T) {
		shortMsg := "short error"
		result := sanitizeErrorMessage(shortMsg)
		assert.Equal(t, shortMsg, result)
	})
}

func TestWantsJSON(t *testing.T) {
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Returns true for application/json", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Accept", "application/json")

		c, _ := gin.CreateTestContext(w)
		c.Request = req

		assert.True(t, wantsJSON(c))
	})

	t.Run("Returns true for API paths with wildcard", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Accept", "*/*")

		c, _ := gin.CreateTestContext(w)
		c.Request = req

		assert.True(t, wantsJSON(c))
	})
}

func TestDefaultRecoveryConfig(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultRecoveryConfig(logger)

	assert.Equal(t, logger, cfg.Logger)
	assert.True(t, cfg.StackTrace)
	assert.False(t, cfg.ReturnStackTrace)
}

func TestPanicReport(t *testing.T) {
	report := &PanicReport{
		CorrelationID: "test-123",
		Panic:         "test panic",
		StackTrace:    "stack trace here",
		Method:        "GET",
		Path:          "/test",
		UserID:        "user-456",
		ClientIP:      "10.0.0.1",
	}

	t.Run("Serializes to JSON", func(t *testing.T) {
		data, err := json.Marshal(report)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "test-123", result["correlation_id"])
		assert.Equal(t, "test panic", result["panic"])
		assert.Equal(t, "GET", result["method"])
		assert.Equal(t, "user-456", result["user_id"])
	})
}
