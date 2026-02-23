// Package middleware provides correlation ID middleware tests
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestCorrelationID(t *testing.T) {
	t.Run("Generates correlation ID when not provided", func(t *testing.T) {
		config := DefaultCorrelationIDConfig()
		config.GenerateIfMissing = true

		router := gin.New()
		router.Use(CorrelationID(config))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		correlationID := w.Header().Get("X-Correlation-ID")
		assert.NotEmpty(t, correlationID)

		// Should be valid UUID
		_, err := uuid.Parse(correlationID)
		assert.NoError(t, err)
	})

	t.Run("Uses provided X-Correlation-ID header", func(t *testing.T) {
		config := DefaultCorrelationIDConfig()

		router := gin.New()
		router.Use(CorrelationID(config))
		router.GET("/test", func(c *gin.Context) {
			correlationID := GetCorrelationID(c)
			c.String(200, correlationID)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Correlation-ID", "test-correlation-id-123")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "test-correlation-id-123", w.Header().Get("X-Correlation-ID"))
		assert.Equal(t, "test-correlation-id-123", w.Body.String())
	})

	t.Run("Falls back to X-Request-ID when configured", func(t *testing.T) {
		config := DefaultCorrelationIDConfig()
		config.UseRequestIDHeader = true

		router := gin.New()
		router.Use(CorrelationID(config))
		router.GET("/test", func(c *gin.Context) {
			correlationID := GetCorrelationID(c)
			c.String(200, correlationID)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Request-ID", "request-id-456")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "request-id-456", w.Header().Get("X-Correlation-ID"))
		assert.Equal(t, "request-id-456", w.Body.String())
	})

	t.Run("X-Correlation-ID takes precedence over X-Request-ID", func(t *testing.T) {
		config := DefaultCorrelationIDConfig()
		config.UseRequestIDHeader = true

		router := gin.New()
		router.Use(CorrelationID(config))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Correlation-ID", "correlation-id")
		req.Header.Set("X-Request-ID", "request-id")
		router.ServeHTTP(w, req)

		assert.Equal(t, "correlation-id", w.Header().Get("X-Correlation-ID"))
	})

	t.Run("Does not generate when GenerateIfMissing is false", func(t *testing.T) {
		config := DefaultCorrelationIDConfig()
		config.GenerateIfMissing = false

		router := gin.New()
		router.Use(CorrelationID(config))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Empty(t, w.Header().Get("X-Correlation-ID"))
	})

	t.Run("Stores correlation ID in context", func(t *testing.T) {
		config := DefaultCorrelationIDConfig()

		router := gin.New()
		router.Use(CorrelationID(config))
		router.GET("/test", func(c *gin.Context) {
			correlationID, exists := c.Get("correlation_id")
			require.True(t, exists)
			c.String(200, correlationID.(string))
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.NotEmpty(t, w.Body.String())
	})

	t.Run("Propagates downstream headers when configured", func(t *testing.T) {
		config := DefaultCorrelationIDConfig()
		config.PropagateToDownstream = true

		router := gin.New()
		router.Use(CorrelationID(config))
		router.GET("/test", func(c *gin.Context) {
			headers, exists := c.Get("downstream_headers")
			require.True(t, exists)
			headerMap := headers.(map[string]string)
			c.JSON(200, headerMap)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Correlation-ID", "test-id")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Contains(t, w.Body.String(), "test-id")
	})
}

func TestGetCorrelationID(t *testing.T) {
	t.Run("Returns correlation ID from context", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("correlation_id", "test-id")

		id := GetCorrelationID(c)
		assert.Equal(t, "test-id", id)
	})

	t.Run("Returns empty string when not in context", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())

		id := GetCorrelationID(c)
		assert.Empty(t, id)
	})

	t.Run("Returns empty string when wrong type in context", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("correlation_id", 123)

		id := GetCorrelationID(c)
		assert.Empty(t, id)
	})
}

func TestSetCorrelationID(t *testing.T) {
	t.Run("Sets correlation ID in context and header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		SetCorrelationID(c, "new-id")

		id, exists := c.Get("correlation_id")
		assert.True(t, exists)
		assert.Equal(t, "new-id", id)
		assert.Equal(t, "new-id", w.Header().Get("X-Correlation-ID"))
	})
}

func TestGetOrGenerate(t *testing.T) {
	t.Run("Returns existing correlation ID", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("correlation_id", "existing-id")

		id := GetOrGenerate(c)
		assert.Equal(t, "existing-id", id)
	})

	t.Run("Generates new ID when none exists", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())

		id := GetOrGenerate(c)
		assert.NotEmpty(t, id)

		// Should be valid UUID
		_, err := uuid.Parse(id)
		assert.NoError(t, err)
	})
}

func TestInjectHeaders(t *testing.T) {
	t.Run("Injects correlation ID into request", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("correlation_id", "test-id")

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		InjectHeaders(c, req)

		assert.Equal(t, "test-id", req.Header.Get("X-Correlation-ID"))
	})

	t.Run("Injects downstream headers into request", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("correlation_id", "test-id")
		c.Set("downstream_headers", map[string]string{
			"X-Correlation-ID": "test-id",
			"X-Trace-ID":       "trace-123",
		})

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		InjectHeaders(c, req)

		assert.Equal(t, "test-id", req.Header.Get("X-Correlation-ID"))
		assert.Equal(t, "trace-123", req.Header.Get("X-Trace-ID"))
	})
}

func TestTracingHeaders(t *testing.T) {
	t.Run("Returns correlation ID in headers", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("correlation_id", "test-id")
		c.Request = httptest.NewRequest("GET", "/test", nil)

		headers := TracingHeaders(c)
		assert.Equal(t, "test-id", headers["X-Correlation-ID"])
	})

	t.Run("Includes request ID if present", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("correlation_id", "test-id")
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.Header.Set("X-Request-ID", "req-123")

		headers := TracingHeaders(c)
		assert.Equal(t, "req-123", headers["X-Request-ID"])
	})

	t.Run("Includes trace parent if present", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("correlation_id", "test-id")
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.Header.Set("traceparent", "00-trace-id")

		headers := TracingHeaders(c)
		assert.Equal(t, "00-trace-id", headers["traceparent"])
	})
}

func TestAddTracingHeaders(t *testing.T) {
	t.Run("Adds tracing headers to request", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("correlation_id", "test-id")
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.Header.Set("X-Request-ID", "req-123")

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		AddTracingHeaders(c, req)

		assert.Equal(t, "test-id", req.Header.Get("X-Correlation-ID"))
		assert.Equal(t, "req-123", req.Header.Get("X-Request-ID"))
	})
}

func TestUUIDGenerator(t *testing.T) {
	t.Run("Generates valid UUIDs", func(t *testing.T) {
		gen := &UUIDGenerator{}

		id := gen.Generate()
		assert.NotEmpty(t, id)

		parsed, err := uuid.Parse(id)
		assert.NoError(t, err)
		assert.Equal(t, id, parsed.String())
	})

	t.Run("Validates correct UUIDs", func(t *testing.T) {
		gen := &UUIDGenerator{}

		validUUID := uuid.New().String()
		assert.True(t, gen.Validate(validUUID))
	})

	t.Run("Rejects invalid UUIDs", func(t *testing.T) {
		gen := &UUIDGenerator{}

		assert.False(t, gen.Validate("not-a-uuid"))
		assert.False(t, gen.Validate(""))
	})
}

func TestNanosecondGenerator(t *testing.T) {
	t.Run("Generates unique IDs", func(t *testing.T) {
		gen := &NanosecondGenerator{}

		id1 := gen.Generate()
		id2 := gen.Generate()

		assert.NotEmpty(t, id1)
		assert.NotEmpty(t, id2)
		assert.NotEqual(t, id1, id2)
	})

	t.Run("Validates non-empty IDs", func(t *testing.T) {
		gen := &NanosecondGenerator{}

		assert.True(t, gen.Validate("anything"))
		assert.False(t, gen.Validate(""))
	})
}

func TestPrefixGenerator(t *testing.T) {
	t.Run("Generates prefixed IDs", func(t *testing.T) {
		uuidGen := &UUIDGenerator{}
		gen := NewPrefixGenerator("gateway", uuidGen)

		id := gen.Generate()
		assert.True(t, len(id) > len("gateway-"))
		assert.True(t, len(id) > 8)
	})

	t.Run("Validates prefix correctly", func(t *testing.T) {
		uuidGen := &UUIDGenerator{}
		gen := NewPrefixGenerator("gateway", uuidGen)

		validID := gen.Generate()
		assert.True(t, gen.Validate(validID))

		invalidID := "other-" + validID[len("gateway-"):]
		assert.False(t, gen.Validate(invalidID))
	})

	t.Run("Validates ID content with prefix", func(t *testing.T) {
		uuidGen := &UUIDGenerator{}
		gen := NewPrefixGenerator("test", uuidGen)

		// Correct format
		validUUID := uuid.New().String()
		assert.True(t, gen.Validate("test-"+validUUID))

		// Invalid UUID part
		assert.False(t, gen.Validate("test-not-a-uuid"))
	})
}

func BenchmarkCorrelationID(b *testing.B) {
	config := DefaultCorrelationIDConfig()
	router := gin.New()
	router.Use(CorrelationID(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req, _ := http.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
