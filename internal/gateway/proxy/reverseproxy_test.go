// Package proxy provides reverse proxy tests
package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockLogger implements gateway.Logger
type mockProxyLogger struct {
	errorCount int
	lastMsg    string
	lastFields []interface{}
}

func (m *mockProxyLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockProxyLogger) Info(msg string, fields ...interface{})  {}
func (m *mockProxyLogger) Warn(msg string, fields ...interface{})  {}
func (m *mockProxyLogger) Error(msg string, fields ...interface{}) {
	m.errorCount++
	m.lastMsg = msg
	m.lastFields = fields
}
func (m *mockProxyLogger) Fatal(msg string, fields ...interface{}) {}
func (m *mockProxyLogger) Sync() error                             { return nil }

func TestNewReverseProxy(t *testing.T) {
	t.Run("Creates proxy with valid config", func(t *testing.T) {
		logger := &mockProxyLogger{}
		config := Config{
			TargetURL:      "http://example.com:8080",
			ServiceName:    "test-service",
			RequestTimeout: 30 * time.Second,
			Logger:         logger,
		}

		proxy, err := NewReverseProxy(config)

		require.NoError(t, err)
		assert.NotNil(t, proxy)
		assert.Equal(t, "test-service", proxy.serviceName)
		assert.Equal(t, 30*time.Second, proxy.requestTimeout)
		assert.NotNil(t, proxy.targetURL)
	})

	t.Run("Fails with invalid URL", func(t *testing.T) {
		logger := &mockProxyLogger{}
		config := Config{
			TargetURL:   "://invalid-url",
			ServiceName: "test-service",
			Logger:      logger,
		}

		proxy, err := NewReverseProxy(config)

		assert.Error(t, err)
		assert.Nil(t, proxy)
	})
}

func TestGetCorrelationID(t *testing.T) {
	t.Run("Gets correlation ID from context", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("correlation_id", "test-id")

		id := GetCorrelationID(c)
		assert.Equal(t, "test-id", id)
	})

	t.Run("Falls back to header when not in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.Header.Set("X-Correlation-ID", "header-id")

		id := GetCorrelationID(c)
		assert.Equal(t, "header-id", id)
	})

	t.Run("Returns empty when not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		id := GetCorrelationID(c)
		assert.Empty(t, id)
	})
}

func TestGetClientIP(t *testing.T) {
	t.Run("Gets IP from Gin context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.RemoteAddr = "192.168.1.1:1234"

		ip := getClientIP(c, c.Request)
		// c.ClientIP() returns just the IP without port
		assert.Equal(t, "192.168.1.1", ip)
	})

	t.Run("Parses X-Forwarded-For header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")

		ip := getClientIP(nil, req)
		assert.Equal(t, "10.0.0.1", ip)
	})

	t.Run("Uses X-Real-IP header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Real-IP", "172.16.0.1")

		ip := getClientIP(nil, req)
		assert.Equal(t, "172.16.0.1", ip)
	})

	t.Run("Falls back to RemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.1.1.1:9999"

		ip := getClientIP(nil, req)
		assert.Equal(t, "10.1.1.1:9999", ip)
	})
}

func TestGetProto(t *testing.T) {
	t.Run("Uses X-Forwarded-Proto header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Forwarded-Proto", "https")

		proto := getProto(nil, req)
		assert.Equal(t, "https", proto)
	})

	t.Run("Uses X-Forwarded-Scheme header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Forwarded-Scheme", "https")

		proto := getProto(nil, req)
		assert.Equal(t, "https", proto)
	})

	t.Run("Detects HTTPS from TLS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.TLS = &tls.ConnectionState{}

		proto := getProto(nil, req)
		assert.Equal(t, "https", proto)
	})

	t.Run("Defaults to http", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		proto := getProto(nil, req)
		assert.Equal(t, "http", proto)
	})
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	t.Run("Removes hop-by-hop headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Connection", "keep-alive, Upgrade")
		req.Header.Set("Keep-Alive", "timeout=5")
		req.Header.Set("Proxy-Authenticate", "Basic")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")

		removeHopByHopHeaders(req.Header)

		assert.Empty(t, req.Header.Get("Connection"))
		assert.Empty(t, req.Header.Get("Keep-Alive"))
		assert.Empty(t, req.Header.Get("Proxy-Authenticate"))
		assert.Empty(t, req.Header.Get("Upgrade"))
		assert.NotEmpty(t, req.Header.Get("Content-Type"))
		assert.NotEmpty(t, req.Header.Get("Authorization"))
	})
}

func TestIsTimeoutError(t *testing.T) {
	t.Run("Detects timeout errors", func(t *testing.T) {
		assert.True(t, isTimeoutError(errors.New("context deadline exceeded")))
		assert.True(t, isTimeoutError(errors.New("request timeout")))
		assert.True(t, isTimeoutError(errors.New("client timeout")))
	})

	t.Run("Returns false for non-timeout errors", func(t *testing.T) {
		assert.False(t, isTimeoutError(errors.New("connection refused")))
		assert.False(t, isTimeoutError(errors.New("some other error")))
		assert.False(t, isTimeoutError(nil))
	})
}

func TestIsConnectionError(t *testing.T) {
	t.Run("Detects connection errors", func(t *testing.T) {
		assert.True(t, isConnectionError(errors.New("connection refused")))
		assert.True(t, isConnectionError(errors.New("no such host")))
		assert.True(t, isConnectionError(errors.New("connection reset")))
	})

	t.Run("Returns false for non-connection errors", func(t *testing.T) {
		assert.False(t, isConnectionError(errors.New("timeout")))
		assert.False(t, isConnectionError(errors.New("some other error")))
		assert.False(t, isConnectionError(nil))
	})
}

func TestStatsTracker(t *testing.T) {
	t.Run("Records proxy statistics", func(t *testing.T) {
		tracker := NewStatsTracker()

		// Record successful requests
		tracker.RecordRequest("identity", 50*time.Millisecond, true)
		tracker.RecordRequest("identity", 75*time.Millisecond, true)
		tracker.RecordRequest("identity", 100*time.Millisecond, false)

		stats := tracker.GetStats("identity")

		assert.Equal(t, int64(3), stats.TotalRequests)
		assert.Equal(t, int64(2), stats.SuccessfulRequests)
		assert.Equal(t, int64(1), stats.FailedRequests)
		assert.Equal(t, 225*time.Millisecond, stats.TotalLatency)
		assert.Greater(t, stats.AvgLatency, time.Duration(0))
	})

	t.Run("Returns empty stats for unknown service", func(t *testing.T) {
		tracker := NewStatsTracker()

		stats := tracker.GetStats("unknown")

		assert.Equal(t, int64(0), stats.TotalRequests)
		assert.Equal(t, int64(0), stats.SuccessfulRequests)
		assert.Equal(t, int64(0), stats.FailedRequests)
	})

	t.Run("Gets all statistics", func(t *testing.T) {
		tracker := NewStatsTracker()

		tracker.RecordRequest("identity", 50*time.Millisecond, true)
		tracker.RecordRequest("oauth", 75*time.Millisecond, true)

		allStats := tracker.GetAllStats()

		assert.Contains(t, allStats, "identity")
		assert.Contains(t, allStats, "oauth")
		assert.Equal(t, int64(1), allStats["identity"].TotalRequests)
		assert.Equal(t, int64(1), allStats["oauth"].TotalRequests)
	})
}

func TestBufferPool(t *testing.T) {
	t.Run("Reuses buffers", func(t *testing.T) {
		pool := NewBufferPool(2)

		buf1 := pool.Get()
		buf1.WriteString("test")
		assert.Equal(t, "test", buf1.String())

		pool.Put(buf1)

		buf2 := pool.Get()
		// Should get the same buffer back (reset)
		assert.Equal(t, "", buf2.String())
		assert.True(t, buf2 == buf1)

		pool.Put(buf2)
	})

	t.Run("Creates new buffer when pool is empty", func(t *testing.T) {
		pool := NewBufferPool(1)

		buf1 := pool.Get()
		// Don't put buf1 back, so pool is empty
		buf2 := pool.Get()

		// Verify they are different pointers
		require.False(t, buf1 == buf2, "buf1 and buf2 should be different pointers")
	})
}

func TestCopyResponse(t *testing.T) {
	t.Run("Copies response body", func(t *testing.T) {
		src := strings.NewReader("test response body")
		dst := &bytes.Buffer{}

		err := CopyResponse(dst, src)

		assert.NoError(t, err)
		assert.Equal(t, "test response body", dst.String())
	})
}

// ServiceHealth is defined in routes package, tested in routes_test.go
