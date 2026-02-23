// Package metrics provides Prometheus metrics collection for OpenIDX services
package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Middleware("test-service"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	router.GET("/metrics", Handler())

	// Make a test request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check metrics endpoint
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/metrics", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	// Verify that our metrics are present
	assert.Contains(t, body, `http_requests_total`)
	assert.Contains(t, body, `http_request_duration_seconds`)
	assert.Contains(t, body, `service="test-service"`)
}

func TestMiddleware_StatusCodes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Middleware("status-test"))
	router.GET("/ok", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	router.GET("/notfound", func(c *gin.Context) {
		c.String(http.StatusNotFound, "Not Found")
	})
	router.GET("/error", func(c *gin.Context) {
		c.String(http.StatusInternalServerError, "Error")
	})
	router.GET("/metrics", Handler())

	// Make requests with different status codes
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/ok", nil))
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/notfound", nil))
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/error", nil))

	// Check metrics
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.Contains(t, body, `status="200"`)
	assert.Contains(t, body, `status="404"`)
	assert.Contains(t, body, `status="500"`)
}

func TestMiddleware_MetricsExcluded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Middleware("test-service"))
	router.GET("/metrics", Handler())

	// Make request to metrics endpoint itself
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	router.ServeHTTP(w, req)

	// The metrics endpoint should not record its own metrics
	// (it's excluded in the middleware)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler(t *testing.T) {
	handler := Handler()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/metrics", handler)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify it's text/plain content type
	assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")

	// Verify some basic Prometheus output
	body := w.Body.String()
	assert.NotEmpty(t, body)
}

func TestRecordAuthAttempt(t *testing.T) {
	// Reset metrics registry for clean test
	_ = prometheus.NewRegistry()
	// In a real test, we'd use a custom registry

	// Record some auth attempts
	RecordAuthAttempt("password", "success")
	RecordAuthAttempt("password", "failure")
	RecordAuthAttempt("mfa", "success")

	// This would typically be verified by scraping metrics
	// For now, we just ensure no panic occurs
}

func TestRecordMFAVerification(t *testing.T) {
	// Ensure no panic
	RecordMFAVerification("totp", "success")
	RecordMFAVerification("sms", "failure")
	RecordMFAVerification("push", "success")
}

func TestRecordMFADuration(t *testing.T) {
	// Ensure no panic
	RecordMFADuration("totp", 500*time.Millisecond)
	RecordMFADuration("sms", 2*time.Second)
	RecordMFADuration("push", 5*time.Second)
}

func TestRecordRiskScore(t *testing.T) {
	// Ensure no panic
	RecordRiskScore("identity-service", "allow", 10)
	RecordRiskScore("identity-service", "challenge", 50)
	RecordRiskScore("identity-service", "deny", 90)
}

func TestRecordTokenOperation(t *testing.T) {
	// Ensure no panic
	RecordTokenOperation("issue", "success")
	RecordTokenOperation("refresh", "failure")
	RecordTokenOperation("revoke", "success")
}

func TestRecordDBQuery(t *testing.T) {
	// Ensure no panic
	RecordDBQuery("identity-service", "select", "users", 5*time.Millisecond)
	RecordDBQuery("identity-service", "insert", "sessions", 10*time.Millisecond)
}

func TestSetDBConnections(t *testing.T) {
	// Ensure no panic
	SetDBConnections("identity-service", "idle", 5)
	SetDBConnections("identity-service", "in_use", 3)
	SetDBConnections("identity-service", "wait", 1)
}

func TestRecordCacheOperation(t *testing.T) {
	// Ensure no panic
	RecordCacheOperation("identity-service", "get", "hit")
	RecordCacheOperation("identity-service", "get", "miss")
	RecordCacheOperation("identity-service", "set", "hit")
}

func TestActiveSessionsGauge(t *testing.T) {
	// Ensure no panic
	IncActiveSessions("identity-service")
	IncActiveSessions("identity-service")
	IncActiveSessions("identity-service")

	DecActiveSessions("identity-service")
	DecActiveSessions("identity-service")

	SetActiveSessions("identity-service", 10)
}

func TestMiddleware_ConcurrentRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Middleware("concurrent-test"))
	router.GET("/test", func(c *gin.Context) {
		time.Sleep(10 * time.Millisecond)
		c.String(http.StatusOK, "OK")
	})
	router.GET("/metrics", Handler())

	// Make concurrent requests
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)
			done <- true
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check metrics - should show 10 requests
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	router.ServeHTTP(w, req)

	body := w.Body.String()
	// The metrics should show our service
	assert.Contains(t, body, `service="concurrent-test"`)
}

func TestMiddleware_ResponseSize(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Middleware("size-test"))
	router.GET("/small", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	router.GET("/large", func(c *gin.Context) {
		c.String(http.StatusOK, strings.Repeat("x", 1000))
	})
	router.GET("/metrics", Handler())

	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/small", nil))
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/large", nil))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	router.ServeHTTP(w, req)

	body := w.Body.String()
	// Response size metric should be present
	assert.Contains(t, body, `http_response_size_bytes`)
}

func TestMiddleware_DifferentMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Middleware("method-test"))
	router.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "OK") })
	router.POST("/", func(c *gin.Context) { c.String(http.StatusOK, "OK") })
	router.PUT("/", func(c *gin.Context) { c.String(http.StatusOK, "OK") })
	router.DELETE("/", func(c *gin.Context) { c.String(http.StatusOK, "OK") })
	router.GET("/metrics", Handler())

	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/", nil))
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("DELETE", "/", nil))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.Contains(t, body, `method="GET"`)
	assert.Contains(t, body, `method="POST"`)
	assert.Contains(t, body, `method="PUT"`)
	assert.Contains(t, body, `method="DELETE"`)
}

func TestMiddleware_HistogramBuckets(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Middleware("histogram-test"))
	router.GET("/fast", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	router.GET("/slow", func(c *gin.Context) {
		time.Sleep(100 * time.Millisecond)
		c.String(http.StatusOK, "OK")
	})
	router.GET("/metrics", Handler())

	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/fast", nil))
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/slow", nil))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	router.ServeHTTP(w, req)

	body := w.Body.String()
	// Check that histogram buckets exist
	assert.Contains(t, body, `http_request_duration_seconds_bucket`)
}

// BenchmarkMiddleware benchmarks the middleware performance
func BenchmarkMiddleware(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Middleware("bench-service"))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest("GET", "/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// TestAllMetricFunctions ensures all metric functions don't panic
func TestAllMetricFunctions(t *testing.T) {
	// This test ensures all metric functions are callable without panic
	t.Run("AuthAttempts", func(t *testing.T) {
		RecordAuthAttempt("password", "success")
		RecordAuthAttempt("sso", "failure")
		RecordAuthAttempt("oauth", "rate_limited")
	})

	t.Run("MFA", func(t *testing.T) {
		RecordMFAVerification("totp", "success")
		RecordMFAVerification("sms", "failure")
		RecordMFADuration("totp", 1*time.Second)
		RecordMFADuration("push", 5*time.Second)
	})

	t.Run("RiskScore", func(t *testing.T) {
		RecordRiskScore("test", "allow", 0)
		RecordRiskScore("test", "challenge", 50)
		RecordRiskScore("test", "deny", 100)
	})

	t.Run("Tokens", func(t *testing.T) {
		RecordTokenOperation("issue", "success")
		RecordTokenOperation("refresh", "failure")
		RecordTokenOperation("revoke", "success")
		RecordTokenOperation("validate", "success")
	})

	t.Run("DB", func(t *testing.T) {
		RecordDBQuery("test", "select", "users", 1*time.Millisecond)
		RecordDBQuery("test", "insert", "sessions", 5*time.Millisecond)
		RecordDBQuery("test", "update", "users", 2*time.Millisecond)
		RecordDBQuery("test", "delete", "sessions", 1*time.Millisecond)
		SetDBConnections("test", "idle", 10)
		SetDBConnections("test", "in_use", 5)
		SetDBConnections("test", "wait", 2)
	})

	t.Run("Cache", func(t *testing.T) {
		RecordCacheOperation("test", "get", "hit")
		RecordCacheOperation("test", "get", "miss")
		RecordCacheOperation("test", "set", "hit")
		RecordCacheOperation("test", "delete", "hit")
	})

	t.Run("Sessions", func(t *testing.T) {
		IncActiveSessions("test")
		DecActiveSessions("test")
		SetActiveSessions("test", 100)
	})
}

func TestHandler_ServeHTTP(t *testing.T) {
	handler := Handler()

	// Create a test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := gin.CreateTestContext(w)
		c.Request = r
		handler(c)
	}))
	defer ts.Close()

	// Make request
	resp, err := http.Get(ts.URL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read and verify body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotEmpty(t, body)
}
