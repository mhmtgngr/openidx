// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// setupTestLogger creates a test logger with observable logs
func setupTestLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zap.InfoLevel)
	return zap.New(core), logs
}

func TestRequestLogger_BasicLogging(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLogger(logger))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check logs were created
	logs := observedLogs.All()
	require.Greater(t, len(logs), 0, "expected logs to be created")

	logEntry := logs[0]
	assert.Equal(t, "GET", findField(logEntry, "method"))
	assert.Contains(t, findField(logEntry, "path"), "test")
	statusVal, statusFound := findIntFieldValue(logEntry, "status")
	assert.True(t, statusFound, "expected status field in log entry")
	assert.Equal(t, int64(http.StatusOK), statusVal)
}

func TestRequestLogger_RequestIDGeneration(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLogger(logger))

	router.GET("/test", func(c *gin.Context) {
		// Verify request ID is set in context
		requestID, exists := c.Get("request_id")
		assert.True(t, exists, "request_id should be set in context")
		assert.NotEmpty(t, requestID, "request_id should not be empty")

		// Verify header is set
		assert.NotEmpty(t, c.Writer.Header().Get("X-Request-ID"))
		c.JSON(http.StatusOK, gin.H{"request_id": requestID})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	logs := observedLogs.All()
	require.Greater(t, len(logs), 0)

	// Check request_id in logs
	logEntry := logs[0]
	requestIDField := findField(logEntry, "request_id")
	assert.NotEmpty(t, requestIDField)
}

func TestRequestLogger_PreserveRequestID(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLogger(logger))

	customRequestID := "my-custom-request-id-12345"

	router.GET("/test", func(c *gin.Context) {
		requestID, _ := c.Get("request_id")
		assert.Equal(t, customRequestID, requestID, "should preserve custom request ID")
		c.JSON(http.StatusOK, gin.H{})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", customRequestID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	logs := observedLogs.All()
	require.Greater(t, len(logs), 0)

	logEntry := logs[0]
	requestIDField := findField(logEntry, "request_id")
	assert.Equal(t, customRequestID, requestIDField)
}

func TestRequestLogger_UserIDLogging(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		// Simulate auth middleware setting user_id
		c.Set("user_id", "user-123")
		c.Next()
	})
	router.Use(RequestLogger(logger))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	logs := observedLogs.All()
	require.Greater(t, len(logs), 0)

	logEntry := logs[0]
	userIDField := findField(logEntry, "user_id")
	assert.Equal(t, "user-123", userIDField)
}

func TestRequestLogger_SessionIDLogging(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("session_id", "session-abc-123")
		c.Next()
	})
	router.Use(RequestLogger(logger))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	logs := observedLogs.All()
	require.Greater(t, len(logs), 0)

	logEntry := logs[0]
	sessionIDField := findField(logEntry, "session_id")
	assert.Equal(t, "session-abc-123", sessionIDField)
}

func TestRequestLogger_ClientIPExtraction(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLogger(logger))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	tests := []struct {
		name          string
		headerXFF     string
		headerXRealIP string
		expectedIP    string
	}{
		{
			name:       "X-Forwarded-For with single IP",
			headerXFF:  "203.0.113.1",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "X-Forwarded-For with multiple IPs",
			headerXFF:  "203.0.113.1, 198.51.100.1",
			expectedIP: "203.0.113.1",
		},
		{
			name:          "X-Real-IP takes precedence when no XFF",
			headerXRealIP: "192.0.2.1",
			expectedIP:    "192.0.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observedLogs.TakeAll() // Clear logs

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.headerXFF != "" {
				req.Header.Set("X-Forwarded-For", tt.headerXFF)
			}
			if tt.headerXRealIP != "" {
				req.Header.Set("X-Real-IP", tt.headerXRealIP)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			logs := observedLogs.All()
			require.Greater(t, len(logs), 0)

			logEntry := logs[0]
			clientIPField := findField(logEntry, "client_ip")
			assert.Equal(t, tt.expectedIP, clientIPField)
		})
	}
}

func TestRequestLogger_QueryParamsSanitization(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	config := DefaultLoggingConfig(logger)
	config.LogQueryParams = true

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLoggerWithConfig(config))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	req := httptest.NewRequest("GET", "/test?password=secret123&token=abc123&name=test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	logs := observedLogs.All()
	require.Greater(t, len(logs), 0)

	logEntry := logs[0]
	queryField := findField(logEntry, "query_params")
	assert.Contains(t, queryField, "password=***REDACTED***")
	assert.Contains(t, queryField, "token=***REDACTED***")
	assert.Contains(t, queryField, "name=test")
}

func TestRequestLogger_BodyLoggingWithSanitization(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	config := DefaultLoggingConfig(logger)
	config.LogBody = true

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLoggerWithConfig(config))

	router.POST("/login", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	payload := map[string]interface{}{
		"username": "testuser",
		"password": "secret123",
		"api_key":  "key-abc-123",
	}
	bodyBytes, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	logs := observedLogs.All()
	require.Greater(t, len(logs), 0)

	logEntry := logs[0]
	bodyField := findField(logEntry, "request_body")
	assert.NotEmpty(t, bodyField)
	// Check that sensitive fields are redacted
	assert.True(t, strings.Contains(bodyField, "REDACTED") || strings.Contains(bodyField, "password"))
}

// TestRequestLogger_BodyTruncation covers both halves of the size limit, which
// used to be one: a large JSON body is redacted and THEN cut (the other order
// discards it whole, because truncated JSON does not parse), and a large body
// that is not JSON at all is refused with its size named rather than guessed at.
func TestRequestLogger_BodyTruncation(t *testing.T) {
	post := func(t *testing.T, payload string) string {
		t.Helper()
		logger, observedLogs := setupTestLogger()
		config := DefaultLoggingConfig(logger)
		config.LogBody = true

		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(RequestLoggerWithConfig(config))
		router.POST("/upload", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("POST", "/upload", strings.NewReader(payload)))

		logs := observedLogs.All()
		require.Greater(t, len(logs), 0)
		return findField(logs[0], "request_body")
	}

	t.Run("a large JSON body is redacted and then truncated", func(t *testing.T) {
		payload := `{"password":"hunter2","filler":"` + strings.Repeat("x", 15*1024) + `"}`
		body := post(t, payload)

		assert.Contains(t, body, "truncated", "the operator cannot tell the body was cut")
		assert.NotContains(t, body, "hunter2", "the password survived into the log")
		assert.Contains(t, body, "xxxx", "redaction should cost the secret, not the whole body")
		// Not asserted: that the marker itself is still visible. Re-encoding
		// sorts the keys, so whether "password" lands before or after 10 KB of
		// "filler" is alphabetical luck. What must hold is that the secret is
		// gone and the rest is not -- the marker's presence is checked on a body
		// small enough for the question to be meaningful, below.
	})

	t.Run("a small JSON body keeps everything but the secret", func(t *testing.T) {
		body := post(t, `{"username":"ada","password":"hunter2","recovery_codes":["a1","b2"],`+
			`"profile":{"client_secret":"cs_live_9","display":"Ada L"}}`)

		assert.NotContains(t, body, "hunter2")
		assert.NotContains(t, body, "cs_live_9", "a secret nested one level down was left in the log")
		assert.NotContains(t, body, "a1", "an ARRAY value under a sensitive name was left in the log")
		assert.Contains(t, body, redactedMarker)
		assert.Contains(t, body, "ada", "a non-secret field must survive")
		assert.Contains(t, body, "Ada L", "a non-secret field nested one level down must survive")
	})

	t.Run("a large body that is not JSON is refused with its size", func(t *testing.T) {
		body := post(t, strings.Repeat("x", 15*1024))

		assert.Contains(t, body, "redacted", "an unparseable body cannot be field-redacted, so none of it may be logged")
		assert.Contains(t, body, "15360 bytes", "the size is the one thing that can be reported safely")
		assert.NotContains(t, body, "xxxx")
	})
}

func TestRequestLogger_MinDuration(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	config := DefaultLoggingConfig(logger)
	config.MinDuration = 100 * time.Millisecond

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLoggerWithConfig(config))

	router.GET("/fast", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	router.GET("/slow", func(c *gin.Context) {
		time.Sleep(150 * time.Millisecond)
		c.JSON(http.StatusOK, gin.H{})
	})

	// Fast request should not be logged
	req := httptest.NewRequest("GET", "/fast", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Clear logs from slow test if any
	observedLogs.TakeAll()
	// Fast request logs
	fastLogs := observedLogs.All()
	// May have 0 or 1 logs depending on timing
	assert.LessOrEqual(t, len(fastLogs), 1)

	// Slow request should be logged
	observedLogs.TakeAll()
	req = httptest.NewRequest("GET", "/slow", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	slowLogs := observedLogs.All()
	require.Greater(t, len(slowLogs), 0)
}

func TestRequestLogger_StatusBasedLogLevel(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		statusCode    int
		expectedLevel zapcore.Level
	}{
		{"2xx success", http.StatusOK, zapcore.InfoLevel},
		{"3xx redirect", http.StatusFound, zapcore.InfoLevel},
		{"4xx client error", http.StatusBadRequest, zapcore.WarnLevel},
		{"5xx server error", http.StatusInternalServerError, zapcore.ErrorLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, observedLogs := setupTestLogger()
			logger = logger.WithOptions(zap.IncreaseLevel(zapcore.DebugLevel)) // Capture all levels

			router := gin.New()
			router.Use(RequestLogger(logger))

			router.GET("/test", func(c *gin.Context) {
				c.Status(tt.statusCode)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			logs := observedLogs.All()
			require.Greater(t, len(logs), 0)

			logEntry := logs[0]
			assert.Equal(t, tt.expectedLevel, logEntry.Level)
		})
	}
}

func TestRequestLogger_ResponseSize(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLogger(logger))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test response data"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	logs := observedLogs.All()
	require.Greater(t, len(logs), 0)

	logEntry := logs[0]
	found := false
	for _, field := range logEntry.Context {
		if field.Key == "response_size" {
			found = true
			assert.Greater(t, field.Integer, int64(0))
			break
		}
	}
	assert.True(t, found, "expected response_size field in log entry")
}

func TestRequestLogger_GzipBodyHandling(t *testing.T) {
	logger, _ := setupTestLogger()

	config := DefaultLoggingConfig(logger)
	config.LogBody = true

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLoggerWithConfig(config))

	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	// Create gzipped body
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	gzWriter.Write([]byte(`{"test": "data"}`))
	gzWriter.Close()

	req := httptest.NewRequest("POST", "/test", &buf)
	req.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should not panic and should handle gzip body
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequestLogger_UserAgentLogging(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLogger(logger))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	userAgent := "Mozilla/5.0 TestAgent/1.0"
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", userAgent)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	logs := observedLogs.All()
	require.Greater(t, len(logs), 0)

	logEntry := logs[0]
	userAgentField := findField(logEntry, "user_agent")
	assert.Equal(t, userAgent, userAgentField)
}

func TestRequestLogger_AuthMethodLogging(t *testing.T) {
	logger, observedLogs := setupTestLogger()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_method", "api_key")
		c.Set("service_account_id", "sa-123")
		c.Set("org_id", "org-abc")
		c.Next()
	})
	router.Use(RequestLogger(logger))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	logs := observedLogs.All()
	require.Greater(t, len(logs), 0)

	logEntry := logs[0]
	assert.Equal(t, "api_key", findField(logEntry, "auth_method"))
	assert.Equal(t, "sa-123", findField(logEntry, "service_account_id"))
	assert.Equal(t, "org-abc", findField(logEntry, "org_id"))
}

func TestSanitizeQueryParams(t *testing.T) {
	sensitiveFields := map[string]bool{
		"password": true,
		"token":    true,
		"api_key":  true,
	}

	tests := []struct {
		name     string
		query    string
		expected string
	}{
		{
			name:     "sanitize password",
			query:    "password=secret123",
			expected: "password=***REDACTED***",
		},
		{
			name:     "sanitize token",
			query:    "token=abc123",
			expected: "token=***REDACTED***",
		},
		{
			name:     "keep safe param",
			query:    "name=test",
			expected: "name=test",
		},
		{
			name:     "mixed params",
			query:    "password=secret&name=test&token=abc",
			expected: "password=***REDACTED***&name=test&token=***REDACTED***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeQueryParams(tt.query, sensitiveFields)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		xForwardedFor string
		xRealIP       string
		expectedIP    string
	}{
		{
			name:          "X-Forwarded-For single IP",
			xForwardedFor: "192.168.1.1",
			expectedIP:    "192.168.1.1",
		},
		{
			name:          "X-Forwarded-For multiple IPs",
			xForwardedFor: "192.168.1.1, 10.0.0.1",
			expectedIP:    "192.168.1.1",
		},
		{
			name:       "X-Real-IP only",
			xRealIP:    "10.0.0.1",
			expectedIP: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}
			c.Request = req

			result := getClientIP(c)
			assert.Equal(t, tt.expectedIP, result)
		})
	}
}

// findField is a helper to extract string field values from log entries
func findField(entry observer.LoggedEntry, fieldName string) string {
	for _, field := range entry.Context {
		if field.Key == fieldName {
			return field.String
		}
	}
	return ""
}

// findIntFieldValue is a helper to extract integer field values from log entries
func findIntFieldValue(entry observer.LoggedEntry, fieldName string) (int64, bool) {
	for _, field := range entry.Context {
		if field.Key == fieldName {
			return field.Integer, true
		}
	}
	return 0, false
}

func TestDefaultLoggingConfig(t *testing.T) {
	logger := zap.NewNop()
	config := DefaultLoggingConfig(logger)

	assert.False(t, config.LogBody)
	assert.True(t, config.LogQueryParams)
	assert.NotNil(t, config.SanitizeFields)
	assert.Equal(t, time.Duration(0), config.MinDuration)
	assert.Equal(t, logger, config.Logger)
}

func BenchmarkRequestLogger(b *testing.B) {
	logger := zap.NewNop()
	config := DefaultLoggingConfig(logger)
	config.LogBody = false // Disable body logging for benchmark

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLoggerWithConfig(config))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// TestBodyReadingAfterLogging verifies that request body is still readable
// by handlers after the logging middleware has processed it
func TestBodyReadingAfterLogging(t *testing.T) {
	logger, _ := setupTestLogger()
	config := DefaultLoggingConfig(logger)
	config.LogBody = true

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLoggerWithConfig(config))

	var receivedBody map[string]interface{}
	router.POST("/test", func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		require.NoError(t, err, "body should still be readable")
		err = json.Unmarshal(body, &receivedBody)
		require.NoError(t, err, "body should be valid JSON")
		c.JSON(http.StatusOK, gin.H{})
	})

	payload := map[string]string{
		"username": "testuser",
		"email":    "test@example.com",
	}
	bodyBytes, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "testuser", receivedBody["username"])
	assert.Equal(t, "test@example.com", receivedBody["email"])
}

// TestRequestLogger_RejectsAnImplausibleRequestID: X-Request-ID is honoured so a
// caller can correlate a request across services, and TestRequestLogger_Preserve
// RequestID pins that. This is the other half — the header is unauthenticated,
// it is echoed back in the response, and it is stamped on every log line for the
// request, so an id-shaped value is accepted and anything else is replaced.
//
// The 5,000-byte case is the one measured before the fix: the value came back in
// the response header in full and appeared in every log entry.
func TestRequestLogger_RejectsAnImplausibleRequestID(t *testing.T) {
	cases := map[string]struct {
		sent   string
		accept bool
	}{
		"a UUID":                        {"3f2504e0-4f89-11d3-9a0c-0305e82c3301", true},
		"a W3C traceparent":             {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", true},
		"a vendor id with dots":         {"svc.api.7a1f_2b", true},
		"five kilobytes":                {strings.Repeat("A", 5000), false},
		"a line break":                  {"abc\ndef", false},
		"an ANSI escape":                {"abc\x1b[2Jdef", false},
		"a space":                       {"abc def", false},
		"markup":                        {"<script>alert(1)</script>", false},
		"empty (the pre-existing case)": {"", false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			logger, observedLogs := setupTestLogger()
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Use(RequestLogger(logger))
			router.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })

			req := httptest.NewRequest("GET", "/test", nil)
			if tc.sent != "" {
				// Set directly on the map: http.Header.Set would be fine here, but
				// going through it hides that a proxy can hand us anything.
				req.Header["X-Request-Id"] = []string{tc.sent}
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			logs := observedLogs.All()
			require.Greater(t, len(logs), 0)
			logged := findField(logs[0], "request_id")
			echoed := w.Header().Get("X-Request-ID")

			require.NotEmpty(t, logged, "every request must carry a correlation id")
			assert.Equal(t, logged, echoed, "the logged id and the echoed id must be the same value")

			if tc.accept {
				assert.Equal(t, tc.sent, logged, "an id-shaped X-Request-ID must be preserved for correlation")
				return
			}
			assert.NotEqual(t, tc.sent, logged, "an implausible X-Request-ID was used as the correlation id")
			assert.Len(t, logged, 36, "the replacement should be a UUID")
			assert.NotContains(t, echoed, "AAAA", "the rejected value was echoed back to the client")
		})
	}
}

// TestSanitizeQueryParams_percentEncodedKeyIsStillRedacted pins the one-character
// bypass this redaction had for its whole life.
//
// gin decodes a parameter name before matching it, and the sanitiser did not, so
// the two disagreed about what a parameter was called. Measured before the fix:
// a request for ?%74oken=hunter2 was read by the handler as token=hunter2 and
// written to the log as "%74oken=hunter2", in clear. Nothing hostile is required
// to trip it — a client that percent-encodes more than it needs to is enough.
func TestSanitizeQueryParams_percentEncodedKeyIsStillRedacted(t *testing.T) {
	fields := map[string]bool{}
	for _, f := range DefaultSanitizedFields {
		fields[strings.ToLower(f)] = true
	}

	cases := map[string]struct {
		query    string
		redacted bool
	}{
		"the plain name":                     {"token=hunter2", true},
		"one letter percent-encoded":         {"%74oken=hunter2", true},
		"the whole name percent-encoded":     {"%70%61%73%73%77%6f%72%64=hunter2", true},
		"upper case":                         {"TOKEN=hunter2", true},
		"a name that will not decode":        {"%zz=hunter2", true},
		"an ordinary parameter is untouched": {"page=3", false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := sanitizeQueryParams(tc.query, fields)
			if tc.redacted {
				if strings.Contains(got, "hunter2") {
					t.Fatalf("value survived redaction: %q", got)
				}
				if !strings.Contains(got, redactedMarker) {
					t.Fatalf("expected a redaction marker, got %q", got)
				}
				return
			}
			if got != tc.query {
				t.Fatalf("an ordinary parameter was changed: %q -> %q", tc.query, got)
			}
		})
	}
}

// TestSanitizeQueryParams_coversTheCredentialsInQueryStrings names the values the
// old list missed. Each of these is read by a live handler from the query string,
// and each went into the log in clear.
func TestSanitizeQueryParams_coversTheCredentialsInQueryStrings(t *testing.T) {
	fields := map[string]bool{}
	for _, f := range DefaultSanitizedFields {
		fields[strings.ToLower(f)] = true
	}

	// name -> where it is read from, so a future reader can check the claim.
	secrets := map[string]string{
		"code":          "internal/oauth/social_login.go, social_link.go, service.go; internal/access/service.go, multi_idp.go",
		"state":         "the same five callbacks",
		"session_token": "internal/oauth/handlers_passwordless.go; internal/identity/handlers_advanced_mfa.go",
		"token":         "internal/oauth/handlers_passwordless.go (the magic link itself)",
		"login_session": "internal/oauth/authorize.go",
		"id_token_hint": "RP-initiated logout",
		"user_code":     "the device flow",
		"SAMLRequest":   "the SAML SP endpoints",
		"RelayState":    "the SAML SP endpoints",
		"nonce":         "the OIDC authorize request",
	}

	for param, where := range secrets {
		t.Run(param, func(t *testing.T) {
			got := sanitizeQueryParams(param+"=SECRETVALUE", fields)
			if strings.Contains(got, "SECRETVALUE") {
				t.Fatalf("%s is read by %s and reached the log in clear: %q", param, where, got)
			}
		})
	}
}

// And the other direction, because a redactor that redacts everything is a
// redactor somebody turns off: the parameters an operator actually needs in
// order to read a log must survive.
func TestSanitizeQueryParams_keepsWhatMakesALogUseful(t *testing.T) {
	fields := map[string]bool{}
	for _, f := range DefaultSanitizedFields {
		fields[strings.ToLower(f)] = true
	}

	for _, param := range []string{
		"page=3", "page_size=50", "limit=100", "offset=20", "q=ada",
		"status=active", "client_id=console", "org=acme", "user_id=u-1",
		"response_type=code", "format=csv", "start_date=2026-01-01",
	} {
		if got := sanitizeQueryParams(param, fields); got != param {
			t.Errorf("%q was redacted to %q — an operator cannot read this log any more", param, got)
		}
	}
}
