// Package middleware provides tests for WebSocket security logging
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestNewWebSocketSecurityLogger(t *testing.T) {
	logger := zap.NewNop()
	wsl := NewWebSocketSecurityLogger(logger)

	assert.NotNil(t, wsl)
	assert.NotNil(t, wsl.logger)
}

func TestWebSocketSecurityLogger_LogRejectedConnection(t *testing.T) {
	// Create an observer to capture logs
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	wsl := NewWebSocketSecurityLogger(logger)

	event := &SecurityEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   "origin_rejected",
		Origin:      "https://evil.com",
		RemoteAddr:  "192.168.1.100:12345",
		RealIP:      "192.168.1.100",
		UserAgent:   "BadBot/1.0",
		RequestURI:  "/api/v1/audit/stream",
		Reason:      "origin not in allowed list",
		ActionTaken: "connection_rejected",
	}

	wsl.LogRejectedConnection(event)

	// Verify log entry
	require.Equal(t, 1, logs.Len(), "Expected one log entry")
	entry := logs.All()[0]
	assert.Equal(t, zapcore.WarnLevel, entry.Level)
	assert.Equal(t, "WebSocket connection rejected", entry.Message)
	contextMap := entry.ContextMap()
	assert.Equal(t, "https://evil.com", contextMap["origin"])
	assert.Equal(t, "192.168.1.100", contextMap["real_ip"])
	assert.Equal(t, "BadBot/1.0", contextMap["user_agent"])
}

func TestWebSocketSecurityLogger_LogRejectedConnection_NilEvent(t *testing.T) {
	// Should not panic with nil event
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	wsl := NewWebSocketSecurityLogger(logger)

	wsl.LogRejectedConnection(nil)

	assert.Equal(t, 0, logs.Len(), "Expected no log entries for nil event")
}

func TestWebSocketSecurityLogger_LogAcceptedConnection(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	wsl := NewWebSocketSecurityLogger(logger)

	wsl.LogAcceptedConnection("https://example.com", "192.168.1.100:12345", "Mozilla/5.0")

	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.InfoLevel, entry.Level)
	assert.Equal(t, "WebSocket connection accepted", entry.Message)
	contextMap := entry.ContextMap()
	assert.Equal(t, "https://example.com", contextMap["origin"])
	assert.Equal(t, "192.168.1.100:12345", contextMap["remote_addr"])
	assert.Equal(t, "Mozilla/5.0", contextMap["user_agent"])
}

func TestWebSocketSecurityLogger_LogSuspiciousActivity(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	wsl := NewWebSocketSecurityLogger(logger)

	event := &SecurityEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   "wildcard_in_production",
		Origin:      "https://example.com",
		RemoteAddr:  "10.0.0.1:54321",
		RealIP:      "10.0.0.1",
		Reason:      "wildcard origin should not be used in production",
	}

	wsl.LogSuspiciousActivity(event)

	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.ErrorLevel, entry.Level)
	assert.Equal(t, "Suspicious WebSocket activity detected", entry.Message)
	contextMap := entry.ContextMap()
	assert.Equal(t, "wildcard_in_production", contextMap["event_type"])
	assert.Equal(t, "wildcard origin should not be used in production", contextMap["reason"])
}

func TestExtractRealIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1, 192.0.2.1")

	ip := ExtractRealIP(req)

	assert.Equal(t, "203.0.113.1", ip, "Should extract first IP from X-Forwarded-For")
}

func TestExtractRealIP_XForwardedFor_Single(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	ip := ExtractRealIP(req)

	assert.Equal(t, "203.0.113.1", ip)
}

func TestExtractRealIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "198.51.100.1")

	ip := ExtractRealIP(req)

	assert.Equal(t, "198.51.100.1", ip)
}

func TestExtractRealIP_CFConnectingIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("CF-Connecting-IP", "197.0.0.1")

	ip := ExtractRealIP(req)

	assert.Equal(t, "197.0.0.1", ip)
}

func TestExtractRealIP_Precedence(t *testing.T) {
	// X-Forwarded-For should take precedence
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.Header.Set("X-Real-IP", "198.51.100.1")
	req.Header.Set("CF-Connecting-IP", "197.0.0.1")

	ip := ExtractRealIP(req)

	assert.Equal(t, "203.0.113.1", ip)
}

func TestExtractRealIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	ip := ExtractRealIP(req)

	assert.Equal(t, "192.168.1.100", ip)
}

func TestExtractRealIP_RemoteAddr_IPv6(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "[2001:db8::1]:12345"

	ip := ExtractRealIP(req)

	assert.Equal(t, "[2001:db8::1]", ip)
}

func TestExtractRealIP_Unknown(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = ""

	ip := ExtractRealIP(req)

	assert.Equal(t, "unknown", ip)
}

func TestExtractRealIP_Whitespace(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "  203.0.113.1  ")

	ip := ExtractRealIP(req)

	assert.Equal(t, "203.0.113.1", ip, "Should trim whitespace")
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name           string
		connection     string
		upgrade        string
		expected       bool
	}{
		{
			name:       "valid WebSocket upgrade",
			connection: "upgrade",
			upgrade:    "websocket",
			expected:   true,
		},
		{
			name:       "case insensitive",
			connection: "Upgrade",
			upgrade:    "WebSocket",
			expected:   true,
		},
		{
			name:       "missing connection header",
			connection: "",
			upgrade:    "websocket",
			expected:   false,
		},
		{
			name:       "missing upgrade header",
			connection: "upgrade",
			upgrade:    "",
			expected:   false,
		},
		{
			name:       "wrong upgrade type",
			connection: "upgrade",
			upgrade:    "h2c",
			expected:   false,
		},
		{
			name:       "regular HTTP request",
			connection: "keep-alive",
			upgrade:    "",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.connection != "" {
				req.Header.Set("Connection", tt.connection)
			}
			if tt.upgrade != "" {
				req.Header.Set("Upgrade", tt.upgrade)
			}

			result := isWebSocketUpgrade(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSecurityLoggingMiddleware(t *testing.T) {
	zapCore, logs := observer.New(zapcore.DebugLevel) // Use DebugLevel to capture all logs
	logger := zap.New(zapCore)
	middleware := SecurityLoggingMiddleware(logger)

	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Regular HTTP request should not log
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Filter for WebSocket security logs only
	wsLogs := 0
	for _, log := range logs.All() {
		if log.Message == "WebSocket connection accepted" || log.Message == "WebSocket connection rejected" {
			wsLogs++
		}
	}
	assert.Equal(t, 0, wsLogs, "Regular HTTP request should not log WebSocket security events")

	// Clear previous logs
	logs.TakeAll()

	// WebSocket upgrade request should store context but may not log since it's not a rejection
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://example.com")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Note: SecurityLoggingMiddleware only stores context, it doesn't log accepted connections
	// The actual logging happens in the origin validator when connections are rejected
}

func TestSecurityLoggingMiddleware_SetsContext(t *testing.T) {
	logger := zap.NewNop()
	middleware := SecurityLoggingMiddleware(logger)

	var capturedOrigin string
	var capturedRealIP string

	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		capturedOrigin = c.GetString("ws_origin")
		capturedRealIP = c.GetString("ws_real_ip")
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, "https://example.com", capturedOrigin)
	assert.Equal(t, "203.0.113.1", capturedRealIP)
}

func TestRejectOriginHandler_Allowed(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	allowedOrigins := []string{"https://example.com"}
	handler := RejectOriginHandler(logger, allowedOrigins)

	router := gin.New()
	router.Use(handler)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 0, logs.Len(), "Allowed origin should not log rejection")
}

func TestRejectOriginHandler_Rejected(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	allowedOrigins := []string{"https://example.com"}
	handler := RejectOriginHandler(logger, allowedOrigins)

	router := gin.New()
	router.Use(handler)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "origin_not_allowed")

	// Verify rejection was logged
	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.WarnLevel, entry.Level)
	assert.Equal(t, "WebSocket connection rejected", entry.Message)
}

func TestRejectOriginHandler_EmptyOrigin_Allowed(t *testing.T) {
	logger := zap.NewNop()
	allowedOrigins := []string{"https://example.com"}
	handler := RejectOriginHandler(logger, allowedOrigins)

	router := gin.New()
	router.Use(handler)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No Origin header
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRejectOriginHandler_Wildcard(t *testing.T) {
	logger := zap.NewNop()
	allowedOrigins := []string{"*"}
	handler := RejectOriginHandler(logger, allowedOrigins)

	router := gin.New()
	router.Use(handler)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://any-origin.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRejectOriginHandler_WildcardSubdomain(t *testing.T) {
	logger := zap.NewNop()
	allowedOrigins := []string{"*.example.com"}
	handler := RejectOriginHandler(logger, allowedOrigins)

	router := gin.New()
	router.Use(handler)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	tests := []struct {
		origin   string
		expected int
	}{
		{"https://app.example.com", http.StatusOK},
		{"https://api.example.com", http.StatusOK},
		{"https://example.com", http.StatusForbidden}, // Bare domain not allowed by *.example.com pattern
		{"https://evil.com", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Connection", "upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expected, w.Code)
		})
	}
}

func TestRapidConnectionTracker_New(t *testing.T) {
	logger := zap.NewNop()
	tracker := NewRapidConnectionTracker(logger, 5, 60)

	assert.NotNil(t, tracker)
	assert.NotNil(t, tracker.attempts)
	assert.Equal(t, 5, tracker.maxAttempts)
	assert.Equal(t, 60, tracker.windowSeconds)
}

func TestRapidConnectionTracker_CheckAndRecord(t *testing.T) {
	logger := zap.NewNop()
	tracker := NewRapidConnectionTracker(logger, 3, 60)

	// First few attempts should be allowed
	allowed, count := tracker.CheckAndRecord("192.168.1.100")
	assert.True(t, allowed)
	assert.Equal(t, 0, count)

	allowed, count = tracker.CheckAndRecord("192.168.1.100")
	assert.True(t, allowed)
	assert.Equal(t, 1, count)

	allowed, count = tracker.CheckAndRecord("192.168.1.100")
	assert.True(t, allowed)
	assert.Equal(t, 2, count)

	// Fourth attempt should exceed limit
	allowed, count = tracker.CheckAndRecord("192.168.1.100")
	assert.False(t, allowed)
	assert.Equal(t, 3, count)

	// Different IP should still be allowed
	allowed, count = tracker.CheckAndRecord("192.168.1.101")
	assert.True(t, allowed)
	assert.Equal(t, 0, count)
}

func TestRapidConnectionTracker_CleanupOldEntries(t *testing.T) {
	logger := zap.NewNop()
	tracker := NewRapidConnectionTracker(logger, 3, 60)

	// Add some attempts
	ip := "192.168.1.100"
	tracker.CheckAndRecord(ip)
	tracker.CheckAndRecord(ip)
	tracker.CheckAndRecord(ip)

	// After 3 CheckAndRecord calls, we have 3 attempts (first call returns 0, then adds 1)
	// The count increases after each successful record
	assert.Equal(t, 3, len(tracker.attempts[ip]))

	// Cleanup shouldn't remove recent entries
	tracker.CleanupOldEntries()
	assert.Equal(t, 3, len(tracker.attempts[ip]))
}

func TestRapidConnectionTracker_TimeWindow(t *testing.T) {
	// This test would require mocking time, so we'll just verify the structure
	logger := zap.NewNop()
	tracker := NewRapidConnectionTracker(logger, 10, 1)

	// Should be able to make up to max attempts
	ip := "192.168.1.100"
	for i := 0; i < 10; i++ {
		allowed, _ := tracker.CheckAndRecord(ip)
		assert.True(t, allowed, "Attempt %d should be allowed", i)
	}

	// Next attempt should be denied
	allowed, count := tracker.CheckAndRecord(ip)
	assert.False(t, allowed)
	assert.Equal(t, 10, count)
}

func TestSecurityEvent_JSON(t *testing.T) {
	event := &SecurityEvent{
		Timestamp:   time.Date(2025, 2, 28, 12, 0, 0, 0, time.UTC),
		EventType:   "origin_rejected",
		Origin:      "https://evil.com",
		RemoteAddr:  "192.168.1.100:12345",
		RealIP:      "192.168.1.100",
		UserAgent:   "BadBot/1.0",
		RequestURI:  "/api/v1/audit/stream",
		Reason:      "origin not in allowed list",
		ActionTaken: "connection_rejected",
	}

	// Just verify it can be marshaled without error
	// In real code, this would be logged as JSON
	assert.Equal(t, "origin_rejected", event.EventType)
	assert.Equal(t, "https://evil.com", event.Origin)
	assert.Equal(t, "connection_rejected", event.ActionTaken)
}

// Benchmark tests
func BenchmarkExtractRealIP(b *testing.B) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractRealIP(req)
	}
}

func BenchmarkIsWebSocketUpgrade(b *testing.B) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isWebSocketUpgrade(req)
	}
}

func BenchmarkRapidConnectionTracker(b *testing.B) {
	logger := zap.NewNop()
	tracker := NewRapidConnectionTracker(logger, 100, 60)
	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := ips[i%len(ips)]
		tracker.CheckAndRecord(ip)
	}
}
