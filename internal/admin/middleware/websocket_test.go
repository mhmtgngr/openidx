// Package middleware provides tests for admin API WebSocket middleware
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestNewWebSocketOriginValidator(t *testing.T) {
	logger := zap.NewNop()
	cfg := &WebSocketOriginConfig{
		AllowedOrigins: []string{"https://example.com"},
		EnableLogging:  true,
	}

	validator := NewWebSocketOriginValidator(logger, cfg)

	assert.NotNil(t, validator)
	assert.NotNil(t, validator.logger)
	assert.NotNil(t, validator.config)
}

func TestNewWebSocketOriginValidator_NilConfig(t *testing.T) {
	logger := zap.NewNop()
	validator := NewWebSocketOriginValidator(logger, nil)

	assert.NotNil(t, validator)
	assert.NotNil(t, validator.config)
	assert.Equal(t, []string{}, validator.config.AllowedOrigins)
	assert.True(t, validator.config.EnableLogging)
}

func TestWebSocketOriginValidator_CheckOrigin_NoOrigin(t *testing.T) {
	logger := zap.NewNop()
	cfg := &WebSocketOriginConfig{
		AllowedOrigins: []string{"https://example.com"},
		EnableLogging:  true,
	}
	validator := NewWebSocketOriginValidator(logger, cfg)

	req := httptest.NewRequest("GET", "/ws", nil)
	// No Origin header

	result := validator.CheckOrigin(req)

	assert.True(t, result, "Non-browser requests without Origin should be allowed")
}

func TestWebSocketOriginValidator_CheckOrigin_ExactMatch(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	cfg := &WebSocketOriginConfig{
		AllowedOrigins: []string{"https://example.com"},
		EnableLogging:  true,
	}
	validator := NewWebSocketOriginValidator(logger, cfg)

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", "https://example.com")

	result := validator.CheckOrigin(req)

	assert.True(t, result)
	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.InfoLevel, entry.Level)
	assert.Equal(t, "Admin WebSocket connection allowed", entry.Message)
}

func TestWebSocketOriginValidator_CheckOrigin_CaseInsensitive(t *testing.T) {
	logger := zap.NewNop()
	cfg := &WebSocketOriginConfig{
		AllowedOrigins: []string{"https://example.com"},
		EnableLogging:  false,
	}
	validator := NewWebSocketOriginValidator(logger, cfg)

	tests := []struct {
		name   string
		origin string
	}{
		{"lowercase", "https://example.com"},
		{"uppercase", "HTTPS://EXAMPLE.COM"},
		{"mixed case", "HtTpS://ExAmPlE.CoM"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ws", nil)
			req.Header.Set("Origin", tt.origin)

			result := validator.CheckOrigin(req)
			assert.True(t, result)
		})
	}
}

func TestWebSocketOriginValidator_CheckOrigin_Wildcard(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	cfg := &WebSocketOriginConfig{
		AllowedOrigins: []string{"*"},
		EnableLogging:  true,
	}
	validator := NewWebSocketOriginValidator(logger, cfg)

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", "https://any-origin.com")

	result := validator.CheckOrigin(req)

	assert.True(t, result)
	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.WarnLevel, entry.Level, "Wildcard should log a warning")
	assert.Equal(t, "Admin WebSocket wildcard origin allowed", entry.Message)
}

func TestWebSocketOriginValidator_CheckOrigin_WildcardSubdomain(t *testing.T) {
	logger := zap.NewNop()
	cfg := &WebSocketOriginConfig{
		AllowedOrigins: []string{"*.example.com"},
		EnableLogging:  false,
	}
	validator := NewWebSocketOriginValidator(logger, cfg)

	tests := []struct {
		origin   string
		expected bool
	}{
		{"https://app.example.com", true},
		{"https://api.example.com", true},
		{"https://sub.sub.example.com", true},
		{"https://example.com", false}, // Bare domain not allowed by *.example.com pattern
		{"https://evil.com", false},
		{"https://example.com.evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ws", nil)
			req.Header.Set("Origin", tt.origin)

			result := validator.CheckOrigin(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWebSocketOriginValidator_CheckOrigin_Rejected(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	cfg := &WebSocketOriginConfig{
		AllowedOrigins: []string{"https://example.com"},
		EnableLogging:  true,
	}
	validator := NewWebSocketOriginValidator(logger, cfg)

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("User-Agent", "BadBot/1.0")

	result := validator.CheckOrigin(req)

	assert.False(t, result)
	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.WarnLevel, entry.Level)
	assert.Equal(t, "Admin WebSocket connection rejected", entry.Message)
}

func TestAdminWebSocketOriginMiddleware_WebSocketRequest_Allowed(t *testing.T) {
	logger := zap.NewNop()
	allowedOrigins := []string{"https://example.com"}

	router := gin.New()
	router.Use(AdminWebSocketOriginMiddleware(logger, allowedOrigins))
	router.GET("/ws", func(c *gin.Context) {
		c.String(http.StatusOK, "WebSocket upgraded")
	})

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminWebSocketOriginMiddleware_WebSocketRequest_Rejected(t *testing.T) {
	logger := zap.NewNop()
	allowedOrigins := []string{"https://example.com"}

	router := gin.New()
	router.Use(AdminWebSocketOriginMiddleware(logger, allowedOrigins))
	router.GET("/ws", func(c *gin.Context) {
		c.String(http.StatusOK, "WebSocket upgraded")
	})

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "websocket_origin_not_allowed")
}

func TestAdminWebSocketOriginMiddleware_NonWebSocketRequest(t *testing.T) {
	logger := zap.NewNop()
	allowedOrigins := []string{"https://example.com"}

	router := gin.New()
	router.Use(AdminWebSocketOriginMiddleware(logger, allowedOrigins))
	router.GET("/api/data", func(c *gin.Context) {
		c.String(http.StatusOK, "data")
	})

	// Regular HTTP request without WebSocket upgrade headers
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should pass through - middleware only checks WebSocket upgrade requests
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminWebSocketOriginMiddleware_EmptyAllowedOrigins(t *testing.T) {
	logger := zap.NewNop()
	allowedOrigins := []string{}

	router := gin.New()
	router.Use(AdminWebSocketOriginMiddleware(logger, allowedOrigins))
	router.GET("/ws", func(c *gin.Context) {
		c.String(http.StatusOK, "WebSocket upgraded")
	})

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://any-origin.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Empty list = same-origin only, but with different host should fail
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestIsWebSocketUpgradeRequest(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		upgrade    string
		expected   bool
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
			name:       "missing connection",
			connection: "",
			upgrade:    "websocket",
			expected:   false,
		},
		{
			name:       "missing upgrade",
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

			result := isWebSocketUpgradeRequest(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWebSocketOriginValidator_UpdateAllowedOrigins(t *testing.T) {
	logger := zap.NewNop()
	cfg := &WebSocketOriginConfig{
		AllowedOrigins: []string{"https://example.com"},
		EnableLogging:  false,
	}
	validator := NewWebSocketOriginValidator(logger, cfg)

	assert.Equal(t, []string{"https://example.com"}, validator.GetAllowedOrigins())

	newOrigins := []string{"https://app.example.com", "https://api.example.com"}
	validator.UpdateAllowedOrigins(newOrigins)

	assert.Equal(t, newOrigins, validator.GetAllowedOrigins())
}

func TestWebSocketOriginValidator_GetAllowedOrigins(t *testing.T) {
	logger := zap.NewNop()
	cfg := &WebSocketOriginConfig{
		AllowedOrigins: []string{"https://example.com", "https://app.example.com"},
		EnableLogging:  false,
	}
	validator := NewWebSocketOriginValidator(logger, cfg)

	origins := validator.GetAllowedOrigins()

	assert.Equal(t, 2, len(origins))
	assert.Contains(t, origins, "https://example.com")
	assert.Contains(t, origins, "https://app.example.com")
}

func TestLogAdminWebSocketSecurityEvent(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)

	event := &AdminWebSocketSecurityEvent{
		Timestamp:  "2025-02-28T12:00:00Z",
		EventType:  "origin_rejected",
		Origin:     "https://evil.com",
		RemoteAddr: "192.168.1.100:12345",
		UserAgent:  "BadBot/1.0",
		Reason:     "origin not in allowed list",
	}

	LogAdminWebSocketSecurityEvent(logger, event)

	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.WarnLevel, entry.Level)
	assert.Equal(t, "Admin WebSocket security event", entry.Message)
	contextMap := entry.ContextMap()
	assert.Equal(t, "origin_rejected", contextMap["event_type"])
	assert.Equal(t, "https://evil.com", contextMap["origin"])
}

func TestAdminWebSocketSecurityEvent_Serialization(t *testing.T) {
	event := &AdminWebSocketSecurityEvent{
		Timestamp:  "2025-02-28T12:00:00Z",
		EventType:  "origin_rejected",
		Origin:     "https://evil.com",
		RemoteAddr: "192.168.1.100:12345",
		UserAgent:  "BadBot/1.0",
		Reason:     "origin not in allowed list",
	}

	// Verify the struct fields are correctly set
	assert.Equal(t, "2025-02-28T12:00:00Z", event.Timestamp)
	assert.Equal(t, "origin_rejected", event.EventType)
	assert.Equal(t, "https://evil.com", event.Origin)
	assert.Equal(t, "192.168.1.100:12345", event.RemoteAddr)
	assert.Equal(t, "BadBot/1.0", event.UserAgent)
	assert.Equal(t, "origin not in allowed list", event.Reason)
}

func TestAdminWebSocketOriginMiddleware_MultipleOrigins(t *testing.T) {
	logger := zap.NewNop()
	allowedOrigins := []string{
		"https://example.com",
		"https://app.example.com",
		"https://admin.example.com",
	}

	router := gin.New()
	router.Use(AdminWebSocketOriginMiddleware(logger, allowedOrigins))
	router.GET("/ws", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	tests := []struct {
		origin        string
		expectAllowed bool
	}{
		{"https://example.com", true},
		{"https://app.example.com", true},
		{"https://admin.example.com", true},
		{"https://evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ws", nil)
			req.Header.Set("Connection", "upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if tt.expectAllowed {
				assert.Equal(t, http.StatusOK, w.Code)
			} else {
				assert.Equal(t, http.StatusForbidden, w.Code)
			}
		})
	}
}

func TestAdminWebSocketOriginMiddleware_Wildcard(t *testing.T) {
	logger := zap.NewNop()
	allowedOrigins := []string{"*"}

	router := gin.New()
	router.Use(AdminWebSocketOriginMiddleware(logger, allowedOrigins))
	router.GET("/ws", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://any-origin.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminWebSocketOriginMiddleware_NoOrigin(t *testing.T) {
	logger := zap.NewNop()
	allowedOrigins := []string{"https://example.com"}

	router := gin.New()
	router.Use(AdminWebSocketOriginMiddleware(logger, allowedOrigins))
	router.GET("/ws", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	// No Origin header
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Non-browser requests without Origin should be allowed
	assert.Equal(t, http.StatusOK, w.Code)
}

// Benchmark tests
func BenchmarkWebSocketOriginValidator_CheckOrigin(b *testing.B) {
	logger := zap.NewNop()
	cfg := &WebSocketOriginConfig{
		AllowedOrigins: []string{"https://example.com", "*.app.example.com"},
		EnableLogging:  false,
	}
	validator := NewWebSocketOriginValidator(logger, cfg)

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", "https://api.app.example.com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.CheckOrigin(req)
	}
}

func BenchmarkIsWebSocketUpgradeRequest(b *testing.B) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isWebSocketUpgradeRequest(req)
	}
}
