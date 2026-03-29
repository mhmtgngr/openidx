// Package audit provides tests for WebSocket origin validation
package audit

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewEventStreamer_WithAllowedOrigins(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	allowedOrigins := []string{"https://example.com", "http://localhost:3000"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	assert.NotNil(t, streamer)
	assert.NotNil(t, streamer.originValidator)
	assert.NotNil(t, streamer.upgrader)

	// Verify upgrader uses the origin validator
	assert.NotNil(t, streamer.upgrader.CheckOrigin)
}

func TestNewEventStreamerWithConfig(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)

	streamConfig := &StreamConfig{
		AllowedOrigins:        []string{"https://example.com", "*.app.example.com"},
		EnableSecurityLogging: true,
		MaxMessageSize:        4096,
		WriteTimeout:          5,
		ReadTimeout:           30,
		PingInterval:          15,
		PongTimeout:           30,
	}

	streamer := NewEventStreamerWithConfig(logger, service, streamConfig)

	assert.NotNil(t, streamer)
	assert.NotNil(t, streamer.originValidator)
	assert.NotNil(t, streamer.upgrader)

	// Check that config was applied
	assert.Equal(t, 4096, streamer.upgrader.ReadBufferSize)
	assert.Equal(t, 4096, streamer.upgrader.WriteBufferSize)
}

func TestNewEventStreamerWithConfig_NilConfig(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)

	streamer := NewEventStreamerWithConfig(logger, service, nil)

	assert.NotNil(t, streamer)
	// Should use defaults from DefaultStreamConfig
	assert.Equal(t, 65536, streamer.upgrader.ReadBufferSize) // 1024 * 64 from MaxMessageSize
	assert.Equal(t, 65536, streamer.upgrader.WriteBufferSize)
}

func TestEventStreamer_GetAllowedOrigins(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	allowedOrigins := []string{"https://example.com", "http://localhost:3000"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	result := streamer.GetAllowedOrigins()
	assert.Equal(t, allowedOrigins, result)
}

func TestEventStreamer_UpdateAllowedOrigins(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	service := createTestService(t)

	streamer := NewEventStreamer(logger, service, []string{"https://example.com"})

	// Clear any logs from initialization
	logs.TakeAll()

	newOrigins := []string{"https://app.example.com", "*.api.example.com"}
	streamer.UpdateAllowedOrigins(newOrigins)

	assert.Equal(t, newOrigins, streamer.GetAllowedOrigins())

	// Verify logging - UpdateAllowedOrigins generates 2 logs:
	// 1. "WebSocket origin validator updated" from OriginValidator.UpdateAllowedOrigins
	// 2. "WebSocket allowed origins updated" from EventStreamer.UpdateAllowedOrigins
	allLogs := logs.All()
	require.GreaterOrEqual(t, len(allLogs), 1, "Expected at least one log entry")

	// Find the EventStreamer log
	found := false
	for _, entry := range allLogs {
		if entry.Message == "WebSocket allowed origins updated" {
			found = true
			contextMap := entry.ContextMap()
			assert.Equal(t, int64(2), contextMap["origin_count"])
			break
		}
	}
	assert.True(t, found, "Expected to find 'WebSocket allowed origins updated' log")
}

func TestEventStreamer_GetOriginValidator(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	allowedOrigins := []string{"https://example.com"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	validator := streamer.GetOriginValidator()
	assert.NotNil(t, validator)
	assert.Same(t, streamer.originValidator, validator)
}

func TestEventStreamer_CheckOrigin_Allowed(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	allowedOrigins := []string{"https://example.com"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "https://example.com")

	result := streamer.originValidator.CheckOrigin(req)
	assert.True(t, result)
}

func TestEventStreamer_CheckOrigin_Denied(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	service := createTestService(t)
	allowedOrigins := []string{"https://example.com"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("User-Agent", "BadBot/1.0")

	result := streamer.originValidator.CheckOrigin(req)
	assert.False(t, result)

	// Verify security logging
	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.WarnLevel, entry.Level)
	assert.Equal(t, "WebSocket connection rejected", entry.Message)
}

func TestEventStreamer_CheckOrigin_Wildcard(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	allowedOrigins := []string{"*"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "https://any-origin.com")

	result := streamer.originValidator.CheckOrigin(req)
	assert.True(t, result)
}

func TestEventStreamer_CheckOrigin_WildcardSubdomain(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	allowedOrigins := []string{"*.example.com"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	tests := []struct {
		origin   string
		expected bool
	}{
		{"https://app.example.com", true},
		{"https://api.example.com", true},
		{"https://example.com", false},
		{"https://evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
			req.Header.Set("Origin", tt.origin)

			result := streamer.originValidator.CheckOrigin(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEventStreamer_CheckOrigin_NoOrigin(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	allowedOrigins := []string{"https://example.com"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	// No Origin header

	result := streamer.originValidator.CheckOrigin(req)
	assert.True(t, result, "Non-browser requests without Origin should be allowed")
}

func TestEventStreamer_CheckOrigin_SameOriginPolicy(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)

	// Empty allowedOrigins means same-origin policy
	streamer := NewEventStreamer(logger, service, []string{})

	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"

	result := streamer.originValidator.CheckOrigin(req)
	assert.True(t, result, "Same-origin request should be allowed")
}

func TestEventStreamer_CheckOrigin_SameOriginPolicy_Denied(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	service := createTestService(t)

	// Empty allowedOrigins means same-origin policy
	streamer := NewEventStreamer(logger, service, []string{})

	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.Host = "example.com"

	result := streamer.originValidator.CheckOrigin(req)
	assert.False(t, result, "Cross-origin request should be denied")

	// Verify security logging
	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.WarnLevel, entry.Level)
	contextMap := entry.ContextMap()
	assert.Equal(t, "same-origin policy violation", contextMap["reason"])
}

func TestEventStreamer_WebSocketUpgrade_AllowedOrigin(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	allowedOrigins := []string{"http://example.com"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	// Test the CheckOrigin function directly for allowed origin
	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "http://example.com")

	result := streamer.originValidator.CheckOrigin(req)

	// The origin should be allowed
	assert.True(t, result, "Allowed origin should pass CheckOrigin")
}

func TestEventStreamer_WebSocketUpgrade_DeniedOrigin(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	service := createTestService(t)
	allowedOrigins := []string{"http://example.com"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	// Test the CheckOrigin function directly for disallowed origin
	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "http://evil.com")
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("User-Agent", "BadBot/1.0")

	result := streamer.originValidator.CheckOrigin(req)

	// The origin should be rejected
	assert.False(t, result, "Disallowed origin should be rejected by CheckOrigin")

	// Verify the rejection was logged
	found := false
	for _, log := range logs.All() {
		if log.Message == "WebSocket connection rejected" {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected to find rejection log")
}

func TestEventStreamer_UpdateAllowedOrigins_Runtime(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)

	streamer := NewEventStreamer(logger, service, []string{"https://example.com"})

	// Initially only example.com is allowed
	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "https://app.example.com")
	result := streamer.originValidator.CheckOrigin(req)
	assert.False(t, result)

	// Update allowed origins to include subdomains
	streamer.UpdateAllowedOrigins([]string{"*.example.com"})

	// Now app.example.com should be allowed
	req = httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "https://app.example.com")
	result = streamer.originValidator.CheckOrigin(req)
	assert.True(t, result)
}

func TestEventStreamer_IsWildcardAllowed(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)

	tests := []struct {
		name          string
		allowedOrigins []string
		expected      bool
	}{
		{
			name:          "wildcard present",
			allowedOrigins: []string{"*"},
			expected:      true,
		},
		{
			name:          "wildcard with dot",
			allowedOrigins: []string{"*."},
			expected:      true,
		},
		{
			name:          "wildcard subdomain",
			allowedOrigins: []string{"*.example.com"},
			expected:      false,
		},
		{
			name:          "specific origins only",
			allowedOrigins: []string{"https://example.com"},
			expected:      false,
		},
		{
			name:          "empty list",
			allowedOrigins: []string{},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			streamer := NewEventStreamer(logger, service, tt.allowedOrigins)
			result := streamer.originValidator.IsWildcardAllowed()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEventStreamer_SecurityLogging(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	service := createTestService(t)

	// Create streamer with security logging enabled
	streamConfig := &StreamConfig{
		AllowedOrigins:        []string{"https://example.com"},
		EnableSecurityLogging: true,
	}
	streamer := NewEventStreamerWithConfig(logger, service, streamConfig)

	// Make a request with disallowed origin
	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("User-Agent", "BadBot/1.0")
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	streamer.originValidator.CheckOrigin(req)

	// Verify security details were logged
	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.WarnLevel, entry.Level)
	contextMap := entry.ContextMap()
	assert.Equal(t, "https://evil.com", contextMap["origin"])
	assert.Equal(t, "192.168.1.100:12345", contextMap["remote_addr"])
	assert.Equal(t, "203.0.113.1", contextMap["real_ip"])
	assert.Equal(t, "BadBot/1.0", contextMap["user_agent"])
}

func TestEventStreamer_SecurityLoggingDisabled(t *testing.T) {
	zapCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(zapCore)
	service := createTestService(t)

	// Create streamer with security logging disabled
	streamConfig := &StreamConfig{
		AllowedOrigins:        []string{"https://example.com"},
		EnableSecurityLogging: false,
	}
	streamer := NewEventStreamerWithConfig(logger, service, streamConfig)

	// Make a request with disallowed origin
	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.RemoteAddr = "192.168.1.100:12345"

	streamer.originValidator.CheckOrigin(req)

	// Verify nothing was logged
	assert.Equal(t, 0, logs.Len())
}

func TestEventStreamer_ConcurrentAccess(t *testing.T) {
	logger := zap.NewNop()
	service := createTestService(t)
	allowedOrigins := []string{"https://example.com"}

	streamer := NewEventStreamer(logger, service, allowedOrigins)

	// Test concurrent access to GetAllowedOrigins and UpdateAllowedOrigins
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			streamer.GetAllowedOrigins()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			streamer.UpdateAllowedOrigins([]string{"https://example.com"})
		}
		done <- true
	}()

	<-done
	<-done

	// Should complete without race condition
	assert.True(t, true)
}

// Benchmark tests
func BenchmarkEventStreamer_CheckOrigin(b *testing.B) {
	logger := zap.NewNop()
	service := createTestService(&testing.T{})
	allowedOrigins := []string{"https://example.com", "*.app.example.com", "http://localhost:3000"}
	streamer := NewEventStreamer(logger, service, allowedOrigins)

	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "https://api.app.example.com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		streamer.originValidator.CheckOrigin(req)
	}
}

func BenchmarkEventStreamer_CheckOrigin_SameOrigin(b *testing.B) {
	logger := zap.NewNop()
	service := createTestService(&testing.T{})
	streamer := NewEventStreamer(logger, service, []string{})

	req := httptest.NewRequest("GET", "/api/v1/audit/stream", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		streamer.originValidator.CheckOrigin(req)
	}
}
