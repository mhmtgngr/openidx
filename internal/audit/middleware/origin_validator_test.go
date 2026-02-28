// Package middleware provides tests for origin validation middleware
package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestDefaultOriginValidationConfig(t *testing.T) {
	cfg := DefaultOriginValidationConfig()

	assert.NotNil(t, cfg)
	assert.Contains(t, cfg.AllowedOrigins, "http://localhost:3000")
	assert.Contains(t, cfg.AllowedOrigins, "http://localhost:5173")
	assert.Contains(t, cfg.AllowedOrigins, "http://127.0.0.1:3000")
	assert.Contains(t, cfg.AllowedOrigins, "http://127.0.0.1:5173")
	assert.Contains(t, cfg.AllowedOrigins, "http://localhost:8080")
	assert.True(t, cfg.EnableLogging)
	assert.True(t, cfg.RejectOnFailure)
	assert.True(t, cfg.AllowEmptyOrigin)
	assert.False(t, cfg.ProductionMode)
}

func TestProductionOriginValidationConfig(t *testing.T) {
	origins := []string{"https://example.com", "https://app.example.com"}
	cfg := ProductionOriginValidationConfig(origins)

	assert.NotNil(t, cfg)
	assert.Equal(t, origins, cfg.AllowedOrigins)
	assert.True(t, cfg.EnableLogging)
	assert.True(t, cfg.RejectOnFailure)
	assert.True(t, cfg.AllowEmptyOrigin)
	assert.True(t, cfg.ProductionMode)
}

func TestProductionOriginValidationConfig_EmptyOrigins(t *testing.T) {
	cfg := ProductionOriginValidationConfig([]string{})

	assert.NotNil(t, cfg)
	assert.Equal(t, []string{}, cfg.AllowedOrigins)
}

func TestOriginValidatorMiddleware_AllowedOrigin(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

func TestOriginValidatorMiddleware_DeniedOrigin(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "origin_not_allowed")
}

func TestOriginValidatorMiddleware_EmptyOrigin_Allowed(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: true,
		ProductionMode:   false,
	}

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No Origin header
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

func TestOriginValidatorMiddleware_EmptyOrigin_Rejected(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No Origin header
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "origin_required")
}

func TestOriginValidatorMiddleware_Wildcard(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"*"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://any-origin.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOriginValidatorMiddleware_WildcardSubdomain(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"*.example.com"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	tests := []struct {
		origin        string
		expectAllowed bool
	}{
		{"https://app.example.com", true},
		{"https://api.example.com", true},
		{"https://sub.sub.example.com", true},
		{"https://example.com", false},
		{"https://evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
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

func TestOriginValidatorMiddleware_SameOriginPolicy(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Create request with same origin
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOriginValidatorMiddleware_ContextValues(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: true,
		ProductionMode:   false,
	}

	var capturedContext *gin.Context

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		capturedContext = c
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.NotNil(t, capturedContext)
	assert.True(t, IsOriginValidated(capturedContext))
	assert.Equal(t, "https://example.com", GetOriginFromContext(capturedContext))
	assert.Equal(t, "https://example.com", capturedContext.GetString("origin"))
	assert.Equal(t, "https://example.com", capturedContext.GetString("matched_pattern"))
}

func TestOriginValidatorMiddleware_NoReject(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com"},
		EnableLogging:    false,
		RejectOnFailure:  false, // Don't reject
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	var capturedContext *gin.Context

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		capturedContext = c
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should pass through even though origin is not allowed
	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedContext)
	assert.False(t, IsOriginValidated(capturedContext))
}

func TestWebSocketOriginValidator(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: true,
		ProductionMode:   false,
	}

	validator := WebSocketOriginValidator(logger, cfg)

	tests := []struct {
		name          string
		origin        string
		host          string
		expected      bool
	}{
		{
			name:     "allowed origin",
			origin:   "https://example.com",
			host:     "example.com",
			expected: true,
		},
		{
			name:     "denied origin",
			origin:   "https://evil.com",
			host:     "evil.com",
			expected: false,
		},
		{
			name:     "empty origin allowed",
			origin:   "",
			host:     "example.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ws", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			req.Host = tt.host

			result := validator(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWebSocketOriginValidator_SameOriginPolicy(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: true,
		ProductionMode:   false,
	}

	validator := WebSocketOriginValidator(logger, cfg)

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Host = "example.com"

	result := validator(req)
	assert.True(t, result, "Same-origin request should be allowed")
}

func TestGetOriginFromContext_NotSet(t *testing.T) {
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		origin := GetOriginFromContext(c)
		assert.Empty(t, origin)
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
}

func TestIsOriginValidated_NotSet(t *testing.T) {
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		validated := IsOriginValidated(c)
		assert.False(t, validated)
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
}

func TestOriginValidatorMiddleware_CaseInsensitive(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	tests := []struct {
		origin string
	}{
		{"https://example.com"},
		{"https://EXAMPLE.COM"},
		{"HTTPS://EXAMPLE.COM"},
		{"HtTpS://ExAmPlE.CoM"},
	}

	for _, origin := range tests {
		t.Run("case: "+origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestOriginValidatorMiddleware_PortNormalization(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	tests := []struct {
		origin   string
		expected int
	}{
		{"https://example.com", http.StatusOK},
		{"https://example.com:443", http.StatusOK},
		{"https://example.com:8443", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run("port: "+tt.origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expected, w.Code)
		})
	}
}

func TestOriginValidatorMiddleware_ProductionMode(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"*"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   true, // Production mode with wildcard
	}

	var contextCaptured bool
	var capturedOrigin string

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		contextCaptured = true
		capturedOrigin = c.GetString("origin")
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// In production mode, wildcard should still work but the code logs it
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, contextCaptured)
	assert.Equal(t, "https://example.com", capturedOrigin)
}

func TestOriginValidatorMiddleware_MultipleOrigins(t *testing.T) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com", "https://app.example.com", "http://localhost:3000"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	tests := []struct {
		origin        string
		expectAllowed bool
	}{
		{"https://example.com", true},
		{"https://app.example.com", true},
		{"http://localhost:3000", true},
		{"https://evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
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

func TestNormalizeOriginUsedInMiddleware(t *testing.T) {
	// Verify that the audit.NormalizeOrigin function is used correctly
	testCases := []struct {
		origin    string
		normalized string
	}{
		{"  HTTP://EXAMPLE.COM  ", "http://example.com"},
		{"https://example.com:443", "https://example.com"},
		{"http://localhost:80", "http://localhost"},
	}

	for _, tc := range testCases {
		t.Run(tc.origin, func(t *testing.T) {
			result := audit.NormalizeOrigin(tc.origin)
			assert.Equal(t, tc.normalized, result)
		})
	}
}

// Test that nil config defaults to DefaultOriginValidationConfig
func TestOriginValidatorMiddleware_NilConfig(t *testing.T) {
	logger := zap.NewNop()

	router := gin.New()
	router.Use(OriginValidatorMiddleware(logger, nil))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Test with default allowed origin
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// Benchmark tests
func BenchmarkOriginValidatorMiddleware(b *testing.B) {
	logger := zap.NewNop()
	cfg := &OriginValidationConfig{
		AllowedOrigins:   []string{"https://example.com", "*.app.example.com"},
		EnableLogging:    false,
		RejectOnFailure:  true,
		AllowEmptyOrigin: false,
		ProductionMode:   false,
	}

	middleware := OriginValidatorMiddleware(logger, cfg)

	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
