package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	// Set Gin to test mode to prevent verbose output
	gin.SetMode(gin.TestMode)
}

func TestSecurityHeaders_DefaultConfig(t *testing.T) {
	router := gin.New()
	router.Use(SecurityHeaders(DefaultSecurityConfig()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify all security headers are set
	headers := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"X-XSS-Protection":        "1; mode=block",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Permissions-Policy":      "geolocation=(), microphone=(), camera=()",
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
	}

	for header, expected := range headers {
		assert.Equal(t, expected, w.Header().Get(header), "Header %s should match", header)
	}

	// HSTS should not be set for non-TLS requests
	assert.Empty(t, w.Header().Get("Strict-Transport-Security"), "HSTS should not be set for non-TLS")
}

func TestSecurityHeaders_WithTLS(t *testing.T) {
	router := gin.New()
	router.Use(SecurityHeaders(SecurityConfig{
		HSTSEnabled:  true,
		CSPEnabled:   true,
		FrameOptions: "DENY",
	}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// Simulate TLS connection
	req.TLS = &tls.ConnectionState{}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "max-age=31536000; includeSubDomains", w.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_HSTSDisabled(t *testing.T) {
	router := gin.New()
	router.Use(SecurityHeaders(SecurityConfig{
		HSTSEnabled: false,
		CSPEnabled:  true,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Strict-Transport-Security"), "HSTS should not be set when disabled")
}

func TestSecurityHeaders_CSPDisabled(t *testing.T) {
	router := gin.New()
	router.Use(SecurityHeaders(SecurityConfig{
		HSTSEnabled: false,
		CSPEnabled:  false,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Content-Security-Policy"), "CSP should not be set when disabled")
}

func TestSecurityHeaders_CustomCSP(t *testing.T) {
	customCSP := "default-src 'self' https://trusted.example.com; script-src 'self' 'unsafe-inline' https://cdn.example.com"

	router := gin.New()
	router.Use(SecurityHeaders(SecurityConfig{
		HSTSEnabled: false,
		CSPEnabled:  true,
		CSPCustom:   customCSP,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, customCSP, w.Header().Get("Content-Security-Policy"))
}

func TestSecurityHeaders_FrameOptions(t *testing.T) {
	tests := []struct {
		name         string
		frameOptions string
		expected     string
	}{
		{
			name:         "DENY",
			frameOptions: "DENY",
			expected:     "DENY",
		},
		{
			name:         "SAMEORIGIN",
			frameOptions: "SAMEORIGIN",
			expected:     "SAMEORIGIN",
		},
		{
			name:         "ALLOW-FROM",
			frameOptions: "ALLOW-FROM https://example.com",
			expected:     "ALLOW-FROM https://example.com",
		},
		{
			name:         "Invalid defaults to DENY",
			frameOptions: "INVALID",
			expected:     "DENY",
		},
		{
			name:         "Lowercase deny is normalized",
			frameOptions: "deny",
			expected:     "DENY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(SecurityHeaders(SecurityConfig{
				FrameOptions: tt.frameOptions,
			}))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "ok")
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expected, w.Header().Get("X-Frame-Options"))
		})
	}
}

func TestSecurityHeadersProduction(t *testing.T) {
	router := gin.New()
	router.Use(SecurityHeadersProduction())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify all headers are set
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "geolocation=(), microphone=(), camera=()", w.Header().Get("Permissions-Policy"))
	assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
}

func TestSecurityHeadersDevelopment(t *testing.T) {
	router := gin.New()
	router.Use(SecurityHeadersDevelopment())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// HSTS should be disabled in development mode
	assert.Empty(t, w.Header().Get("Strict-Transport-Security"))

	// Other headers should still be set
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
}

func TestCustomFrameOptions(t *testing.T) {
	router := gin.New()
	router.Use(CustomFrameOptions("SAMEORIGIN"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, "SAMEORIGIN", w.Header().Get("X-Frame-Options"))
}

func TestCustomCSP(t *testing.T) {
	customCSP := "default-src 'self' https://cdn.example.com"

	router := gin.New()
	router.Use(CustomCSP(customCSP))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, customCSP, w.Header().Get("Content-Security-Policy"))
}

func TestSecurityHeaders_AllHeadersPresent(t *testing.T) {
	router := gin.New()
	router.Use(SecurityHeaders(DefaultSecurityConfig()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	requiredHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Permissions-Policy",
		"Content-Security-Policy",
	}

	for _, header := range requiredHeaders {
		assert.NotEmpty(t, w.Header().Get(header), "Header %s should be set", header)
	}
}
