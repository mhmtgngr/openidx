// Package middleware provides tests for CORS middleware
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestCORSMiddlewareDefaults tests the default CORS configuration
func TestCORSMiddlewareDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotNil(t, cfg)
	assert.Contains(t, cfg.AllowedOrigins, "http://localhost:5173")
	assert.Contains(t, cfg.AllowedOrigins, "http://localhost:3000")
	assert.Contains(t, cfg.AllowedMethods, "GET")
	assert.Contains(t, cfg.AllowedMethods, "POST")
	assert.Contains(t, cfg.AllowedMethods, "PUT")
	assert.Contains(t, cfg.AllowedMethods, "DELETE")
	assert.Contains(t, cfg.AllowedMethods, "OPTIONS")
	assert.True(t, cfg.AllowCredentials)
	assert.Equal(t, 86400, cfg.MaxAge)
}

// TestCORSMiddlewareProductionConfig tests production CORS configuration
func TestCORSMiddlewareProductionConfig(t *testing.T) {
	origins := []string{"https://example.com", "https://app.example.com"}
	cfg := ProductionConfig(origins)

	assert.NotNil(t, cfg)
	assert.Equal(t, origins, cfg.AllowedOrigins)
	assert.True(t, cfg.AllowCredentials)
	assert.Equal(t, 86400, cfg.MaxAge)
	assert.NotContains(t, cfg.AllowedMethods, "OPTIONS") // Production doesn't include OPTIONS by default
}

// TestCORSMiddlewareWithNilConfig tests that nil config defaults to DefaultConfig
func TestCORSMiddlewareWithNilConfig(t *testing.T) {
	router := gin.New()
	router.Use(CORSMiddleware(nil))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Origin"), "http://localhost:5173")
}

// TestCORSMiddlewareAllowedOrigin tests allowed origin handling
func TestCORSMiddlewareAllowedOrigin(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		expectAllowed  bool
		expectedHeader string
	}{
		{
			name:           "localhost 5173 allowed",
			origin:         "http://localhost:5173",
			expectAllowed:  true,
			expectedHeader: "http://localhost:5173",
		},
		{
			name:           "localhost 3000 allowed",
			origin:         "http://localhost:3000",
			expectAllowed:  true,
			expectedHeader: "http://localhost:3000",
		},
		{
			name:           "127.0.0.1 5173 allowed",
			origin:         "http://127.0.0.1:5173",
			expectAllowed:  true,
			expectedHeader: "http://127.0.0.1:5173",
		},
		{
			name:          "unknown origin forbidden",
			origin:        "http://evil.com",
			expectAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(CORSMiddleware(DefaultConfig()))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "ok")
			})

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if tt.expectAllowed {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, tt.expectedHeader, w.Header().Get("Access-Control-Allow-Origin"))
			} else {
				assert.Equal(t, http.StatusForbidden, w.Code)
			}
		})
	}
}

// TestCORSMiddlewarePreflight tests preflight request handling
func TestCORSMiddlewarePreflight(t *testing.T) {
	router := gin.New()
	router.Use(CORSMiddleware(DefaultConfig()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Authorization")
}

// TestCORSMiddlewareNoOrigin tests requests without Origin header
func TestCORSMiddlewareNoOrigin(t *testing.T) {
	router := gin.New()
	router.Use(CORSMiddleware(DefaultConfig()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// No CORS headers should be set for non-browser requests
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

// TestCORSMiddlewareWildcard tests wildcard origin support
func TestCORSMiddlewareWildcard(t *testing.T) {
	cfg := &Config{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: false,
		MaxAge:           86400,
	}

	router := gin.New()
	router.Use(CORSMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Any origin should be allowed with wildcard
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://any-origin.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

// TestCORSMiddlewareWildcardSubdomain tests wildcard subdomain support
func TestCORSMiddlewareWildcardSubdomain(t *testing.T) {
	cfg := &Config{
		AllowedOrigins:   []string{"*.example.com"},
		AllowedMethods:   []string{"GET"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           86400,
	}

	tests := []struct {
		name          string
		origin        string
		expectAllowed bool
	}{
		{
			name:          "app.example.com allowed",
			origin:        "https://app.example.com",
			expectAllowed: true,
		},
		{
			name:          "api.example.com allowed",
			origin:        "https://api.example.com",
			expectAllowed: true,
		},
		{
			name:          "sub.sub.example.com allowed",
			origin:        "https://sub.sub.example.com",
			expectAllowed: true,
		},
		{
			name:          "example.com NOT allowed (bare domain with wildcard *.example.com)",
			origin:        "https://example.com",
			expectAllowed: false,
		},
		{
			name:          "evil.com forbidden",
			origin:        "https://evil.com",
			expectAllowed: false,
		},
		{
			name:          "example.com.evil.com forbidden",
			origin:        "https://example.com.evil.com",
			expectAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(CORSMiddleware(cfg))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "ok")
			})

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if tt.expectAllowed {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, tt.origin, w.Header().Get("Access-Control-Allow-Origin"))
			} else {
				assert.Equal(t, http.StatusForbidden, w.Code)
			}
		})
	}
}

// TestCORSMiddlewareExposedHeaders tests exposed headers
func TestCORSMiddlewareExposedHeaders(t *testing.T) {
	router := gin.New()
	router.Use(CORSMiddleware(DefaultConfig()))
	router.GET("/test", func(c *gin.Context) {
		c.Header("X-Request-ID", "12345")
		c.Header("X-Total-Count", "100")
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	exposedHeaders := w.Header().Get("Access-Control-Expose-Headers")
	assert.Contains(t, exposedHeaders, "X-Request-ID")
	assert.Contains(t, exposedHeaders, "X-Total-Count")
	assert.Contains(t, exposedHeaders, "Content-Range")
}

// TestCORSMiddlewareCredentials tests credentials header
func TestCORSMiddlewareCredentials(t *testing.T) {
	cfg := &Config{
		AllowedOrigins:   []string{"http://localhost:5173"},
		AllowedMethods:   []string{"GET"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           86400,
	}

	router := gin.New()
	router.Use(CORSMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

// TestCORSMiddlewareVaryHeader tests Vary header for specific origins
func TestCORSMiddlewareVaryHeader(t *testing.T) {
	router := gin.New()
	router.Use(CORSMiddleware(DefaultConfig()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "Origin", w.Header().Get("Vary"))
}

// TestCORSMiddlewareMaxAge tests Max-Age header
func TestCORSMiddlewareMaxAge(t *testing.T) {
	cfg := &Config{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: false,
		MaxAge:           3600,
	}

	router := gin.New()
	router.Use(CORSMiddleware(cfg))
	router.OPTIONS("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "3600", w.Header().Get("Access-Control-Max-Age"))
}

// TestCORSConvenienceFunction tests the CORS convenience function
func TestCORSConvenienceFunction(t *testing.T) {
	router := gin.New()
	router.Use(CORS("https://example.com"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

// TestCORSConvenienceFunctionMultipleOrigins tests the CORS function with multiple origins
func TestCORSConvenienceFunctionMultipleOrigins(t *testing.T) {
	router := gin.New()
	router.Use(CORS("https://example.com", "https://app.example.com"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	tests := []struct {
		origin        string
		expectAllowed bool
	}{
		{"https://example.com", true},
		{"https://app.example.com", true},
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

// TestCORSMiddlewareMethodNormalization tests method case normalization
func TestCORSMiddlewareMethodNormalization(t *testing.T) {
	cfg := &Config{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"get", "post", "put"}, // lowercase
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: false,
		MaxAge:           86400,
	}

	router := gin.New()
	router.Use(CORSMiddleware(cfg))
	router.OPTIONS("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	methodsHeader := w.Header().Get("Access-Control-Allow-Methods")
	// Methods should be normalized to uppercase
	assert.Contains(t, methodsHeader, "GET")
	assert.Contains(t, methodsHeader, "POST")
	assert.Contains(t, methodsHeader, "PUT")
}

// TestCORSMiddlewareAllowedHeaders tests allowed headers
func TestCORSMiddlewareAllowedHeaders(t *testing.T) {
	router := gin.New()
	router.Use(CORSMiddleware(DefaultConfig()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	allowedHeaders := w.Header().Get("Access-Control-Allow-Headers")
	assert.Contains(t, allowedHeaders, "Origin")
	assert.Contains(t, allowedHeaders, "Content-Type")
	assert.Contains(t, allowedHeaders, "Authorization")
	assert.Contains(t, allowedHeaders, "X-Request-ID")
	assert.Contains(t, allowedHeaders, "Accept")
	assert.Contains(t, allowedHeaders, "X-Tenant-ID")
}
