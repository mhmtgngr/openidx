// Package api provides API versioning and negotiation for OpenIDX services
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestVersionMiddleware(t *testing.T) {
	router := gin.New()
	router.Use(VersionMiddleware("1.0", []string{"1.0", "1"}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "1.0", w.Header().Get(HeaderAPIVersion))
}

func TestVersionMiddleware_SupportedVersion(t *testing.T) {
	router := gin.New()
	router.Use(VersionMiddleware("1.0", []string{"1.0", "2.0"}))
	router.GET("/test", func(c *gin.Context) {
		version := GetVersion(c)
		c.String(http.StatusOK, version)
	})

	tests := []struct {
		name           string
		requestVersion string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "no version header",
			requestVersion: "",
			expectedStatus: http.StatusOK,
			expectedBody:   "1.0",
		},
		{
			name:           "supported version 1.0",
			requestVersion: "1.0",
			expectedStatus: http.StatusOK,
			expectedBody:   "1.0",
		},
		{
			name:           "supported version 2.0",
			requestVersion: "2.0",
			expectedStatus: http.StatusOK,
			expectedBody:   "2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			if tt.requestVersion != "" {
				req.Header.Set(HeaderAPIVersionRequest, tt.requestVersion)
			}
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, tt.expectedBody, w.Body.String())
		})
	}
}

func TestVersionMiddleware_UnsupportedVersion(t *testing.T) {
	router := gin.New()
	router.Use(VersionMiddleware("1.0", []string{"1.0", "2.0"}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderAPIVersionRequest, "3.0")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotAcceptable, w.Code)
	assert.Contains(t, w.Body.String(), "unsupported_api_version")
}

func TestGetVersion(t *testing.T) {
	router := gin.New()
	router.Use(VersionMiddleware("2.5", []string{"2.5"}))
	router.GET("/test", func(c *gin.Context) {
		version := GetVersion(c)
		c.JSON(http.StatusOK, gin.H{"version": version})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"version":"2.5"`)
}

func TestVersionRouteGroup(t *testing.T) {
	router := gin.New()

	v1Group := VersionRouteGroup(router, "1")
	v1Group.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "v1 endpoint")
	})

	v2Group := VersionRouteGroup(router, "2")
	v2Group.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "v2 endpoint")
	})

	// Test v1 endpoint
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/api/v1/test", nil)
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "v1 endpoint", w1.Body.String())

	// Test v2 endpoint
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/api/v2/test", nil)
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "v2 endpoint", w2.Body.String())
}

func TestVersionRouteGroup_WithVPrefix(t *testing.T) {
	router := gin.New()

	// Should handle both "1" and "v1"
	v1Group := VersionRouteGroup(router, "v1")
	v1Group.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "v1 endpoint")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "v1 endpoint", w.Body.String())
}

func TestStandardVersionMiddleware(t *testing.T) {
	middleware := StandardVersionMiddleware()

	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "1.0", w.Header().Get(HeaderAPIVersion))
}

func TestV2VersionMiddleware(t *testing.T) {
	middleware := V2VersionMiddleware()

	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "2.0", w.Header().Get(HeaderAPIVersion))
}

func TestWithVersion(t *testing.T) {
	router := gin.New()

	group := router.Group("/api")
	versionedGroup := WithVersion(group, "1.0", []string{"1.0", "1"})
	versionedGroup.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "versioned endpoint")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "1.0", w.Header().Get(HeaderAPIVersion))
	assert.Equal(t, "versioned endpoint", w.Body.String())
}

func TestVersionNegotiationMiddleware(t *testing.T) {
	middleware := NewVersionNegotiationMiddleware("1.5", []string{"1.0", "1.5", "2.0"})

	router := gin.New()
	router.Use(middleware.Handler())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	t.Run("default version", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "1.5", w.Header().Get(HeaderAPIVersion))
	})

	t.Run("requested supported version", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set(HeaderAPIVersionRequest, "1.0")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("requested unsupported version", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set(HeaderAPIVersionRequest, "3.0")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotAcceptable, w.Code)
	})
}

func TestIsVersionSupported(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		supported []string
		expected  bool
	}{
		{
			name:      "exact match",
			version:   "1.0",
			supported: []string{"1.0", "2.0"},
			expected:  true,
		},
		{
			name:      "minor version match",
			version:   "1",
			supported: []string{"1.0", "2.0"},
			expected:  true,
		},
		{
			name:      "not supported",
			version:   "3.0",
			supported: []string{"1.0", "2.0"},
			expected:  false,
		},
		{
			name:      "empty supported",
			version:   "1.0",
			supported: []string{},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isVersionSupported(tt.version, tt.supported)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetVersion_Default(t *testing.T) {
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		// No version middleware, should return default
		version := GetVersion(c)
		c.String(http.StatusOK, version)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, DefaultAPIVersion, w.Body.String())
}

func TestHeaderConstants(t *testing.T) {
	assert.Equal(t, "X-API-Version", HeaderAPIVersion)
	assert.Equal(t, "X-API-Version", HeaderAPIVersionRequest)
	assert.Equal(t, "1.0", DefaultAPIVersion)
}

func TestVersionMiddleware_ContextValue(t *testing.T) {
	router := gin.New()
	router.Use(VersionMiddleware("1.0", []string{"1.0", "2.0"}))
	router.GET("/test", func(c *gin.Context) {
		version, exists := c.Get("api_version")
		require.True(t, exists)
		versionStr, ok := version.(string)
		require.True(t, ok)
		// Return the version from context - don't assert a specific value
		c.String(http.StatusOK, versionStr)
	})

	// Test without requesting specific version
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "1.0", w.Body.String())

	// Test with requested version
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.Header.Set(HeaderAPIVersionRequest, "2.0")
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "2.0", w2.Body.String())
}

func TestVersionMiddleware_ErrorResponse(t *testing.T) {
	router := gin.New()
	router.Use(VersionMiddleware("1.0", []string{"1.0"}))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderAPIVersionRequest, "99.0")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotAcceptable, w.Code)

	// Verify error response structure
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Equal(t, "unsupported_api_version", resp["error"])
	assert.Contains(t, resp["message"], "not supported")
	assert.NotEmpty(t, resp["supported_versions"])
}

func TestVersionRouteGroup_NestedRoutes(t *testing.T) {
	router := gin.New()

	v1 := VersionRouteGroup(router, "1")
	users := v1.Group("/users")
	users.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "list users")
	})
	users.GET("/:id", func(c *gin.Context) {
		c.String(http.StatusOK, "get user")
	})

	// Test list users
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/api/v1/users/", nil)
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "list users", w1.Body.String())

	// Test get user
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/api/v1/users/123", nil)
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "get user", w2.Body.String())
}

func TestVersionMiddleware_Chain(t *testing.T) {
	router := gin.New()

	// Multiple versioned groups - add middleware BEFORE routes
	v1 := VersionRouteGroup(router, "1")
	v1.Use(VersionMiddleware("1.0", []string{"1.0"}))
	v1.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "v1")
	})

	v2 := VersionRouteGroup(router, "2")
	v2.Use(VersionMiddleware("2.0", []string{"2.0"}))
	v2.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "v2")
	})

	// Test v1
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/api/v1/test", nil)
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "v1", w1.Body.String())
	assert.Equal(t, "1.0", w1.Header().Get(HeaderAPIVersion))

	// Test v2
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/api/v2/test", nil)
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "v2", w2.Body.String())
	assert.Equal(t, "2.0", w2.Header().Get(HeaderAPIVersion))
}
