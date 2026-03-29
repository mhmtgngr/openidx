// Package middleware provides tests for API versioning middleware
package middleware

import (
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

func TestAPIVersion_URLPathVersioning(t *testing.T) {
	cfg := &VersionConfig{
		Supported:  []string{"v1", "v2"},
		Default:    "v1",
		Deprecated: map[string]string{},
		Latest:     "v2",
	}

	middleware := APIVersionWithConfig(cfg)

	tests := []struct {
		name           string
		path           string
		expectedVersion string
	}{
		{"v1 path", "/api/v1/users", "v1"},
		{"v2 path", "/api/v2/users", "v2"},
		{"no version - default", "/api/users", "v1"},
		{"root path", "/", "v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			c.Request = httptest.NewRequest("GET", tt.path, nil)

			middleware(c)

			version, exists := c.Get(ContextAPIVersion)
			require.True(t, exists, "version should be set in context")
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}

func TestAPIVersion_HeaderVersioning(t *testing.T) {
	cfg := &VersionConfig{
		Supported:  []string{"v1", "v2"},
		Default:    "v1",
		Deprecated: map[string]string{},
		Latest:     "v2",
	}

	middleware := APIVersionWithConfig(cfg)

	tests := []struct {
		name            string
		header          string
		expectedVersion string
		expectError     bool
	}{
		{"v1 header", "v1", "v1", false},
		{"v2 header", "v2", "v2", false},
		{"numeric v1", "1", "v1", false},
		{"numeric v2", "2", "v2", false},
		{"unsupported version", "v3", "", true},
		{"empty header", "", "v1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req := httptest.NewRequest("GET", "/api/users", nil)
			if tt.header != "" {
				req.Header.Set(HeaderAPIVersionRequest, tt.header)
			}
			c.Request = req

			// Create a test route
			router := gin.New()
			router.Use(middleware)
			router.GET("/api/users", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			router.ServeHTTP(w, req)

			if tt.expectError {
				assert.Equal(t, http.StatusNotAcceptable, w.Code)
			} else {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, tt.expectedVersion, w.Header().Get(HeaderAPIVersion))
			}
		})
	}
}

func TestAPIVersion_AcceptHeaderVersioning(t *testing.T) {
	cfg := &VersionConfig{
		Supported:  []string{"v1", "v2"},
		Default:    "v1",
		Deprecated: map[string]string{},
		Latest:     "v2",
	}

	middleware := APIVersionWithConfig(cfg)

	tests := []struct {
		name            string
		accept          string
		expectedVersion string
	}{
		{"vnd.openidx.v2+json", "application/vnd.openidx.v2+json", "v2"},
		{"vnd.openidx.v1+json", "application/vnd.openidx.v1+json", "v1"},
		{"vnd.api.v2+json", "application/vnd.api.v2+json", "v2"},
		{"standard json", "application/json", "v1"},
		{"empty accept", "", "v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req := httptest.NewRequest("GET", "/api/users", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			c.Request = req

			middleware(c)

			version, exists := c.Get(ContextAPIVersion)
			require.True(t, exists)
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}

func TestAPIVersion_DeprecationHeaders(t *testing.T) {
	cfg := &VersionConfig{
		Supported:  []string{"v1", "v2"},
		Default:    "v1",
		Deprecated: map[string]string{"v1": "2027-12-31"},
		Latest:     "v2",
	}

	middleware := APIVersionWithConfig(cfg)

	tests := []struct {
		name           string
		requestVersion string
		expectDeprecation bool
	}{
		{"deprecated v1", "v1", true},
		{"current v2", "v2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req := httptest.NewRequest("GET", "/api/users", nil)
			req.Header.Set(HeaderAPIVersionRequest, tt.requestVersion)
			c.Request = req

			middleware(c)

			hasDeprecation := c.Writer.Header().Get(HeaderDeprecation) == "true"
			assert.Equal(t, tt.expectDeprecation, hasDeprecation)

			if tt.expectDeprecation {
				assert.NotEmpty(t, c.Writer.Header().Get(HeaderSunset))
				assert.NotEmpty(t, c.Writer.Header().Get("Warning"))
			}
		})
	}
}

func TestParseAPIVersion(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*gin.Context)
		expected string
	}{
		{
			name: "existing v1",
			setup: func(c *gin.Context) {
				c.Set(ContextAPIVersion, "v1")
			},
			expected: "v1",
		},
		{
			name: "existing v2",
			setup: func(c *gin.Context) {
				c.Set(ContextAPIVersion, "v2")
			},
			expected: "v2",
		},
		{
			name:     "no version set",
			setup:    func(c *gin.Context) {},
			expected: "v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			tt.setup(c)
			assert.Equal(t, tt.expected, ParseAPIVersion(c))
		})
	}
}

func TestSetAPIVersionHeaders(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		deprecated bool
	}{
		{"v1 deprecated", "v1", true},
		{"v2 current", "v2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			SetAPIVersionHeaders(c, tt.version, tt.deprecated)

			assert.Equal(t, tt.version, w.Header().Get(HeaderAPIVersion))
			assert.Equal(t, tt.deprecated, w.Header().Get(HeaderDeprecation) == "true")
			assert.NotEmpty(t, w.Header().Get(HeaderAlternateVersions))
		})
	}
}

func TestVersionConstraint(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		constraint string
		allowed    bool
	}{
		{"v1 exact match", "v1", "v1", true},
		{"v1 not match v2", "v1", "v2", false},
		{"v1 greater than v0", "v1", ">=v1", true},
		{"v1 less than v2", "v1", "<v2", true},
		{"v2 greater than v1", "v2", ">v1", true},
		{"v2 not less than v1", "v2", "<v1", false},
		{"v1 not v1 excluded", "v1", "!v1", false},
		{"v2 not v1 excluded", "v2", "!v1", true},
		{"v1 in OR", "v1", "v1 || v3", true},
		{"v2 in OR", "v2", "v1 || v3", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			c.Set(ContextAPIVersion, tt.version)
			c.Request = httptest.NewRequest("GET", "/", nil)

			middleware := VersionConstraint(tt.constraint)
			middleware(c)

			if tt.allowed {
				assert.False(t, c.IsAborted())
			} else {
				assert.True(t, c.IsAborted())
			}
		})
	}
}

func TestVersionedRoute(t *testing.T) {
	tests := []struct {
		name       string
		versions   []string
		requestVer string
		allowed    bool
	}{
		{"v1 route with v1 request", []string{"v1"}, "v1", true},
		{"v1 route with v2 request", []string{"v1"}, "v2", false},
		{"multi version route v1", []string{"v1", "v2"}, "v1", true},
		{"multi version route v2", []string{"v1", "v2"}, "v2", true},
		{"multi version route v3", []string{"v1", "v2"}, "v3", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			c.Set(ContextAPIVersion, tt.requestVer)
			c.Request = httptest.NewRequest("GET", "/", nil)

			middleware := VersionedRoute(tt.versions...)
			middleware(c)

			if tt.allowed {
				assert.False(t, c.IsAborted())
			} else {
				assert.True(t, c.IsAborted())
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{"v1 < v2", "v1", "v2", -1},
		{"v2 > v1", "v2", "v1", 1},
		{"v1 == v1", "v1", "v1", 0},
		{"1 < 2", "1", "2", -1},
		{"v10 > v2", "v10", "v2", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareVersions(tt.v1, tt.v2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"v1", "v1"},
		{"v2", "v2"},
		{"1", "v1"},
		{"2", "v2"},
		{"", "v1"},
		{"10", "v10"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeVersion(tt.input))
		})
	}
}

func TestExtractVersionFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/api/v1/users", "v1"},
		{"/api/v2/users", "v2"},
		{"/api/v10/users", "v10"},
		{"/api/users", ""},
		{"/health", ""},
		{"/api/v1", "v1"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractVersionFromPath(tt.path))
		})
	}
}

func TestExtractVersionFromAccept(t *testing.T) {
	tests := []struct {
		accept   string
		expected string
	}{
		{"application/vnd.openidx.v2+json", "v2"},
		{"application/vnd.openidx.v1+json", "v1"},
		{"application/vnd.api.v2+json", "v2"},
		{"application/json", ""},
		{"", ""},
		{"application/vnd.openidx.v10+json", "v10"},
	}

	for _, tt := range tests {
		t.Run(tt.accept, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractVersionFromAccept(tt.accept))
		})
	}
}

func TestVersionRouteGroup(t *testing.T) {
	router := gin.New()

	v1Group := VersionRouteGroup(router, "v1")
	v1Group.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "v1")
	})

	v2Group := VersionRouteGroup(router, "v2")
	v2Group.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "v2")
	})

	tests := []struct {
		path           string
		expectedStatus int
		expectedBody   string
	}{
		{"/api/v1/test", http.StatusOK, "v1"},
		{"/api/v2/test", http.StatusOK, "v2"},
		{"/api/v3/test", http.StatusNotFound, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.path, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Equal(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestMigrateVersion(t *testing.T) {
	callCount := 0
	migrator := func(c *gin.Context) error {
		callCount++
		return nil
	}

	middleware := MigrateVersion("v1", "v2", migrator)

	tests := []struct {
		name           string
		requestVersion string
		expectMigrate  bool
		finalVersion   string
	}{
		{"migrate v1 to v2", "v1", true, "v2"},
		{"v2 stays v2", "v2", false, "v2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount = 0
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			c.Set(ContextAPIVersion, tt.requestVersion)
			c.Request = httptest.NewRequest("GET", "/", nil)

			middleware(c)

			assert.Equal(t, tt.expectMigrate, callCount > 0)

			version, _ := c.Get(ContextAPIVersion)
			assert.Equal(t, tt.finalVersion, version)
		})
	}
}

func TestWrapVersionedResponse(t *testing.T) {
	tests := []struct {
		name          string
		setupContext  func(*gin.Context)
		expectMeta    bool
		expectDeprec  bool
	}{
		{
			name: "standard v1 response",
			setupContext: func(c *gin.Context) {
				c.Set(ContextAPIVersion, "v1")
			},
			expectMeta: true,
			expectDeprec: false,
		},
		{
			name: "deprecated version response",
			setupContext: func(c *gin.Context) {
				c.Set(ContextAPIVersion, "v1")
				c.Writer.Header().Set(HeaderDeprecation, "true")
				c.Writer.Header().Set(HeaderSunset, "Sun, 31 Dec 2027 23:59:59 GMT")
			},
			expectMeta: true,
			expectDeprec: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/", nil)
			tt.setupContext(c)

			data := map[string]string{"message": "test"}
			response := WrapVersionedResponse(c, data)

			assert.NotNil(t, response)
			assert.Equal(t, data, response.Data)

			if tt.expectMeta {
				assert.NotEmpty(t, response.Meta.Version)
			}

			if tt.expectDeprec {
				assert.True(t, response.Meta.Deprecated)
				assert.NotEmpty(t, response.Meta.SunsetDate)
			}
		})
	}
}
