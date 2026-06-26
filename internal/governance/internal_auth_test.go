package governance

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// TestInternalTokenBypass verifies the service-to-service auth path on
// openIDXAuthMiddleware: a matching X-Internal-Token is accepted only on the
// evaluate endpoints; everything else still requires a user JWT.
func TestInternalTokenBypass(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const secret = "s3cr3t-internal-token"
	s := &Service{logger: zap.NewNop(), config: &config.Config{InternalServiceToken: secret}}

	router := gin.New()
	g := router.Group("/api/v1/governance")
	g.Use(s.openIDXAuthMiddleware())
	g.POST("/policies/:id/evaluate", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	g.GET("/policies", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	tests := []struct {
		name     string
		method   string
		path     string
		token    string
		wantCode int
	}{
		{"evaluate with valid internal token", "POST", "/api/v1/governance/policies/p1/evaluate", secret, http.StatusOK},
		{"evaluate with wrong internal token", "POST", "/api/v1/governance/policies/p1/evaluate", "nope", http.StatusUnauthorized},
		{"evaluate with no token", "POST", "/api/v1/governance/policies/p1/evaluate", "", http.StatusUnauthorized},
		{"non-evaluate route rejects internal token", "GET", "/api/v1/governance/policies", secret, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.token != "" {
				req.Header.Set("X-Internal-Token", tt.token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.wantCode, w.Code)
		})
	}
}

// TestInternalTokenDisabledWhenEmpty verifies that an empty InternalServiceToken
// disables the bypass entirely — even a request presenting an empty token is
// rejected, so the path can't be reached on installs that didn't configure it.
func TestInternalTokenDisabledWhenEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)

	s := &Service{logger: zap.NewNop(), config: &config.Config{InternalServiceToken: ""}}
	router := gin.New()
	g := router.Group("/api/v1/governance")
	g.Use(s.openIDXAuthMiddleware())
	g.POST("/policies/:id/evaluate", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("POST", "/api/v1/governance/policies/p1/evaluate", nil)
	req.Header.Set("X-Internal-Token", "")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
