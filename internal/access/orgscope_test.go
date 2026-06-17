package access

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// v1.7.0 org-scoping contract: access-service admin handlers that manage
// tenant-scoped resources (proxy_routes, proxy_sessions, ziti_*) read the org
// from the request context and refuse to run without one. The guard fires before
// any DB access, so these hold with a nil pool — a request that carries no org
// gets a non-2xx (403) and never panics. The proxy data-plane (route resolution
// by host, session lookup by token, activity heartbeat) and the background sync
// engines (continuous verification, Ziti user/cert sync) are deliberately
// org-derived-from-data or //orgscope:ignore and are not covered here.
func TestAccess_handlersRequireOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{logger: zap.NewNop()}

	cases := []struct {
		name    string
		method  string
		target  string
		body    string
		handler gin.HandlerFunc
	}{
		{"handleListRoutes", http.MethodGet, "/routes", "", s.handleListRoutes},
		{"handleCreateRoute", http.MethodPost, "/routes", `{"name":"r","from_url":"http://a","to_url":"http://b"}`, s.handleCreateRoute},
		{"handleQuickCreate", http.MethodPost, "/quick", `{"name":"r","domain":"x.example","target_url":"http://b"}`, s.handleQuickCreate},
		{"handleListSessions", http.MethodGet, "/sessions", "", s.handleListSessions},
		{"handleListRoutes_noPanic_nilOrg", http.MethodGet, "/routes?limit=5", "", s.handleListRoutes},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			var bodyReader *strings.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := httptest.NewRequest(tc.method, tc.target, bodyReader)
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			c.Request = req

			// No org in the request context → the handler must refuse before any DB
			// access (nil pool) rather than panicking or returning 2xx.
			tc.handler(c)

			if w.Code >= 200 && w.Code < 300 {
				t.Fatalf("%s: status = %d, want a non-2xx (org guard should fire)", tc.name, w.Code)
			}
		})
	}
}
