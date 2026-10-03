package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// GET /api/v1/dashboard answers with the organization's latest audit events,
// failed-login and suspicious-IP counts and user and session counts. Driven
// through RegisterAllRoutes, as cmd/admin-api mounts it: a plain user, a caller
// with no roles, an auditor, a compliance_reader and a role the product does
// not define are refused 403 operator access required; an operator, an admin
// and a super_admin reach the handler (which, given no organization here,
// answers its own 403 organization context required).
func TestTheDashboardAnswersStaffOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	call := func(roles []string) (int, string) {
		r := gin.New()
		v1 := r.Group("/api/v1")
		v1.Use(func(c *gin.Context) {
			if roles != nil {
				c.Set("roles", roles)
			}
			c.Next()
		})
		RegisterAllRoutes(v1, nil, zap.NewNop(), nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil))
		return w.Code, w.Body.String()
	}
	for _, roles := range [][]string{{"user"}, nil, {}, {"auditor"}, {"compliance_reader"}, {"manager"}} {
		if code, body := call(roles); code != http.StatusForbidden || !strings.Contains(body, "operator access required") {
			t.Errorf("roles %v: %d %s, want 403 operator access required", roles, code, body)
		}
	}
	for _, roles := range [][]string{{"operator"}, {"admin"}, {"super_admin"}, {"user", "operator"}} {
		if code, body := call(roles); strings.Contains(body, "operator access required") || !strings.Contains(body, "organization context required") {
			t.Errorf("roles %v: %d %s, want the handler reached", roles, code, body)
		}
	}
}
