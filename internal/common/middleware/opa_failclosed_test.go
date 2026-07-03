package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/opa"
)

// TestOPAAuthzFailClosedInProduction pins the production security posture: when
// OPA is unreachable, the middleware must fail CLOSED (403) unless devMode is on.
// In every running service devMode is passed as cfg.IsDevelopment(), which is
// false in production (Environment=production/prod) — so this fail-open branch is
// structurally unreachable in prod. This test guards that a future refactor can't
// silently flip the prod default to fail-open.
func TestOPAAuthzFailClosedInProduction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Unreachable OPA endpoint → client.Authorize returns an error, exercising the
	// fail-open/closed branch.
	client := opa.NewClient("http://127.0.0.1:1", zap.NewNop())

	run := func(devMode bool) int {
		r := gin.New()
		r.Use(OPAAuthz(client, zap.NewNop(), devMode))
		r.GET("/api/v1/identity/users", func(c *gin.Context) { c.Status(http.StatusOK) })
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/identity/users", nil)
		r.ServeHTTP(w, req)
		return w.Code
	}

	t.Run("devMode=false (production) fails closed with 403", func(t *testing.T) {
		if code := run(false); code != http.StatusForbidden {
			t.Fatalf("expected 403 when OPA unreachable and devMode=false, got %d", code)
		}
	})

	t.Run("devMode=true (development) fails open (allows through)", func(t *testing.T) {
		if code := run(true); code != http.StatusOK {
			t.Fatalf("expected 200 when OPA unreachable and devMode=true, got %d", code)
		}
	})
}
