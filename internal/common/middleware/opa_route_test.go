package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/opa"
)

// OPAAuthz sends the route gin matched as input.resource.route: the template,
// not the path the caller wrote, which is what the policy's access-request
// rule names. A fake OPA records the input it is asked about.
func TestOPAIsToldTheMatchedRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var got opa.Input
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input opa.Input `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = body.Input
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"result": opa.Decision{Allow: true}})
	}))
	defer srv.Close()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "u-1")
		c.Set("roles", []string{"user"})
		c.Next()
	})
	r.Use(OPAAuthz(opa.NewClient(srv.URL, zap.NewNop()), zap.NewNop(), false))
	r.POST("/api/v1/governance/requests/:id/approve", func(c *gin.Context) { c.String(http.StatusOK, "reached") })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/governance/requests/r-1/approve", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("the request answered %d", w.Code)
	}
	if got.Resource.Route != "/api/v1/governance/requests/:id/approve" {
		t.Errorf("OPA was told the route %q; want the template gin matched", got.Resource.Route)
	}
	if got.Path != "/api/v1/governance/requests/r-1/approve" {
		t.Errorf("OPA was told the path %q", got.Path)
	}
}
