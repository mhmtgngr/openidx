package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/opa"
)

// TestOPAAuthzHonoursDeny pins the fix for a policy decision that was computed
// and then discarded.
//
// authz.rego raises deny[msg] for exactly two things: cross-tenant access and
// a separation-of-duties violation. Both are written to refuse a request that
// an allow rule has already permitted -- that is what a deny rule IS -- and
// the policy says so itself with `final_allow if { allow; count(deny) == 0 }`.
// The middleware read only decision.Allow and passed decision.Deny to the
// logger, so a request carrying both allow=true and a cross-tenant denial went
// through with the denial written to stdout. Nothing queried final_allow
// either: the client asks for the whole /v1/data/openidx/authz document.
//
// The fake OPA server here returns each combination directly, so the test
// pins the middleware's reading of the decision rather than the policy's
// evaluation of it.
func TestOPAAuthzHonoursDeny(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newServer := func(d opa.Decision) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"result": d})
		}))
	}

	run := func(t *testing.T, d opa.Decision) (int, string) {
		t.Helper()
		srv := newServer(d)
		defer srv.Close()

		r := gin.New()
		r.Use(func(c *gin.Context) {
			// A resolved caller, so the middleware sends a real input rather
			// than the anonymous one.
			c.Set("user_id", "u-1")
			c.Set("roles", []string{"approver", "requester"})
			c.Set("tenant_id", "org-a")
			c.Next()
		})
		r.Use(OPAAuthz(opa.NewClient(srv.URL, zap.NewNop()), zap.NewNop(), false))
		r.GET("/api/v1/governance/reviews", func(c *gin.Context) { c.String(http.StatusOK, "reached") })

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/governance/reviews", nil))
		return w.Code, w.Body.String()
	}

	t.Run("allow with no deny proceeds", func(t *testing.T) {
		code, body := run(t, opa.Decision{Allow: true})
		if code != http.StatusOK || body != "reached" {
			t.Fatalf("allow=true, deny=[] => %d %q, want 200 reached", code, body)
		}
	})

	t.Run("allow with a deny is refused", func(t *testing.T) {
		code, body := run(t, opa.Decision{
			Allow: true,
			Deny:  []string{"cross-tenant access denied"},
		})
		if code != http.StatusForbidden {
			t.Fatalf("allow=true with a deny => %d, want 403 (deny overrides allow)", code)
		}
		if body == "reached" {
			t.Fatal("the handler ran despite a policy denial")
		}
		// The reason must reach the caller, not just the log: an operator
		// debugging a 403 should not have to read stdout to learn it was a
		// tenant-boundary refusal.
		if want := "cross-tenant access denied"; !strings.Contains(body, want) {
			t.Errorf("response body %q does not carry the deny reason %q", body, want)
		}
	})

	t.Run("separation-of-duties deny is refused", func(t *testing.T) {
		code, _ := run(t, opa.Decision{
			Allow: true,
			Deny:  []string{"separation of duties violation: conflicting roles [approver requester]"},
		})
		if code != http.StatusForbidden {
			t.Fatalf("allow=true with an SoD deny => %d, want 403", code)
		}
	})

	t.Run("no allow is refused", func(t *testing.T) {
		if code, _ := run(t, opa.Decision{Allow: false}); code != http.StatusForbidden {
			t.Fatalf("allow=false => %d, want 403", code)
		}
	})
}
