package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TestCreateDelegationValidation covers the input guards in
// handleCreateDelegation that run BEFORE any database access. delegate_id and
// scope_id are uuid columns, so non-UUID input must fail closed with a 400
// instead of reaching Postgres and surfacing as a confusing 500. These cases
// use a Service with a nil db on purpose: a valid payload would panic on the
// DB call, which proves the guards return early for every case below.
func TestCreateDelegationValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &Service{logger: zap.NewNop()}

	validUUID := "00000000-0000-0000-0000-000000000001"

	cases := []struct {
		name string
		body string
		want int
	}{
		{"missing fields", `{}`, http.StatusBadRequest},
		{"missing scope_type", `{"delegate_id":"` + validUUID + `"}`, http.StatusBadRequest},
		{"non-uuid scope_id", `{"delegate_id":"` + validUUID + `","scope_type":"organization","scope_id":"engineering-team"}`, http.StatusBadRequest},
		{"non-uuid delegate_id", `{"delegate_id":"someuser","scope_type":"organization","scope_id":"` + validUUID + `"}`, http.StatusBadRequest},
		{"invalid scope_type", `{"delegate_id":"` + validUUID + `","scope_type":"planet","scope_id":"` + validUUID + `"}`, http.StatusBadRequest},
		{"malformed json", `{`, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.POST("/delegations", func(c *gin.Context) {
				c.Set("user_id", validUUID)
				svc.handleCreateDelegation(c)
			})
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/delegations", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Errorf("handleCreateDelegation[%s] = %d, want %d (body=%s)", tc.name, w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestCreateDelegationRefusesNarrowingScopes is the handler half of the
// delegation-scope decision (#956): a group, role or application scope is
// refused with a 400 that says why, before the service is reached. Those
// scopes were recorded and never enforced. The organization half and the edit
// path run against Postgres in delegation_scope_test.go.
func TestCreateDelegationRefusesNarrowingScopes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &Service{logger: zap.NewNop()}

	validUUID := "00000000-0000-0000-0000-000000000001"

	for _, scope := range []string{"group", "role", "application"} {
		t.Run(scope, func(t *testing.T) {
			r := gin.New()
			r.POST("/delegations", func(c *gin.Context) {
				c.Set("user_id", validUUID)
				svc.handleCreateDelegation(c)
			})
			body := `{"delegate_id":"` + validUUID + `","scope_type":"` + scope + `","scope_id":"` + validUUID +
				`","permissions":["users:read"]}`
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/delegations", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("a %s-scoped delegation got %d, want 400: the scope would narrow nothing, "+
					"because RequirePermission compares resource and action only (body=%s)",
					scope, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "not enforced") {
				t.Fatalf("the refusal does not tell the administrator why: %s", w.Body.String())
			}
		})
	}
}

// TestCreateDSARValidation covers the input guards in handleCreateDSAR that run
// BEFORE any database access. The create form is a free-text "Enter user ID"
// field, so an operator can submit a username or partial id; user_id is a uuid
// column, so a non-UUID value must fail closed with a 400 instead of reaching
// Postgres and surfacing as a 500. A nil db is used on purpose: a valid payload
// would panic on the DB call, which proves the guards return early below.
func TestCreateDSARValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &Service{logger: zap.NewNop()}

	validUUID := "00000000-0000-0000-0000-000000000001"

	cases := []struct {
		name string
		body string
		want int
	}{
		{"missing fields", `{}`, http.StatusBadRequest},
		{"empty user_id", `{"user_id":"","request_type":"export"}`, http.StatusBadRequest},
		{"non-uuid user_id (username)", `{"user_id":"admin","request_type":"export"}`, http.StatusBadRequest},
		{"invalid request_type", `{"user_id":"` + validUUID + `","request_type":"teleport"}`, http.StatusBadRequest},
		{"malformed json", `{`, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.POST("/dsars", func(c *gin.Context) {
				// handleCreateDSAR calls requireAdmin first.
				c.Set("roles", []string{"admin"})
				c.Set("user_id", validUUID)
				svc.handleCreateDSAR(c)
			})
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/dsars", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Errorf("handleCreateDSAR[%s] = %d, want %d (body=%s)", tc.name, w.Code, tc.want, w.Body.String())
			}
		})
	}
}
