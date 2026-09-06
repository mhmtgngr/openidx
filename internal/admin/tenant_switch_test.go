package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestTenantSwitchAndPostureAgainstTheRealSchema covers three admin reads that
// asked for columns the schema does not have.
//
// The tenant switcher is the sharpest of them: handleSwitchTenant and
// handleGetCurrentTenant both selected display_name and enabled from
// organizations, which is (id, name, slug, domain, plan, status, ...) and has
// neither. The statement could not plan, the handlers map any error from that
// row to 404, and so switching tenant in the console has answered
// "Organization not found" for every organization that exists -- a feature that
// looks like a permissions problem to whoever hits it.
//
// The dormant-account count is the other shape: users records the last sign-in
// as last_login_at, the query asked for last_login, and the security-posture
// card therefore reported 0 dormant accounts on every install. Zero dormant
// accounts is the answer that makes the card look best.
func TestTenantSwitchAndPostureAgainstTheRealSchema(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	seedCtx := orgctx.WithBypassRLS(context.Background())

	const (
		orgA  = "00000000-0000-0000-0000-000000000010" // seeded default org
		orgB  = "88888888-0000-0000-0000-0000000000b1"
		admin = "88888888-0000-0000-0000-0000000000a1"
		stale = "88888888-0000-0000-0000-0000000000a2"
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug, domain, status) VALUES ($1, 'Second Tenant', 'second-tenant', 'second.example', 'active')`, orgB)
	exec(`INSERT INTO users (id, username, email, org_id, enabled, last_login_at) VALUES ($1, 'tenant-admin', 'ta@test.local', $2, true, NOW())`, admin, orgA)
	// Enabled, and last seen a year ago: the definition of dormant.
	exec(`INSERT INTO users (id, username, email, org_id, enabled, last_login_at) VALUES ($1, 'long-gone', 'lg@test.local', $2, true, NOW() - INTERVAL '365 days')`, stale, orgA)
	exec(`INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, 'admin')`, orgB, admin)

	svc := &Service{db: db, logger: zap.NewNop()}

	call := func(handler gin.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		c.Request = r.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgA}))
		c.Set("roles", []string{"admin"})
		c.Set("user_id", admin)
		handler(c)
		return w
	}

	t.Run("switching to an organization that exists succeeds", func(t *testing.T) {
		w := call(svc.handleSwitchTenant, http.MethodPost, "/api/v1/admin/tenants/switch",
			`{"org_id":"`+orgB+`"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("switch returned %d (%s); the tenant switcher has answered 404 "+
				"for every organization since it was written", w.Code, w.Body.String())
		}
		var body struct {
			Organization struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				DisplayName string `json:"display_name"`
				Enabled     bool   `json:"enabled"`
			} `json:"organization"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v (%s)", err, w.Body.String())
		}
		if body.Organization.Name != "Second Tenant" {
			t.Errorf("organization.name = %q, want Second Tenant (body %s)",
				body.Organization.Name, w.Body.String())
		}
		if !body.Organization.Enabled {
			t.Error("an organization with status 'active' came back disabled")
		}
	})

	t.Run("switching to an organization that does not exist still 404s", func(t *testing.T) {
		w := call(svc.handleSwitchTenant, http.MethodPost, "/api/v1/admin/tenants/switch",
			`{"org_id":"99999999-0000-0000-0000-000000000099"}`)
		if w.Code != http.StatusNotFound {
			t.Errorf("switch to a missing organization returned %d, want 404", w.Code)
		}
	})

	t.Run("the current organization resolves for a member", func(t *testing.T) {
		w := call(svc.handleGetCurrentTenant, http.MethodGet, "/api/v1/admin/tenants/current", "")
		if w.Code != http.StatusOK {
			t.Fatalf("current tenant returned %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("a dormant account is counted", func(t *testing.T) {
		w := call(svc.handleGetCompliancePosture, http.MethodGet, "/api/v1/admin/compliance-posture", "")
		if w.Code != http.StatusOK {
			t.Fatalf("compliance posture returned %d (%s)", w.Code, w.Body.String())
		}
		var posture struct {
			DormantAccountsCount int `json:"dormant_accounts_count"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &posture); err != nil {
			t.Fatalf("decode posture: %v (%s)", err, w.Body.String())
		}
		if posture.DormantAccountsCount < 1 {
			t.Errorf("dormant_accounts_count = %d against a user last seen a year ago; "+
				"the card read 0 on every install", posture.DormantAccountsCount)
		}
	})
}
