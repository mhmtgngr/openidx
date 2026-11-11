package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The vendor API reads and writes the migration 247 fields (B2.3): a
// federated vendor needs a default sponsor, names one of the organization's
// identity providers and only groups open to external users; an update that
// leaves the fields out keeps them; the sponsor can be changed on its own.
// The external-user list filters by source.
func TestAVendorsFederationIsSetThroughTheAPI(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	admin := scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
		org, "vf-admin-"+suffix)
	sponsor2 := scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
		org, "vf-sponsor-"+suffix)
	idp := scalar(`INSERT INTO identity_providers (org_id, name, provider_type, issuer_url, client_id, client_secret, enabled)
		VALUES ($1, $2, 'oidc', 'https://idp.example.test', 'c', 's', true) RETURNING id::text`, org, "vf-idp-"+suffix)
	open := scalar(`INSERT INTO groups (org_id, name, external_allowed) VALUES ($1, $2, true) RETURNING id::text`, org, "vf-open-"+suffix)
	closed := scalar(`INSERT INTO groups (org_id, name, external_allowed) VALUES ($1, $2, false) RETURNING id::text`, org, "vf-closed-"+suffix)

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", admin)
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.POST("/vendor-orgs", svc.handleCreateVendorOrg)
	r.PUT("/vendor-orgs/:id", svc.handleUpdateVendorOrg)
	r.GET("/external-users", svc.handleListExternalUsers)
	call := func(method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	name := `"name":"Partner ` + suffix + `"`

	if code, body := call(http.MethodPost, "/vendor-orgs", `{`+name+`,"onboarding_mode":"federated"}`); code != http.StatusBadRequest {
		t.Fatalf("a federated vendor without a sponsor: %d %v, want 400", code, body)
	}
	if code, body := call(http.MethodPost, "/vendor-orgs", `{`+name+`,"onboarding_mode":"sometimes"}`); code != http.StatusBadRequest {
		t.Fatalf("an unknown onboarding mode: %d %v, want 400", code, body)
	}
	if code, body := call(http.MethodPost, "/vendor-orgs", fmt.Sprintf(`{%s,"onboarding_mode":"federated","default_sponsor_user_id":%q,"default_group_ids":[%q]}`,
		name, admin, closed)); code != http.StatusBadRequest {
		t.Fatalf("a default group closed to external users: %d %v, want 400", code, body)
	}
	code, body := call(http.MethodPost, "/vendor-orgs", fmt.Sprintf(
		`{%s,"onboarding_mode":"federated","default_sponsor_user_id":%q,"idp_id":%q,"sliding_expiry":true,"default_group_ids":[%q]}`,
		name, admin, idp, open))
	vendor, _ := body["id"].(string)
	if code != http.StatusCreated || body["onboarding_mode"] != "federated" || body["idp_id"] != idp || body["sliding_expiry"] != true {
		t.Fatalf("create a federated vendor: %d %v", code, body)
	}
	if g, _ := body["default_group_ids"].([]interface{}); len(g) != 1 || g[0] != open {
		t.Fatalf("default groups: %v", body["default_group_ids"])
	}

	// An update from a form that predates the fields keeps them.
	code, body = call(http.MethodPut, "/vendor-orgs/"+vendor, fmt.Sprintf(`{%s,"default_sponsor_user_id":%q}`, name, sponsor2))
	if code != http.StatusOK || body["onboarding_mode"] != "federated" || body["idp_id"] != idp ||
		body["sliding_expiry"] != true || body["default_sponsor_user_id"] != sponsor2 {
		t.Fatalf("change the default sponsor alone: %d %v", code, body)
	}
	// Dropping the sponsor of a federated vendor is refused.
	if code, body := call(http.MethodPut, "/vendor-orgs/"+vendor, `{`+name+`}`); code != http.StatusBadRequest {
		t.Fatalf("a federated vendor losing its sponsor: %d %v, want 400", code, body)
	}
	// Back to invitations, provider unbound.
	code, body = call(http.MethodPut, "/vendor-orgs/"+vendor, `{`+name+`,"onboarding_mode":"invitation","idp_id":""}`)
	if code != http.StatusOK || body["onboarding_mode"] != "invitation" || body["idp_id"] != "" {
		t.Fatalf("back to invitation: %d %v", code, body)
	}

	// source filter.
	expires := time.Now().Add(30 * 24 * time.Hour)
	fed := scalar(`INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at, account_status, source)
		VALUES ($1, $2::text, $2::text || '@partner.example.test', 'external', $3::uuid, $4::uuid, $5, 'active', 'federated') RETURNING id::text`,
		org, "vf-fed-"+suffix, vendor, admin, expires)
	inv := scalar(`INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at, account_status)
		VALUES ($1, $2::text, $2::text || '@partner.example.test', 'external', $3::uuid, $4::uuid, $5, 'active') RETURNING id::text`,
		org, "vf-inv-"+suffix, vendor, admin, expires)
	ids := func(q string) map[string]string {
		t.Helper()
		code, body := call(http.MethodGet, "/external-users?vendor_org_id="+vendor+q, "")
		if code != http.StatusOK {
			t.Fatalf("list external users%s: %d %v", q, code, body)
		}
		out := map[string]string{}
		list, _ := body["external_users"].([]interface{})
		for _, u := range list {
			m := u.(map[string]interface{})
			out[m["id"].(string)], _ = m["source"].(string)
		}
		return out
	}
	if got := ids("&source=federated"); len(got) != 1 || got[fed] != "federated" {
		t.Errorf("source=federated listed %v, want only %s", got, fed)
	}
	if got := ids(""); len(got) != 2 || got[inv] != "local" {
		t.Errorf("no source filter listed %v", got)
	}
}
