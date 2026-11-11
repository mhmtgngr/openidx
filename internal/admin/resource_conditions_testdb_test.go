package admin

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

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/organization"
)

// The application conditions write path: PUT upserts resource_conditions in
// the caller's organization, validates its input, is read back by GET, and
// cannot reach another organization's application.
func TestApplicationConditionsWritePath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupPAMTestDB(t)
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(query string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, query, args...).Scan(&v); err != nil {
			t.Fatalf("read %q: %v", query, err)
		}
		return v
	}
	orgA := scalar(`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "cond-a-"+suffix)
	orgB := scalar(`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "cond-b-"+suffix)
	adminA := scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2::text, $2::text || '@example.test', true)
		RETURNING id::text`, orgA, "cond-admin-"+suffix)
	app := func(org, name string) string {
		return scalar(`INSERT INTO applications (org_id, client_id, name, type, protocol)
			VALUES ($1::uuid, $2, $2, 'web', 'openid-connect') RETURNING id::text`, org, name+"-"+suffix)
	}
	appA, appB := app(orgA, "cond-app-a"), app(orgB, "cond-app-b")

	svc := NewService(db, &database.RedisClient{}, &config.Config{}, zap.NewNop())
	lookup := organization.NewOrgLookup(organization.NewService(db, &database.RedisClient{}, &config.Config{}, zap.NewNop()))
	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.Use(func(c *gin.Context) {
		c.Set("user_id", adminA)
		c.Set("roles", []string{"admin"})
		c.Set("org_id", orgA)
		c.Next()
	})
	v1.Use(middleware.TenantResolver(lookup, middleware.TenantResolverConfig{
		DefaultOrgFallback:     true,
		DefaultOrgID:           middleware.DefaultOrgID,
		PlatformAdminPredicate: auth.SuperAdminPredicate,
	}))
	RegisterRoutes(v1, svc)
	send := func(method, path, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-Slug", "cond-a-"+suffix)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}

	code, body := send(http.MethodGet, "/api/v1/applications/"+appA+"/conditions", "")
	if code != http.StatusOK || !strings.Contains(body, `"declared":false`) {
		t.Fatalf("GET before any write: %d %s", code, body)
	}
	code, body = send(http.MethodPut, "/api/v1/applications/"+appA+"/conditions",
		`{"require_step_up":true,"require_device_trust":true,"max_risk_score":40,"allowed_countries":["tr","DE","tr"]}`)
	if code != http.StatusOK {
		t.Fatalf("PUT: %d %s", code, body)
	}
	var got ApplicationConditions
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Declared || !got.RequireStepUp || !got.RequireDeviceTrust || got.MaxRiskScore == nil || *got.MaxRiskScore != 40 ||
		strings.Join(got.AllowedCountries, ",") != "TR,DE" {
		t.Fatalf("PUT answered %+v", got)
	}
	if n := scalar(`SELECT count(*)::text FROM admin_audit_log WHERE action = 'update_application_conditions' AND target_id = $1`, appA); n != "1" {
		t.Fatalf("audit rows = %s", n)
	}

	for name, bad := range map[string]string{
		"risk out of range": `{"max_risk_score":101}`,
		"bad country":       `{"allowed_countries":["Turkey"]}`,
		"bad posture id":    `{"posture_profile_id":"nope"}`,
		"time window array": `{"time_window":[1,2]}`,
	} {
		if code, body := send(http.MethodPut, "/api/v1/applications/"+appA+"/conditions", bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}

	if code, _ := send(http.MethodPut, "/api/v1/applications/"+appB+"/conditions", `{"require_step_up":true}`); code != http.StatusNotFound {
		t.Fatalf("another organization's application: %d", code)
	}
	if n := scalar(`SELECT count(*)::text FROM resource_conditions WHERE application_id = $1`, appB); n != "0" {
		t.Fatal("a write reached another organization's application")
	}
}
