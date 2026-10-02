package access

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
	"github.com/openidx/openidx/internal/migrations"
)

// Invariant I4 of the third-party access framework at a privileged launch: an
// external (vendor) user with a connect grant launches nothing until the
// account is active with a strong second factor, and the refusal comes after
// the grant check (an ungranted caller still reads "not permitted") and
// before the approval gate (a refused launch does not spend the approval).
// The entries are websites, the one type connect answers without a broker.
func TestAnExternalUserLaunchesNothingWithoutASecondFactor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	octx := orgctx.With(ctx, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(octx, q, args...).Scan(&v); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
		return v
	}
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(octx, q, args...); err != nil {
			t.Fatalf("exec (%s): %v", q, err)
		}
	}
	admin := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "xl-admin-"+suffix)
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "Acme "+suffix)
	external := scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '30 days')
		RETURNING id::text`, org, "xl-vendor-"+suffix, vendor, admin)

	logger := zap.NewNop()
	svc := &Service{db: db, config: &config.Config{}, logger: logger, auditService: NewUnifiedAuditService(db, logger)}
	as := func(userID string, roles ...string) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", append([]string{}, roles...))
			c.Next()
		})
		r.POST("/pam/entries", svc.handlePamCreateEntry)
		r.POST("/pam/entries/:id/grants", svc.handlePamAddEntryGrant)
		r.POST("/pam/entries/:id/connect", svc.handlePamConnect)
		return r
	}
	call := func(r *gin.Engine, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	adminAPI := as(admin, "admin")
	entry := func(name string, approval bool) string {
		t.Helper()
		code, body := call(adminAPI, "/pam/entries", `{"name":"`+name+` `+suffix+`","entry_type":"website",`+
			`"url":"https://`+name+`.example.test","require_approval":`+fmt.Sprint(approval)+`}`)
		id, _ := body["id"].(string)
		if code != http.StatusCreated || id == "" {
			t.Fatalf("create entry: %d %v", code, body)
		}
		return id
	}
	plain, gated, ungranted := entry("portal", false), entry("billing", true), entry("hr", false)
	for _, e := range []string{plain, gated} {
		if code, body := call(adminAPI, "/pam/entries/"+e+"/grants",
			`{"principal_type":"user","principal_id":"`+external+`","actions":["connect"]}`); code != http.StatusCreated {
			t.Fatalf("grant: %d %v", code, body)
		}
	}
	vendorAPI := as(external)
	approved := func() string {
		return scalar(`INSERT INTO pam_entry_access_requests (org_id, entry_id, requester_id, reason, status, expires_at)
			VALUES ($1, $2, $3, 'maintenance', 'approved', NOW() + interval '1 hour') RETURNING id::text`, org, gated, external)
	}

	request := approved()
	if code, body := call(vendorAPI, "/pam/entries/"+ungranted+"/connect", ""); code != http.StatusForbidden || body["error"] != "not permitted" {
		t.Errorf("an entry the external user holds no grant on: %d %v, want 403 not permitted", code, body)
	}
	for _, e := range []string{plain, gated} {
		if code, body := call(vendorAPI, "/pam/entries/"+e+"/connect", ""); code != http.StatusForbidden || body["code"] != "external_not_activated" {
			t.Errorf("a granted entry with no second factor: %d %v, want 403 external_not_activated", code, body)
		}
	}
	if status := scalar(`SELECT status FROM pam_entry_access_requests WHERE id = $1`, request); status != "approved" {
		t.Errorf("the refused launch spent the approval: it is %s", status)
	}

	exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'JBSWY3DPEHPK3PXP', true, $2)`, external, org)
	if code, body := call(vendorAPI, "/pam/entries/"+plain+"/connect", ""); code != http.StatusOK {
		t.Errorf("a granted entry with an authenticator: %d %v, want 200", code, body)
	}
	if code, body := call(vendorAPI, "/pam/entries/"+gated+"/connect", ""); code != http.StatusOK {
		t.Errorf("an approved entry with an authenticator: %d %v, want 200", code, body)
	}
	if status := scalar(`SELECT status FROM pam_entry_access_requests WHERE id = $1`, request); status != "consumed" {
		t.Errorf("the approval of the launch that went through is %s, want consumed", status)
	}

	exec(`UPDATE users SET account_status = 'pending_mfa' WHERE id = $1`, external)
	if code, body := call(vendorAPI, "/pam/entries/"+plain+"/connect", ""); code != http.StatusForbidden || body["code"] != "external_not_activated" {
		t.Errorf("an external account that is not active: %d %v, want 403 external_not_activated", code, body)
	}
	if code, body := call(adminAPI, "/pam/entries/"+plain+"/connect", ""); code != http.StatusOK {
		t.Errorf("an internal administrator with no second factor: %d %v; internal users are not held to I4", code, body)
	}
}
