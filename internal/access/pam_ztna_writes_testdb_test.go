package access

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// An entry on the overlay used to be moved back to direct reach by one click
// on its page whatever PAM_REQUIRE_ZTNA said, turning an entry the gate let
// launch into one it refuses. On the migrated schema, through the handler:
//
//   - under enforce, disabling the overlay of an entry on it answers 409
//     ztna_required_direct_reach, leaves the entry on the overlay and audits
//     the refusal;
//   - under observe it goes through, and its audit event says enforce would
//     have refused it;
//   - with the gate off it goes through and says nothing of the kind;
//   - an entry already direct is not refused under enforce: nothing moves.
func TestAnOverlayEntryIsNotTurnedDirectUnderEnforcement(t *testing.T) {
	f := newExternalPamFixture(t)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Set("user_id", f.admin)
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.POST("/pam/entries/:id/ziti/disable", f.svc.handlePamDisableZiti)
	disable := func(id string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/pam/entries/"+id+"/ziti/disable", nil))
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	reach := func(id string) string {
		return f.scalar(`SELECT reach_mode FROM pam_entries WHERE id = $1`, id)
	}

	f.svc.config.PAMRequireZTNA = "enforce"
	onOverlay := f.entry("zt-enforce", "ssh", "ziti", 22, "{}")
	if code, body := disable(onOverlay); code != http.StatusConflict || body["code"] != "ztna_required_direct_reach" {
		t.Errorf("disabling the overlay under enforce: %d %v, want 409 ztna_required_direct_reach", code, body)
	}
	if got := reach(onOverlay); got != "ziti" {
		t.Errorf("a refused disable moved the entry to %q", got)
	}
	if !f.audit.has("pam.ziti_disable_refused", "success", map[string]interface{}{"entry_id": onOverlay}) {
		t.Error("the refused disable was not audited")
	}
	alreadyDirect := f.entry("zt-direct", "ssh", "direct", 22, "{}")
	if code, body := disable(alreadyDirect); code != http.StatusOK {
		t.Errorf("disabling the overlay of a direct entry under enforce: %d %v, want 200 (nothing moves)", code, body)
	}

	f.svc.config.PAMRequireZTNA = "observe"
	observed := f.entry("zt-observe", "ssh", "ziti", 22, "{}")
	if code, body := disable(observed); code != http.StatusOK {
		t.Fatalf("disabling the overlay under observe: %d %v, want 200", code, body)
	}
	if got := reach(observed); got != "direct" {
		t.Errorf("under observe the entry is %q, want direct", got)
	}
	if !f.audit.has("pam.ziti_disabled", "success", map[string]interface{}{"entry_id": observed, "ztna_would_refuse": true}) {
		t.Error("under observe the audit event does not say enforce would have refused")
	}

	f.svc.config.PAMRequireZTNA = ""
	off := f.entry("zt-off", "ssh", "ziti", 22, "{}")
	if code, body := disable(off); code != http.StatusOK {
		t.Fatalf("disabling the overlay with the gate off: %d %v, want 200", code, body)
	}
	if !f.audit.has("pam.ziti_disabled", "success", map[string]interface{}{"entry_id": off, "ztna_would_refuse": false}) {
		t.Error("with the gate off the audit event should not say enforce would have refused")
	}
}

// TestBrokeredSessionsAreRecordedByAdministratorsOnly walks the REAL route
// table. POST /pam/brokered-sessions records a db or k8s session the caller
// asserts: its target is free text that names no PAM entry and no grant, and
// nothing is issued. Any signed-in user with a fresh second factor could write
// such a row into the privileged-session ledger, an external user included.
// Only an administrator may now, as only an administrator may list them.
func TestBrokeredSessionsAreRecordedByAdministratorsOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rolesAs := func(roles ...string) gin.HandlerFunc {
		return func(c *gin.Context) {
			if len(roles) > 0 {
				c.Set("roles", roles)
			}
			c.Set("user_id", "11111111-0000-0000-0000-000000000001")
			c.Next()
		}
	}
	post := func(auth gin.HandlerFunc) (int, string) {
		r := gin.New()
		svc := NewService(&database.PostgresDB{}, &database.RedisClient{},
			&config.Config{Environment: "production"}, zap.NewNop())
		RegisterRoutes(r, svc, auth)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/access/pam/brokered-sessions",
			strings.NewReader(`{"target_type":"db","target":"prod-db.example.test:5432","principal":"dba"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	for _, tc := range []struct {
		name  string
		roles []string
	}{{"a plain user", []string{"user"}}, {"a caller with no roles", nil}, {"an operator", []string{"operator"}}} {
		if code, body := post(rolesAs(tc.roles...)); code != http.StatusForbidden || !strings.Contains(body, "admin access required") {
			t.Errorf("%s recording a brokered session: %d %s, want 403 at the admin gate", tc.name, code, body)
		}
	}
	// An administrator passes the admin gate (and meets the step-up gate and
	// the handler behind it, which a stub service cannot satisfy).
	if code, body := post(rolesAs("admin")); strings.Contains(body, "admin access required") {
		t.Errorf("an administrator was stopped at the admin gate: %d %s", code, body)
	}
}
