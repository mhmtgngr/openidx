package access

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The watermark (migration 242), on the migrated schema through the real
// routes: an external user's launch always carries one naming them; an
// internal user's carries none until the organization's policy asks, then one
// naming them, from the users row and not from anything the request says; a
// policy save that leaves the field out keeps it.
func TestPamSessionWatermark(t *testing.T) {
	f := newExternalPamFixture(t)
	f.svc.config.GuacamoleRecordingPath = t.TempDir()
	maint := f.entry("wm", "ssh", "ziti", 22, `{}`)
	f.exec(`UPDATE users SET email = 'ops@corp.example.test' WHERE id = $1`, f.operator)

	policyRouter := gin.New()
	policyRouter.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Set("user_id", f.admin)
		c.Set("org_id", f.org)
		c.Set("roles", []string{"admin"})
	})
	policyRouter.PUT("/pam/policy", f.svc.handleSetPamPolicy)
	httpCall := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		policyRouter.ServeHTTP(w, req)
		return w
	}

	launch := func(userID string) map[string]interface{} {
		t.Helper()
		code, body := f.call(userID, http.MethodPost, "/pam/entries/"+maint+"/connect", "{}")
		if code != http.StatusOK {
			t.Fatalf("connect as %s: %d %v", userID, code, body)
		}
		return body
	}

	if wm := launch(f.operator)["watermark"]; wm != nil {
		t.Errorf("an internal launch under the default policy carries a watermark: %v", wm)
	}

	// The external user, after an approved request.
	_, body := f.call(f.external, http.MethodPost, "/pam/entries/"+maint+"/request", `{"reason":"patching"}`)
	req, _ := body["request_id"].(string)
	if code, body := f.call(f.admin, http.MethodPost, "/pam/entry-requests/"+req+"/approve", "{}", "admin"); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, body)
	}
	ext := launch(f.external)
	wm, _ := ext["watermark"].(map[string]interface{})
	text, _ := wm["text"].(string)
	sid, _ := ext["session_id"].(string)
	if !strings.Contains(text, f.externalAccount) || !strings.Contains(text, "session "+sid[:8]) || !strings.Contains(text, "UTC") {
		t.Errorf("external watermark %q does not name the user, the session and the time", text)
	}

	// The organization asks for it on internal sessions too.
	save := func(body string) {
		t.Helper()
		w := httpCall(http.MethodPut, "/pam/policy", body)
		if w.Code != http.StatusOK {
			t.Fatalf("save policy %s: %d %s", body, w.Code, w.Body.String())
		}
	}
	save(`{"max_session_hours":8,"idle_timeout_minutes":0,"require_approval_internal":false,"record_internal":true,"launch_approval_window_minutes":60,"watermark_internal":true}`)
	if !f.audit.has("pam.policy_set", "success", map[string]interface{}{"watermark_internal": true}) {
		t.Error("the policy change was not audited with the watermark")
	}
	in := launch(f.operator)
	wm, _ = in["watermark"].(map[string]interface{})
	if text, _ := wm["text"].(string); !strings.HasPrefix(text, "ops@corp.example.test · session ") {
		t.Errorf("internal watermark %q does not name the operator from the users row", text)
	}

	// An older client's save leaves the field out, and the watermark stays.
	save(`{"max_session_hours":8,"idle_timeout_minutes":0,"require_approval_internal":false,"record_internal":true,"launch_approval_window_minutes":60}`)
	if f.scalar(`SELECT watermark_internal::text FROM org_pam_policy WHERE org_id = $1`, f.org) != "true" {
		t.Error("a save without watermark_internal cleared it")
	}
	save(`{"max_session_hours":8,"idle_timeout_minutes":0,"require_approval_internal":false,"record_internal":true,"launch_approval_window_minutes":60,"watermark_internal":false}`)
	if launch(f.operator)["watermark"] != nil {
		t.Error("the watermark stayed after the policy turned it off")
	}
}
