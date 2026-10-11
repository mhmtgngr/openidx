package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// A vendor's remote support on the migrated schema. Without an engagement
// covering the device the start is refused; an internal user is sent to the
// staff path. Inside one, the session is attended, relayed, broker-recorded,
// tied to the engagement and ends no later than it. A second start on the
// busy device is a 409, another user cannot see or end the session, and once
// the engagement is closed the janitor ends it.
func TestAVendorSupportsADeviceOnlyInsideItsEngagement(t *testing.T) {
	f := newExternalPamFixture(t)
	agent := "agent-rs-" + f.suffix
	f.exec(`INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash, org_id) VALUES ($1, $1, 'active', 'x', $2)`, agent, f.org)
	vendor := f.scalar(`SELECT vendor_org_id::text FROM users WHERE id = $1`, f.external)

	store, err := newFilesystemRecordingStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewRemoteSupportHandler(zap.NewNop(), f.db, nil)
	h.SetRecordingStore(store)
	router := func(user string) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
			c.Set("user_id", user)
			c.Next()
		})
		h.RegisterRemoteSupportVendorRoutes(r.Group(""), func(c *gin.Context) { c.Next() })
		return r
	}
	call := func(user, method, path string, body interface{}) (int, map[string]interface{}) {
		t.Helper()
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		router(user).ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	start := map[string]string{"agent_id": agent}

	if code, body := call(f.operator, http.MethodPost, "/my/remote-support/sessions", start); code != http.StatusForbidden || body["code"] != "not_external" {
		t.Fatalf("an internal user on the vendor path = %d %v, want 403 not_external", code, body)
	}
	if code, body := call(f.external, http.MethodPost, "/my/remote-support/sessions", start); code != http.StatusForbidden || body["code"] != "external_no_engagement" {
		t.Fatalf("a vendor with no engagement = %d %v, want 403 external_no_engagement", code, body)
	}

	ends := time.Now().Add(2 * time.Hour)
	eng := f.scalar(`INSERT INTO vendor_engagements (org_id, vendor_org_id, title, starts_at, ends_at)
		VALUES ($1, $2, 'Support', NOW() - interval '1 minute', $3) RETURNING id::text`, f.org, vendor, ends)
	f.exec(`INSERT INTO vendor_engagement_targets (engagement_id, org_id, target_type, target_id) VALUES ($1, $2, 'device', $3)`, eng, f.org, agent)

	code, body := call(f.external, http.MethodPost, "/my/remote-support/sessions", start)
	if code != http.StatusCreated {
		t.Fatalf("a vendor inside the engagement = %d %v", code, body)
	}
	id := body["id"].(string)
	if body["transport"] != "relay" || body["consent_required"] != true || body["recording"] != "server" || body["engagement_id"] != eng {
		t.Fatalf("the session should be relayed, attended, broker-recorded and tied to the engagement: %v", body)
	}
	got := f.scalar(`SELECT consent_required::text || '/' || transport || '/' || server_recording::text || '/' || recording_format || '/' ||
		recording_enabled::text || '/' || (expires_at <= $2::timestamptz + interval '1 second')::text
		FROM remote_support_sessions WHERE id = $1`, id, ends)
	if got != "true/relay/true/ivf/false/true" {
		t.Fatalf("stored session = %s", got)
	}

	if code, _ := call(f.external, http.MethodPost, "/my/remote-support/sessions", start); code != http.StatusConflict {
		t.Fatalf("a second start on the busy device = %d, want 409", code)
	}
	if code, body := call(f.external, http.MethodGet, "/my/remote-support/sessions", nil); code != http.StatusOK || len(body["sessions"].([]interface{})) != 1 {
		t.Fatalf("list = %d %v", code, body)
	}
	if code, _ := call(f.operator, http.MethodPost, "/my/remote-support/sessions/"+id+"/end", nil); code != http.StatusNotFound {
		t.Fatalf("someone else ending the vendor's session = %d, want 404", code)
	}
	if code, _ := call(f.operator, http.MethodGet, "/my/remote-support/sessions/"+id+"/ws", nil); code != http.StatusNotFound {
		t.Fatalf("someone else opening the vendor's viewer = %d, want 404", code)
	}

	// The engagement closes: the janitor ends the session.
	f.exec(`UPDATE vendor_engagements SET status = 'closed', closed_at = NOW(), close_reason = 'closed' WHERE id = $1`, eng)
	h.endLapsedVendorSessions(orgctx.WithBypassRLS(context.Background()))
	if got := f.scalar(`SELECT status || '/' || end_reason FROM remote_support_sessions WHERE id = $1`, id); got != "ended/engagement_ended" {
		t.Fatalf("after the engagement closed the session is %s, want ended/engagement_ended", got)
	}
	if code, _ := call(f.external, http.MethodGet, "/my/remote-support/sessions/"+id+"/ws", nil); code != http.StatusNotFound {
		t.Fatalf("the vendor's viewer after the engagement closed = %d, want 404", code)
	}
}
