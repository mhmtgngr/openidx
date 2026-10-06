package access

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
	"github.com/openidx/openidx/internal/migrations"
)

// Enrolling a revoked device again does not bring it back.
//
// Enrolment re-uses an agent row when the request names the same device
// fingerprint, and it used to set that row active with a fresh token whatever
// its status was. The fingerprint is the client's own claim, so anyone with a
// valid enrollment token, or any user of the organization through
// /agent/enroll/oauth, could undo an administrator's revoke by naming the
// machine. These tests drive the real handlers through gin against the
// migrated schema: the administrator revokes through the fleet route, and a
// re-enrolment by token, by a single-use token and by OAuth is each answered
// 403 agent_revoked, leaves the row revoked with its old token hash, is
// audited in the agent's tenant, and does not make the old credential work
// again. A device that was not revoked re-enrols on each path as before.
func TestReenrolmentDoesNotBringARevokedDeviceBack(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	// Not the default tenant, so the audit check can tell the agent's tenant
	// from the fallback.
	var orgID, userID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('reenrol-org', 'reenrol-org') RETURNING id::text`).
		Scan(&orgID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, 'reenrol-user', 'reenrol-user@example.test', true)
		 RETURNING id::text`, orgID).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	newToken := func(plain string, reusable bool) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO agent_enrollment_tokens (token_hash, description, expires_at, reusable, revoked, org_id)
			VALUES ($1, 'test', NOW() + interval '1 hour', $2, false, $3)`, sha256Hex(plain), reusable, orgID); err != nil {
			t.Fatalf("seed enrollment token: %v", err)
		}
	}
	newToken("fleet-token", true)

	agentH := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	router := gin.New()
	agentH.RegisterAgentPublicRoutes(router.Group("/api/v1/access"))
	// The admin surface sits behind the JWT middleware in the service, which
	// puts the caller, their scope and their tenant on the request. This group
	// stands in for it; the operator gate is not what is under test.
	admin := router.Group("/api/v1/access", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
		c.Set("user_id", userID)
		c.Set("scope", "openid offline_access "+enrollScope)
		c.Next()
	})
	agentH.RegisterAgentAdminRoutes(admin, nil)

	type enrolment struct {
		AgentID   string `json:"agent_id"`
		AuthToken string `json:"auth_token"`
		Status    string `json:"status"`
	}
	send := func(method, path string, header map[string]string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	device := func(fp string) map[string]any {
		return map[string]any{"hostname": "PC-" + fp, "platform": "windows", "device_fingerprint": fp}
	}
	byToken := func(token, fp string) *httptest.ResponseRecorder {
		return send(http.MethodPost, "/api/v1/access/agent/enroll",
			map[string]string{"Authorization": "Bearer " + token}, device(fp))
	}
	byOAuth := func(fp string) *httptest.ResponseRecorder {
		return send(http.MethodPost, "/api/v1/access/agent/enroll/oauth", nil, device(fp))
	}
	enrolled := func(t *testing.T, w *httptest.ResponseRecorder) enrolment {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("enrolment answered %d, want 200: %s", w.Code, w.Body.String())
		}
		var e enrolment
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.AgentID == "" || e.AuthToken == "" {
			t.Fatalf("enrolment answer has no credential (%v): %s", err, w.Body.String())
		}
		return e
	}
	revoke := func(t *testing.T, agentID string) {
		t.Helper()
		if w := send(http.MethodDelete, "/api/v1/access/agents/"+agentID, nil, nil); w.Code != http.StatusOK {
			t.Fatalf("revoke answered %d: %s", w.Code, w.Body.String())
		}
	}
	config := func(e enrolment) int {
		return send(http.MethodGet, "/api/v1/access/agent/config",
			map[string]string{"X-Agent-ID": e.AgentID, "X-Auth-Token": e.AuthToken}, nil).Code
	}
	type row struct{ status, hash string }
	read := func(t *testing.T, agentID string) row {
		t.Helper()
		var r row
		if err := db.Pool.QueryRow(ctx,
			`SELECT status, auth_token_hash FROM enrolled_agents WHERE agent_id = $1`, agentID).
			Scan(&r.status, &r.hash); err != nil {
			t.Fatalf("read %s: %v", agentID, err)
		}
		return r
	}
	refusals := func(t *testing.T, agentID string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `
			SELECT count(*) FROM unified_audit_events
			 WHERE event_type = 'agent.enroll_denied' AND org_id::text = $1
			   AND details->>'agent_id' = $2 AND details->>'outcome' = 'denied'`,
			orgID, agentID).Scan(&n); err != nil {
			t.Fatalf("read the audit trail: %v", err)
		}
		return n
	}
	assertRefused := func(t *testing.T, w *httptest.ResponseRecorder, agentID string, before row, auditsBefore int) {
		t.Helper()
		if w.Code != http.StatusForbidden {
			t.Fatalf("re-enrolling a revoked device answered %d, want 403: %s", w.Code, w.Body.String())
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("the refusal is not JSON: %s", w.Body.String())
		}
		if body["code"] != "agent_revoked" || body["error"] != "agent revoked" {
			t.Errorf("refusal body = %v, want error %q and code %q", body, "agent revoked", "agent_revoked")
		}
		if _, leaked := body["auth_token"]; leaked {
			t.Errorf("the refusal carries a credential: %s", w.Body.String())
		}
		if _, leaked := body["agent_id"]; leaked {
			t.Errorf("the refusal names the agent to a caller who only claimed a fingerprint: %s", w.Body.String())
		}
		if after := read(t, agentID); after != before {
			t.Errorf("the refused enrolment changed the revoked row: %+v -> %+v", before, after)
		}
		if n := refusals(t, agentID); n != auditsBefore+1 {
			t.Errorf("found %d agent.enroll_denied records in the agent's tenant, want %d", n, auditsBefore+1)
		}
	}

	t.Run("by enrollment token", func(t *testing.T) {
		const fp = "win:token-revoked"
		first := enrolled(t, byToken("fleet-token", fp))
		revoke(t, first.AgentID)
		before := read(t, first.AgentID)

		assertRefused(t, byToken("fleet-token", fp), first.AgentID, before, 0)
		if code := config(first); code != http.StatusForbidden {
			t.Errorf("the revoked device's old credential answered %d on /agent/config, want 403", code)
		}
	})

	t.Run("by a single-use token, which stays spent", func(t *testing.T) {
		const fp = "win:single-use-revoked"
		first := enrolled(t, byToken("fleet-token", fp))
		revoke(t, first.AgentID)
		before := read(t, first.AgentID)

		newToken("one-shot", false)
		assertRefused(t, byToken("one-shot", fp), first.AgentID, before, 0)
		var usedBy *string
		if err := db.Pool.QueryRow(ctx,
			`SELECT used_by_agent FROM agent_enrollment_tokens WHERE token_hash = $1`, sha256Hex("one-shot")).
			Scan(&usedBy); err != nil {
			t.Fatalf("read the token back: %v", err)
		}
		if usedBy != nil {
			t.Errorf("the token records %q as the agent it enrolled; it enrolled none", *usedBy)
		}
		if w := byToken("one-shot", "win:some-other-machine"); w.Code != http.StatusUnauthorized {
			t.Errorf("the single-use token presented for a revoked machine still enrols: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("by OAuth, as any user of the organization", func(t *testing.T) {
		const fp = "win:oauth-revoked"
		first := enrolled(t, byOAuth(fp))
		revoke(t, first.AgentID)
		before := read(t, first.AgentID)

		assertRefused(t, byOAuth(fp), first.AgentID, before, 0)
		// The device was enrolled by OAuth and revoked; an enrollment token
		// does not bring it back either.
		assertRefused(t, byToken("fleet-token", fp), first.AgentID, before, 1)
		if code := config(first); code != http.StatusForbidden {
			t.Errorf("the revoked device's old credential answered %d on /agent/config, want 403", code)
		}
	})

	t.Run("a device that was not revoked re-enrols on each path", func(t *testing.T) {
		const fp = "win:still-active"
		first := enrolled(t, byToken("fleet-token", fp))
		again := enrolled(t, byToken("fleet-token", fp))
		viaOAuth := enrolled(t, byOAuth(fp))
		if again.AgentID != first.AgentID || viaOAuth.AgentID != first.AgentID {
			t.Errorf("re-enrolment changed the agent: %q, %q, %q", first.AgentID, again.AgentID, viaOAuth.AgentID)
		}
		if viaOAuth.Status != "active" {
			t.Errorf("re-enrolled status %q, want active", viaOAuth.Status)
		}
		if code := config(viaOAuth); code != http.StatusOK {
			t.Errorf("the newest credential answered %d on /agent/config, want 200", code)
		}
		if code := config(first); code != http.StatusUnauthorized {
			t.Errorf("a rotated-out credential answered %d on /agent/config, want 401", code)
		}
	})

	t.Run("a suspended device re-enrols to active, which is how a suspension lifts", func(t *testing.T) {
		const fp = "win:suspended"
		first := enrolled(t, byToken("fleet-token", fp))
		if _, err := db.Pool.Exec(ctx,
			`UPDATE enrolled_agents SET status = 'suspended', compliance_status = 'non_compliant' WHERE agent_id = $1`,
			first.AgentID); err != nil {
			t.Fatalf("suspend: %v", err)
		}
		again := enrolled(t, byToken("fleet-token", fp))
		if again.AgentID != first.AgentID {
			t.Errorf("re-enrolment changed the agent: %q -> %q", first.AgentID, again.AgentID)
		}
		if r := read(t, first.AgentID); r.status != "active" {
			t.Errorf("a re-enrolled suspended device is %q, want active", r.status)
		}
	})
}
