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

// continuityHarness drives the real enrolment and fleet handlers through gin
// against the migrated schema (v252), as an operator of one organization.
type continuityHarness struct {
	t      *testing.T
	ctx    context.Context
	h      *AgentAPIHandler
	router *gin.Engine
	orgID  string
	admin  string
}

type continuityEnrolment struct {
	AgentID   string `json:"agent_id"`
	AuthToken string `json:"auth_token"`
	Status    string `json:"status"`
}

func newContinuityHarness(t *testing.T, slug string) (*continuityHarness, func(sql string, args ...any) error, func(dst []any, sql string, args ...any)) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.Skip("no test database")
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	var orgID, adminID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, slug).Scan(&orgID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2::text, $2::text || '@example.test', true)
		 RETURNING id::text`, orgID, slug+"-admin").Scan(&adminID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, description, expires_at, reusable, revoked, org_id)
		VALUES ($1, 'fleet', NOW() + interval '1 hour', true, false, $2)`, sha256Hex(slug+"-fleet"), orgID); err != nil {
		t.Fatalf("seed enrollment token: %v", err)
	}
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	router := gin.New()
	h.RegisterAgentPublicRoutes(router.Group("/api/v1/access"))
	admin := router.Group("/api/v1/access", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
		c.Set("user_id", adminID)
		c.Next()
	})
	h.RegisterAgentAdminRoutes(admin, nil, nil, nil)
	exec := func(sql string, args ...any) error { _, err := db.Pool.Exec(ctx, sql, args...); return err }
	query := func(dst []any, sql string, args ...any) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx, sql, args...).Scan(dst...); err != nil {
			t.Fatalf("query %q: %v", sql, err)
		}
	}
	return &continuityHarness{t: t, ctx: ctx, h: h, router: router, orgID: orgID, admin: adminID}, exec, query
}

func (c *continuityHarness) send(method, path string, header map[string]string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
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
	c.router.ServeHTTP(w, req)
	return w
}

func (c *continuityHarness) enrol(token string, body map[string]any) *httptest.ResponseRecorder {
	return c.send(http.MethodPost, "/api/v1/access/agent/enroll", map[string]string{"Authorization": "Bearer " + token}, body)
}

func (c *continuityHarness) enrolled(w *httptest.ResponseRecorder) continuityEnrolment {
	c.t.Helper()
	if w.Code != http.StatusOK {
		c.t.Fatalf("enrolment answered %d, want 200: %s", w.Code, w.Body.String())
	}
	var e continuityEnrolment
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.AgentID == "" {
		c.t.Fatalf("enrolment answer has no credential (%v): %s", err, w.Body.String())
	}
	return e
}

func (c *continuityHarness) config(e continuityEnrolment) int {
	return c.send(http.MethodGet, "/api/v1/access/agent/config",
		map[string]string{"X-Agent-ID": e.AgentID, "X-Auth-Token": e.AuthToken}, nil).Code
}

func machine(host, fp, prev string) map[string]any {
	m := map[string]any{"hostname": host, "platform": "windows", "device_fingerprint": fp}
	if prev != "" {
		m["device_fingerprint_prev"] = prev
	}
	return m
}

// An administrator's Reinstate lifts a revoke: the device's next enrolment
// gets the same agent back, active. Without Reinstate it is refused as before.
func TestReinstateLetsRevokedDeviceEnrolAgain(t *testing.T) {
	c, _, query := newContinuityHarness(t, "reinstate-org")
	token := "reinstate-org-fleet"
	first := c.enrolled(c.enrol(token, machine("PC-1", "win2:reinstate", "")))
	if w := c.send(http.MethodDelete, "/api/v1/access/agents/"+first.AgentID, nil, nil); w.Code != http.StatusOK {
		t.Fatalf("revoke answered %d: %s", w.Code, w.Body.String())
	}
	if w := c.enrol(token, machine("PC-1", "win2:reinstate", "")); w.Code != http.StatusForbidden {
		t.Fatalf("a revoked device re-enrolled without Reinstate: %d", w.Code)
	}
	if w := c.send(http.MethodPost, "/api/v1/access/agents/"+first.AgentID+"/reinstate", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("reinstate answered %d: %s", w.Code, w.Body.String())
	}
	if code := c.config(first); code == http.StatusOK || code == http.StatusForbidden {
		t.Errorf("the revoked credential answered %d after reinstate; it must be refused 401 until the device enrols", code)
	}
	again := c.enrolled(c.enrol(token, machine("PC-1", "win2:reinstate", "")))
	if again.AgentID != first.AgentID {
		t.Errorf("reinstated device came back as %q, want %q", again.AgentID, first.AgentID)
	}
	if code := c.config(again); code != http.StatusOK {
		t.Errorf("the reinstated device's new credential answered %d", code)
	}
	var status string
	var reinstated bool
	query([]any{&status, &reinstated}, `SELECT status, reinstated_at IS NOT NULL FROM enrolled_agents WHERE agent_id = $1`, first.AgentID)
	if status != "active" || !reinstated {
		t.Errorf("row status=%q reinstated=%v, want active and stamped", status, reinstated)
	}
	if w := c.send(http.MethodPost, "/api/v1/access/agents/"+first.AgentID+"/reinstate", nil, nil); w.Code != http.StatusConflict {
		t.Errorf("reinstating an active device answered %d, want 409", w.Code)
	}
	if w := c.send(http.MethodPost, "/api/v1/access/agents/agent-nope/reinstate", nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("reinstating an unknown device answered %d, want 404", w.Code)
	}
}

// An old agent's row (hostname-folded fingerprint) moves to the stable
// fingerprint when the upgraded agent enrols with both, keeping its agent id.
func TestLegacyFingerprintMigratesToStableOne(t *testing.T) {
	c, _, query := newContinuityHarness(t, "legacy-org")
	token := "legacy-org-fleet"
	old := c.enrolled(c.enrol(token, machine("PC-OLD", "win:legacyhash", "")))
	upgraded := c.enrolled(c.enrol(token, machine("PC-OLD", "win2:stablehash", "win:legacyhash")))
	if upgraded.AgentID != old.AgentID {
		t.Fatalf("the upgraded agent got a new row %q, want %q", upgraded.AgentID, old.AgentID)
	}
	var fp string
	var n int
	query([]any{&fp}, `SELECT device_fingerprint FROM enrolled_agents WHERE agent_id = $1`, old.AgentID)
	query([]any{&n}, `SELECT count(*) FROM enrolled_agents WHERE org_id = $1`, c.orgID)
	if fp != "win2:stablehash" || n != 1 {
		t.Errorf("fingerprint=%q rows=%d, want the stable fingerprint on the one row", fp, n)
	}
	// And from then on the stable fingerprint alone finds it.
	if again := c.enrolled(c.enrol(token, machine("PC-OLD", "win2:stablehash", ""))); again.AgentID != old.AgentID {
		t.Errorf("the stable fingerprint did not find the row: %q", again.AgentID)
	}
}

// Renaming a PC keeps one row and records the new name.
func TestHostnameChangeKeepsOneRow(t *testing.T) {
	c, _, query := newContinuityHarness(t, "rename-org")
	token := "rename-org-fleet"
	first := c.enrolled(c.enrol(token, machine("PC-ALICE", "win2:rename", "win:alice")))
	renamed := c.enrolled(c.enrol(token, machine("PC-BOB", "win2:rename", "win:bob")))
	if renamed.AgentID != first.AgentID {
		t.Fatalf("rename made a second agent %q", renamed.AgentID)
	}
	var n int
	var host string
	query([]any{&n}, `SELECT count(*) FROM enrolled_agents WHERE org_id = $1`, c.orgID)
	query([]any{&host}, `SELECT hostname FROM enrolled_agents WHERE agent_id = $1`, first.AgentID)
	if n != 1 || host != "PC-BOB" {
		t.Errorf("rows=%d hostname=%q, want one row named PC-BOB", n, host)
	}
	w := c.send(http.MethodGet, "/api/v1/access/agents", nil, nil)
	var list []agentRecord
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 || list[0].Hostname != "PC-BOB" {
		t.Errorf("fleet list = %+v, want one device named PC-BOB", list)
	}
}

// Reassigning the owner moves the device and its known-device link to the new
// person and stamps who did it.
func TestReassignOwnerRebindsKnownDevice(t *testing.T) {
	c, exec, query := newContinuityHarness(t, "owner-org")
	token := "owner-org-fleet"
	e := c.enrolled(c.enrol(token, machine("PC-9", "win2:owner", "")))
	var alice, bob string
	query([]any{&alice}, `INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, 'alice-o', 'alice-o@example.test', true) RETURNING id::text`, c.orgID)
	query([]any{&bob}, `INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, 'bob-o', 'bob-o@example.test', true) RETURNING id::text`, c.orgID)

	if w := c.send(http.MethodPut, "/api/v1/access/agents/"+e.AgentID+"/owner", nil, map[string]string{"user_id": alice}); w.Code != http.StatusOK {
		t.Fatalf("assign to alice answered %d: %s", w.Code, w.Body.String())
	}
	var aliceKnown string
	query([]any{&aliceKnown}, `SELECT known_device_id::text FROM enrolled_agents WHERE agent_id = $1`, e.AgentID)
	if err := exec(`UPDATE known_devices SET trusted = true WHERE id = $1::uuid`, aliceKnown); err != nil {
		t.Fatal(err)
	}

	if w := c.send(http.MethodPut, "/api/v1/access/agents/"+e.AgentID+"/owner", nil, map[string]string{"user_id": bob}); w.Code != http.StatusOK {
		t.Fatalf("reassign to bob answered %d: %s", w.Code, w.Body.String())
	}
	var owner, known, changedBy, knownUser string
	var aliceTrusted bool
	query([]any{&owner, &known, &changedBy},
		`SELECT enrolled_by_user_id::text, known_device_id::text, owner_changed_by::text FROM enrolled_agents WHERE agent_id = $1`, e.AgentID)
	query([]any{&knownUser}, `SELECT user_id::text FROM known_devices WHERE id = $1::uuid`, known)
	query([]any{&aliceTrusted}, `SELECT trusted FROM known_devices WHERE id = $1::uuid`, aliceKnown)
	if owner != bob || knownUser != bob || changedBy != c.admin {
		t.Errorf("owner=%s known-device user=%s changed_by=%s, want bob, bob, the admin", owner, knownUser, changedBy)
	}
	if aliceTrusted {
		t.Error("the previous owner's known device kept its trust")
	}
	if w := c.send(http.MethodPut, "/api/v1/access/agents/"+e.AgentID+"/owner", nil, map[string]string{"user_id": "00000000-0000-0000-0000-000000000000"}); w.Code != http.StatusNotFound {
		t.Errorf("assigning to a user outside the organization answered %d, want 404", w.Code)
	}
}

// Retire frees the fingerprint (the same machine enrols as a new row), the
// retired device is answered 403 and hidden from the list unless asked for,
// and purge deletes only a retired row.
func TestRetireFreesFingerprintAndPurgeNeedsRetired(t *testing.T) {
	c, _, query := newContinuityHarness(t, "retire-org")
	token := "retire-org-fleet"
	e := c.enrolled(c.enrol(token, machine("PC-R", "win2:retire", "")))
	if w := c.send(http.MethodDelete, "/api/v1/access/agents/"+e.AgentID+"?purge=1", nil, nil); w.Code != http.StatusConflict {
		t.Errorf("purging an active device answered %d, want 409", w.Code)
	}
	if w := c.send(http.MethodPost, "/api/v1/access/agents/"+e.AgentID+"/retire", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("retire answered %d: %s", w.Code, w.Body.String())
	}
	if code := c.config(e); code != http.StatusForbidden {
		t.Errorf("a retired device's credential answered %d, want 403", code)
	}
	fresh := c.enrolled(c.enrol(token, machine("PC-R", "win2:retire", "")))
	if fresh.AgentID == e.AgentID {
		t.Error("the retired row was brought back; retire must free the fingerprint")
	}
	var list []agentRecord
	_ = json.Unmarshal(c.send(http.MethodGet, "/api/v1/access/agents", nil, nil).Body.Bytes(), &list)
	if len(list) != 1 || list[0].AgentID != fresh.AgentID {
		t.Errorf("default list = %+v, want only the new device", list)
	}
	_ = json.Unmarshal(c.send(http.MethodGet, "/api/v1/access/agents?include_retired=1", nil, nil).Body.Bytes(), &list)
	if len(list) != 2 {
		t.Errorf("include_retired list has %d devices, want 2", len(list))
	}
	if w := c.send(http.MethodDelete, "/api/v1/access/agents/"+e.AgentID+"?purge=1", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("purge answered %d: %s", w.Code, w.Body.String())
	}
	var n int
	query([]any{&n}, `SELECT count(*) FROM enrolled_agents WHERE agent_id = $1`, e.AgentID)
	if n != 0 {
		t.Error("purge left the row")
	}
}
