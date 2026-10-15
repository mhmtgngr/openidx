package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The agent API contract, driven end to end.
//
// Five times in three weeks the server and a client stopped speaking the
// same language -- the posture check's field, the tunnel status, the push
// approval, the mobile dial, the notification body -- and each was found by
// a person. This test drives the real handlers, on the migrated schema, with
// the exact JSON the shipped agents send (api/agent-v1/examples), through the
// whole life of a device: enrol, read the config, report posture in the
// desktop shape and in the Android shape, show up in the fleet, be revoked,
// and be refused everywhere after. A field renamed on one side only fails
// here, in CI, before a device does.

// agentExample reads one file from api/agent-v1/examples and fills the
// placeholders the file leaves for values only a running test has.
func agentExample(t *testing.T, name string, fill map[string]string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "agent-v1", "examples", name))
	if err != nil {
		t.Fatalf("read the example %s: %v", name, err)
	}
	s := string(b)
	for placeholder, value := range fill {
		if !strings.Contains(s, placeholder) {
			t.Fatalf("the example %s has no placeholder %q to fill", name, placeholder)
		}
		s = strings.ReplaceAll(s, placeholder, value)
	}
	if strings.Contains(s, "; the test fills it>") {
		t.Fatalf("the example %s still has an unfilled placeholder:\n%s", name, s)
	}
	return []byte(s)
}

func TestAgentContractFlow(t *testing.T) {
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
	var orgID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('contract-org', 'contract-org') RETURNING id::text`).
		Scan(&orgID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	octx := orgctx.With(ctx, orgctx.Org{ID: orgID})
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, description, expires_at, reusable, revoked, org_id)
		VALUES ($1, 'contract', NOW() + interval '1 hour', true, false, $2)`, sha256Hex("fleet-token"), orgID); err != nil {
		t.Fatalf("seed enrollment token: %v", err)
	}

	agentH := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	router := gin.New()
	agentH.RegisterAgentPublicRoutes(router.Group("/api/v1/access"))
	admin := router.Group("/api/v1/access", func(c *gin.Context) {
		c.Request = c.Request.WithContext(octx)
		c.Next()
	})
	agentH.RegisterAgentAdminRoutes(admin, nil)

	type credential struct{ agentID, deviceID, token string }
	send := func(method, path string, headers map[string]string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	asAgent := func(cr credential) map[string]string {
		return map[string]string{"X-Agent-ID": cr.agentID, "X-Auth-Token": cr.token}
	}
	decode := func(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("the answer is not a JSON object: %s", w.Body.String())
		}
		return m
	}
	enrol := func(t *testing.T, body []byte) credential {
		t.Helper()
		w := send(http.MethodPost, "/api/v1/access/agent/enroll", map[string]string{"Authorization": "Bearer fleet-token"}, body)
		if w.Code != http.StatusOK {
			t.Fatalf("enrol answered %d: %s", w.Code, w.Body.String())
		}
		m := decode(t, w)
		cr := credential{agentID: str(m["agent_id"]), deviceID: str(m["device_id"]), token: str(m["auth_token"])}
		if cr.agentID == "" || cr.deviceID == "" || cr.token == "" {
			t.Fatalf("the enrolment answer lacks agent_id, device_id or auth_token: %s", w.Body.String())
		}
		return cr
	}
	postureRows := func(t *testing.T, agentID string) map[string]string {
		t.Helper()
		rows, err := db.Pool.Query(octx, `SELECT check_type, status FROM agent_posture_results WHERE agent_id = $1`, agentID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		got := map[string]string{}
		for rows.Next() {
			var ct, st string
			if err := rows.Scan(&ct, &st); err != nil {
				t.Fatal(err)
			}
			got[ct] = st
		}
		return got
	}
	tunnelState := func(t *testing.T, agentID string) (state string, lastSeen bool) {
		t.Helper()
		if err := db.Pool.QueryRow(octx, `
			SELECT COALESCE(tunnel_status->>'state', ''), tunnel_last_seen IS NOT NULL
			  FROM enrolled_agents WHERE agent_id = $1`, agentID).Scan(&state, &lastSeen); err != nil {
			t.Fatal(err)
		}
		return state, lastSeen
	}

	// --- 1. The desktop agent enrols, naming its device key.
	priv, pub := newTestDeviceKey(t)
	desktop := enrol(t, agentExample(t, "enroll-request.json", map[string]string{
		"<enrollment token; also sent as Authorization: Bearer>":  "fleet-token",
		"<device public key, base64 PKIX DER; the test fills it>": pub,
	}))
	var bound bool
	if err := db.Pool.QueryRow(octx, `SELECT device_public_key IS NOT NULL FROM enrolled_agents WHERE agent_id = $1`, desktop.agentID).Scan(&bound); err != nil || !bound {
		t.Fatalf("the enrolment did not bind the device key (err %v)", err)
	}

	// --- 2. The config the agent reads every 30 seconds.
	w := send(http.MethodGet, "/api/v1/access/agent/config", asAgent(desktop), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("config answered %d: %s", w.Code, w.Body.String())
	}
	cfg := decode(t, w)
	if cfg["report_interval"] != "30s" {
		t.Errorf("report_interval = %v, want 30s for an active agent", cfg["report_interval"])
	}
	if cfg["enrollment_status"] != "active" {
		t.Errorf("enrollment_status = %v, want active", cfg["enrollment_status"])
	}
	if _, ok := cfg["device_trusted"].(bool); !ok {
		t.Errorf("device_trusted is %T, want a boolean", cfg["device_trusted"])
	}
	if checks, ok := cfg["checks"].([]any); !ok {
		t.Errorf("checks is %T, want an array (the agent decodes it as a slice)", cfg["checks"])
	} else {
		for _, c := range checks {
			m, _ := c.(map[string]any)
			if _, has := m["type"]; !has {
				t.Errorf("a configured check carries no \"type\": %v (the agent ran every check as unknown when it was \"check_type\")", m)
			}
		}
	}

	// --- 3. The desktop agent reports, signed, in its own shape.
	report := agentExample(t, "report-desktop-agent.json", map[string]string{
		"<the agent's own id; the test fills it>":    desktop.agentID,
		"<the agent's device id; the test fills it>": desktop.deviceID,
	})
	ts, sig := signAgentRequest(t, priv, http.MethodPost, "/api/v1/access/agent/report", desktop.agentID, time.Now(), report)
	signed := asAgent(desktop)
	signed[headerAgentKeyTimestamp], signed[headerAgentKeySignature] = ts, sig
	w = send(http.MethodPost, "/api/v1/access/agent/report", signed, report)
	if w.Code != http.StatusAccepted {
		t.Fatalf("the desktop report answered %d: %s", w.Code, w.Body.String())
	}
	if m := decode(t, w); m["status"] != "accepted" {
		t.Errorf("report answer = %s, want status accepted", w.Body.String())
	}
	if got := postureRows(t, desktop.agentID); got["disk_encryption"] != "pass" || got["firewall"] != "fail" {
		t.Errorf("the desktop report's nested results were stored as %v, want disk_encryption=pass firewall=fail", got)
	}
	if state, seen := tunnelState(t, desktop.agentID); state != "up" || !seen {
		t.Errorf("the desktop tunnel status landed as state %q (seen %v), want up (connected) and a last-seen time", state, seen)
	}
	if w := send(http.MethodPost, "/api/v1/access/agent/report", asAgent(desktop), report); w.Code != http.StatusUnauthorized {
		t.Errorf("an unsigned report from the keyed device answered %d, want 401", w.Code)
	}

	// --- 4. The Android agent enrols without a key and reports flat.
	android := enrol(t, []byte(`{"hostname":"pixel","os":"android","platform":"android","device_fingerprint":"android:contract","form_factor":"phone","management_mode":"device_owner"}`))
	flat := agentExample(t, "report-android-agent.json", map[string]string{
		"<the agent's own id; the test fills it>": android.agentID,
	})
	if w := send(http.MethodPost, "/api/v1/access/agent/report", asAgent(android), flat); w.Code != http.StatusAccepted {
		t.Fatalf("the Android report answered %d: %s", w.Code, w.Body.String())
	}
	if got := postureRows(t, android.agentID); got["screen_lock"] != "pass" || got["developer_options"] != "fail" {
		t.Errorf("the Android report's flat results were stored as %v, want screen_lock=pass developer_options=fail", got)
	}
	if state, _ := tunnelState(t, android.agentID); state != "up" {
		t.Errorf("the Android tunnel status (services as objects, state up) landed as %q, want up", state)
	}

	// --- 5. Both devices are in the fleet, with the fields the console reads.
	w = send(http.MethodGet, "/api/v1/access/agents", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("the fleet list answered %d: %s", w.Code, w.Body.String())
	}
	// The list is a bare JSON array, which the console's fleet page reads.
	var agents []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatalf("the fleet list is not a JSON array: %s", w.Body.String())
	}
	seen := map[string]map[string]any{}
	for _, m := range agents {
		seen[str(m["agent_id"])] = m
	}
	for _, id := range []string{desktop.agentID, android.agentID} {
		m, ok := seen[id]
		if !ok {
			t.Errorf("the fleet list does not show %s: %s", id, w.Body.String())
			continue
		}
		for _, key := range []string{"status", "platform", "tunnel_status", "tunnel_policy_state"} {
			if _, has := m[key]; !has {
				t.Errorf("the fleet row for %s has no %q", id, key)
			}
		}
	}

	// --- 6. Revoked from the fleet, the device is refused on every route.
	if w := send(http.MethodDelete, "/api/v1/access/agents/"+desktop.agentID, nil, nil); w.Code != http.StatusOK {
		t.Fatalf("revoke answered %d: %s", w.Code, w.Body.String())
	}
	refused := func(t *testing.T, name string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusForbidden {
			t.Errorf("%s answered %d after the revoke, want 403: %s", name, w.Code, w.Body.String())
			return
		}
		if m := decode(t, w); m["code"] != "agent_revoked" {
			t.Errorf("%s refusal code = %v, want agent_revoked", name, m["code"])
		}
	}
	refused(t, "config", send(http.MethodGet, "/api/v1/access/agent/config", asAgent(desktop), nil))
	refused(t, "report", send(http.MethodPost, "/api/v1/access/agent/report", signed, report))
	refused(t, "device-key", send(http.MethodPost, "/api/v1/access/agent/device-key", asAgent(desktop), []byte(`{"public_key":"x","kind":"file"}`)))
	// And the Android device, untouched, still reports.
	if w := send(http.MethodPost, "/api/v1/access/agent/report", asAgent(android), flat); w.Code != http.StatusAccepted {
		t.Errorf("the other device's report answered %d after a different device's revoke", w.Code)
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
