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

// THE FLEET IS PER-TENANT (migration v197), measured against the full chain.
//
// Three tables from v43 carried no org_id, so the admin fleet list and the
// token list were the installation's rather than the organization's, a kiosk
// assignment could target another tenant's device, and a token-enrolled
// device with no enrolling user belonged to nobody. This test migrates to
// v196, seeds the old shape, migrates to the latest, and measures:
//
//   - the backfill, source by source: a token from its minting user, an agent
//     from its enrolling user, then from the token that admitted it, then the
//     oldest organization; posture from its agent;
//   - the schema: NOT NULL, the per-tenant fingerprint key in place of the
//     install-wide one;
//   - the handlers: each organization's administrator lists, revokes and
//     approves only its own devices and tokens, and a token minted in one
//     tenant enrols a device into that tenant.
//
// setupTestDB connects as a superuser, which RLS does not apply to, so what
// this measures is the predicates the handlers carry; the belt itself is
// measured as the application role in fleet_belt_testdb_test.go.
func TestFleet_TenantIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	mig := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop())
	if err := mig.MigrateTo(ctx, 196); err != nil {
		t.Fatalf("migrate to v196: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB, oldest string
	if err := db.Pool.QueryRow(ctx, `INSERT INTO organizations (name, slug) VALUES ('fleet-b','fleet-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1`).Scan(&oldest); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var alice, bob string
	if err := db.Pool.QueryRow(ctx, `INSERT INTO users (org_id, username, email) VALUES ($1, 'alice-'||$2, 'alice-'||$2||'@a.example') RETURNING id::text`, orgA, suffix).Scan(&alice); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `INSERT INTO users (org_id, username, email) VALUES ($1, 'bob-'||$2, 'bob-'||$2||'@b.example') RETURNING id::text`, orgB, suffix).Scan(&bob); err != nil {
		t.Fatalf("seed bob: %v", err)
	}

	// The old shape: no tenant anywhere.
	seeds := []string{
		// tokens: minted by alice (A), by bob (B), by free text (nobody)
		`INSERT INTO agent_enrollment_tokens (token_hash, created_by, expires_at) VALUES ('h-alice', '` + alice + `', NOW() + interval '1 day')`,
		`INSERT INTO agent_enrollment_tokens (token_hash, created_by, expires_at, used_by_agent) VALUES ('h-bob', '` + bob + `', NOW() + interval '1 day', 'agent-token-only')`,
		`INSERT INTO agent_enrollment_tokens (token_hash, created_by, expires_at) VALUES ('h-text', 'MDM rollout', NOW() + interval '1 day')`,
		// agents: enrolled by alice (A); admitted by bob's token, no user (B); nothing at all (oldest)
		`INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash, enrolled_by_user_id) VALUES ('agent-alice', 'd1', 'active', 'h1', '` + alice + `')`,
		`INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash) VALUES ('agent-token-only', 'd2', 'active', 'h2')`,
		`INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash) VALUES ('agent-orphan', 'd3', 'active', 'h3')`,
		// posture: alice's agent (A), bob's agent (B), an agent that no longer exists (oldest)
		`INSERT INTO agent_posture_results (agent_id, check_type, status, severity) VALUES ('agent-alice', 'disk', 'pass', 'low')`,
		`INSERT INTO agent_posture_results (agent_id, check_type, status, severity) VALUES ('agent-token-only', 'disk', 'fail', 'high')`,
		`INSERT INTO agent_posture_results (agent_id, check_type, status, severity) VALUES ('agent-gone', 'disk', 'pass', 'low')`,
	}
	for _, s := range seeds {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v\n%s", err, s)
		}
	}

	if err := mig.MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	orgOf := func(table, key, val string) string {
		t.Helper()
		var org string
		if err := db.Pool.QueryRow(ctx, `SELECT org_id::text FROM `+table+` WHERE `+key+` = $1`, val).Scan(&org); err != nil {
			t.Fatalf("%s %s=%s: %v", table, key, val, err)
		}
		return org
	}
	t.Run("the backfill attributes every row to the most exact tenant it can", func(t *testing.T) {
		if got := orgOf("agent_enrollment_tokens", "token_hash", "h-alice"); got != orgA {
			t.Errorf("alice's token went to %s, want her organization", got)
		}
		if got := orgOf("agent_enrollment_tokens", "token_hash", "h-bob"); got != orgB {
			t.Errorf("bob's token went to %s, want his organization", got)
		}
		if got := orgOf("agent_enrollment_tokens", "token_hash", "h-text"); got != oldest {
			t.Errorf("a token nobody can be attributed went to %s, want the oldest organization", got)
		}
		if got := orgOf("enrolled_agents", "agent_id", "agent-alice"); got != orgA {
			t.Errorf("alice's device went to %s, want her organization", got)
		}
		if got := orgOf("enrolled_agents", "agent_id", "agent-token-only"); got != orgB {
			t.Errorf("the device admitted by bob's token went to %s, want bob's organization: a token-enrolled device with no user had no tenant, and the token is what knows it", got)
		}
		if got := orgOf("enrolled_agents", "agent_id", "agent-orphan"); got != oldest {
			t.Errorf("an unattributable device went to %s, want the oldest organization", got)
		}
		if got := orgOf("agent_posture_results", "agent_id", "agent-alice"); got != orgA {
			t.Errorf("posture of alice's device went to %s", got)
		}
		if got := orgOf("agent_posture_results", "agent_id", "agent-token-only"); got != orgB {
			t.Errorf("posture of the token-enrolled device went to %s", got)
		}
		if got := orgOf("agent_posture_results", "agent_id", "agent-gone"); got != oldest {
			t.Errorf("posture of a vanished device went to %s, want the oldest organization", got)
		}
	})

	t.Run("the schema holds the tenant and keys the fingerprint per tenant", func(t *testing.T) {
		for _, table := range []string{"enrolled_agents", "agent_posture_results", "agent_enrollment_tokens"} {
			var nullable string
			if err := db.Pool.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns WHERE table_name = $1 AND column_name = 'org_id'`, table).Scan(&nullable); err != nil {
				t.Fatalf("%s.org_id: %v", table, err)
			}
			if nullable != "NO" {
				t.Errorf("%s.org_id is nullable; a device without a tenant is the old shape", table)
			}
			var forced bool
			if err := db.Pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname = $1`, table).Scan(&forced); err != nil {
				t.Fatal(err)
			}
			if !forced {
				t.Errorf("%s is not under FORCE ROW LEVEL SECURITY", table)
			}
		}
		var oldKey, newKey int
		_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname = 'enrolled_agents_device_fingerprint_key'`).Scan(&oldKey)
		_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname = 'enrolled_agents_org_device_fingerprint_key'`).Scan(&newKey)
		if oldKey != 0 || newKey != 1 {
			t.Errorf("fingerprint keys: install-wide=%d per-tenant=%d, want 0 and 1", oldKey, newKey)
		}
		// One machine, two tenants: two devices.
		for _, org := range []string{orgA, orgB} {
			if _, err := db.Pool.Exec(ctx, `INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash, device_fingerprint, org_id) VALUES ('shared-'||$1::text, 'd', 'active', 'h', 'fp:shared', $1::uuid)`, org); err != nil {
				t.Errorf("tenant %s could not enrol a machine another tenant also manages: %v", org, err)
			}
		}
		if _, err := db.Pool.Exec(ctx, `INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash, device_fingerprint, org_id) VALUES ('shared-again', 'd', 'active', 'h', 'fp:shared', $1::uuid)`, orgA); err == nil {
			t.Error("the same fingerprint enrolled twice into ONE tenant; the stable-identity key is gone")
		}
	})

	h := NewAgentAPIHandler(zap.NewNop(), db, nil, &config.Config{Environment: "production"})
	call := func(handler gin.HandlerFunc, org, method, path, body string, params gin.Params) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		r := httptest.NewRequest(method, path, nil)
		if body != "" {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		c.Request = r.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Params = params
		handler(c)
		return w
	}
	listAgents := func(org string) []string {
		t.Helper()
		w := call(h.HandleListAgents, org, http.MethodGet, "/agents", "", nil)
		if w.Code != 200 {
			t.Fatalf("list agents as %s: %d %s", org, w.Code, w.Body.String())
		}
		var out []agentRecord
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, a := range out {
			ids = append(ids, a.AgentID)
		}
		return ids
	}

	t.Run("the admin fleet list is the organization's, not the installation's", func(t *testing.T) {
		for _, id := range listAgents(orgA) {
			if id == "agent-token-only" || id == "shared-"+orgB {
				t.Errorf("tenant A's fleet list shows tenant B's device %s", id)
			}
		}
		for _, id := range listAgents(orgB) {
			if id == "agent-alice" || id == "agent-orphan" {
				t.Errorf("tenant B's fleet list shows a device that is not its own: %s", id)
			}
		}
		if len(listAgents(orgB)) == 0 {
			t.Error("tenant B's list is empty; its own device is missing")
		}
	})

	t.Run("revoke and approve reach only the caller's own device", func(t *testing.T) {
		p := gin.Params{{Key: "agent_id", Value: "agent-alice"}}
		if w := call(h.HandleRevokeAgent, orgB, http.MethodDelete, "/agents/agent-alice", "", p); w.Code != http.StatusNotFound {
			t.Errorf("tenant B revoked tenant A's device: %d %s", w.Code, w.Body.String())
		}
		var status string
		_ = db.Pool.QueryRow(ctx, `SELECT status FROM enrolled_agents WHERE agent_id = 'agent-alice'`).Scan(&status)
		if status != "active" {
			t.Errorf("alice's device is %q after a foreign revoke", status)
		}
		if w := call(h.HandleRevokeAgent, orgA, http.MethodDelete, "/agents/agent-alice", "", p); w.Code != http.StatusOK {
			t.Errorf("tenant A could not revoke its own device: %d %s", w.Code, w.Body.String())
		}
		if _, err := db.Pool.Exec(ctx, `UPDATE enrolled_agents SET status = 'pending' WHERE agent_id = 'agent-token-only'`); err != nil {
			t.Fatal(err)
		}
		p = gin.Params{{Key: "agent_id", Value: "agent-token-only"}}
		if w := call(h.HandleApproveAgent, orgA, http.MethodPost, "/agents/agent-token-only/approve", "", p); w.Code != http.StatusConflict {
			t.Errorf("tenant A approved tenant B's pending device: %d %s", w.Code, w.Body.String())
		}
		if w := call(h.HandleApproveAgent, orgB, http.MethodPost, "/agents/agent-token-only/approve", "", p); w.Code != http.StatusOK {
			t.Errorf("tenant B could not approve its own device: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("a token minted in one tenant enrols a device into that tenant, and its list is that tenant's", func(t *testing.T) {
		w := call(h.HandleGenerateToken, orgB, http.MethodPost, "/agent/tokens", `{"description":"b-desk"}`, nil)
		if w.Code != http.StatusOK && w.Code != http.StatusCreated {
			t.Fatalf("mint token as B: %d %s", w.Code, w.Body.String())
		}
		var minted struct {
			Token string `json:"token"`
			ID    string `json:"id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &minted); err != nil || minted.Token == "" {
			t.Fatalf("mint response: %v %s", err, w.Body.String())
		}
		if got := orgOf("agent_enrollment_tokens", "id", minted.ID); got != orgB {
			t.Errorf("the token was minted into %s, want the caller's tenant", got)
		}
		// Token lists: A does not see B's token.
		wl := call(h.HandleListTokens, orgA, http.MethodGet, "/agent/tokens", "", nil)
		if w := wl; w.Code == 200 && containsID(w.Body.Bytes(), minted.ID) {
			t.Error("tenant A's token list shows tenant B's token")
		}
		// A cannot revoke B's token.
		if w := call(h.HandleRevokeToken, orgA, http.MethodDelete, "/agent/tokens/"+minted.ID, "", gin.Params{{Key: "token_id", Value: minted.ID}}); w.Code != http.StatusNotFound {
			t.Errorf("tenant A revoked tenant B's token: %d", w.Code)
		}
		// The public enrol: no tenant on the request; the token decides.
		we := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(we)
		c.Request = httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
		c.Request.Header.Set("Authorization", "Bearer "+minted.Token)
		h.HandleEnroll(c)
		if we.Code != http.StatusOK {
			t.Fatalf("enrol with B's token: %d %s", we.Code, we.Body.String())
		}
		var enrolled struct {
			AgentID string `json:"agent_id"`
		}
		if err := json.Unmarshal(we.Body.Bytes(), &enrolled); err != nil || enrolled.AgentID == "" {
			t.Fatalf("enrol response: %v %s", err, we.Body.String())
		}
		if got := orgOf("enrolled_agents", "agent_id", enrolled.AgentID); got != orgB {
			t.Errorf("the device enrolled by B's token landed in %s, want B", got)
		}
		for _, id := range listAgents(orgA) {
			if id == enrolled.AgentID {
				t.Error("tenant A's fleet list shows the device B's token just enrolled")
			}
		}
	})
}

func containsID(body []byte, id string) bool {
	var rows []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return false
	}
	for _, r := range rows {
		if r.ID == id {
			return true
		}
	}
	return false
}
