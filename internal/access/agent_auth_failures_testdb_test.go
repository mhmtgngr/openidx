package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// A device whose credential is refused is counted on its row, and the run of
// refusals is audited once when it reaches its threshold, instead of only one
// agent.auth_failed record per refusal forever. A probe with an invented
// agent id counts nothing; the device's next accepted request clears the run.
func TestRefusedAgentCredentialsAreCountedAndAuditedOnce(t *testing.T) {
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
		`INSERT INTO organizations (name, slug) VALUES ('authfail-org', 'authfail-org') RETURNING id::text`).
		Scan(&orgID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	const agentID, goodToken = "agent-authfail", "the-right-token"
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash, enrolled_at, compliance_status, org_id)
		VALUES ($1, 'device-authfail', 'active', $2, NOW(), 'unknown', $3::uuid)`,
		agentID, sha256Hex(goodToken), orgID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	agentH := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	router := gin.New()
	agentH.RegisterAgentPublicRoutes(router.Group("/api/v1/access"))
	config := func(id, token string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/access/agent/config", nil)
		req.Header.Set("X-Agent-ID", id)
		req.Header.Set("X-Auth-Token", token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}
	count := func(t *testing.T) (n int, failedAtSet bool) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx,
			`SELECT auth_fail_count, auth_failed_at IS NOT NULL FROM enrolled_agents WHERE agent_id = $1`, agentID).
			Scan(&n, &failedAtSet); err != nil {
			t.Fatalf("read the row: %v", err)
		}
		return n, failedAtSet
	}
	persistent := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `
			SELECT count(*) FROM unified_audit_events
			 WHERE event_type = 'agent.auth_failed_persistent' AND org_id::text = $1
			   AND details->>'agent_id' = $2`, orgID, agentID).Scan(&n); err != nil {
			t.Fatalf("read the audit trail: %v", err)
		}
		return n
	}

	for i := 1; i < authFailPersistentThreshold; i++ {
		if code := config(agentID, "stale"); code != http.StatusUnauthorized {
			t.Fatalf("a stale credential answered %d, want 401", code)
		}
	}
	if n, set := count(t); n != authFailPersistentThreshold-1 || !set {
		t.Fatalf("after %d refusals the row says count=%d failed_at set=%v", authFailPersistentThreshold-1, n, set)
	}
	if n := persistent(t); n != 0 {
		t.Fatalf("%d persistent records before the threshold, want 0", n)
	}

	for i := 0; i < 3; i++ {
		config(agentID, "stale")
	}
	if n := persistent(t); n != 1 {
		t.Errorf("found %d agent.auth_failed_persistent records in the agent's tenant, want exactly 1", n)
	}

	if code := config("agent-does-not-exist", "x"); code != http.StatusUnauthorized {
		t.Fatalf("an invented agent answered %d, want 401", code)
	}
	var phantom int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM enrolled_agents WHERE agent_id = 'agent-does-not-exist'`).Scan(&phantom); err != nil || phantom != 0 {
		t.Errorf("a probe with an invented id created or touched a row (%d, %v)", phantom, err)
	}

	if code := config(agentID, goodToken); code != http.StatusOK {
		t.Fatalf("the right credential answered %d, want 200", code)
	}
	if n, _ := count(t); n != 0 {
		t.Errorf("an accepted request left auth_fail_count=%d, want 0", n)
	}

	// A new run after recovery is audited again.
	for i := 0; i < authFailPersistentThreshold; i++ {
		config(agentID, "stale")
	}
	if n := persistent(t); n != 2 {
		t.Errorf("a second run of refusals left %d persistent records, want 2", n)
	}
}
