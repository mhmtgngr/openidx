package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// A refusal that was not recorded must not be answered as one.
//
// The denial branch of HandleAgentConsent carries the comment "A denial ends
// the session immediately (fail-closed)", and the statement under it discarded
// its error. So on a failure the session was NOT ended, the audit still wrote
// remote_support.consent_denied with outcome "success", and the agent was
// answered {"consent_status":"denied","status":"ended"}.
//
// The person at the device refused to have their screen watched, was shown a
// confirmation, and the session stayed live. Every record said they had been
// listened to.

func TestARefusedRemoteSupportSessionIsActuallyEnded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgID = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	octx := orgctx.With(ctx, orgctx.Org{ID: orgID})

	agentID := fmt.Sprintf("consent-agent-%d", time.Now().UnixNano())
	const token = "an-agent-token"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO enrolled_agents (agent_id, device_id, platform, status, compliance_status, auth_token_hash)
		 VALUES ($1, $1, 'linux', 'active', 'compliant', $2)`,
		agentID, sha256Hex(token)); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	var sessionID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO remote_support_sessions (agent_id, status, mode, consent_status, org_id)
		VALUES ($1, 'pending', 'interactive', 'pending', $2) RETURNING id::text`,
		agentID, orgID).Scan(&sessionID); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	h := &RemoteSupportHandler{logger: zap.NewNop(), db: db}

	deny := func() *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"decision": "deny"})
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost,
			"/agent/remote-support/sessions/"+sessionID+"/consent", bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request.Header.Set("X-Agent-ID", agentID)
		c.Request.Header.Set("X-Auth-Token", token)
		c.Request = c.Request.WithContext(octx)
		c.Params = gin.Params{{Key: "id", Value: sessionID}}
		h.HandleAgentConsent(c)
		return w
	}

	// The refusal lands: the session ends.
	if w := deny(); w.Code != http.StatusOK {
		t.Fatalf("a refusal the database accepted was answered %d: %s", w.Code, w.Body.String())
	}
	var status, consent string
	if err := db.Pool.QueryRow(octx,
		`SELECT status, consent_status FROM remote_support_sessions WHERE id = $1::uuid`, sessionID).
		Scan(&status, &consent); err != nil {
		t.Fatalf("read the session back: %v", err)
	}
	if status != "ended" || consent != "denied" {
		t.Fatalf("after a refusal the session is status=%q consent=%q, want ended/denied", status, consent)
	}

	// Now put the session back and make the write fail. This is the state the
	// old code answered 200 over.
	if _, err := db.Pool.Exec(octx, `
		UPDATE remote_support_sessions SET status='pending', consent_status='pending',
		       ended_at=NULL, end_reason=NULL WHERE id = $1::uuid`, sessionID); err != nil {
		t.Fatalf("reset the session: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		CREATE FUNCTION refuse_consent_write() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refusing the consent write'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_consent_write BEFORE UPDATE ON remote_support_sessions
		FOR EACH ROW EXECUTE FUNCTION refuse_consent_write();`); err != nil {
		t.Fatalf("install the failure: %v", err)
	}
	defer func() {
		_, _ = db.Pool.Exec(ctx, `DROP TRIGGER IF EXISTS refuse_consent_write ON remote_support_sessions`)
	}()

	w := deny()
	if w.Code == http.StatusOK {
		t.Errorf("a refusal the database refused was answered %d %s. The person at the device is shown a "+
			"confirmation and the session is still live.", w.Code, w.Body.String())
	}

	if err := db.Pool.QueryRow(octx,
		`SELECT status FROM remote_support_sessions WHERE id = $1::uuid`, sessionID).Scan(&status); err != nil {
		t.Fatalf("read the session back: %v", err)
	}
	if status == "ended" {
		t.Error("the failure injection did not take — the session ended anyway, so this test is not " +
			"exercising the path it claims")
	}
}
