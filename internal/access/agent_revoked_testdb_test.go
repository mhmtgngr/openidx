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

// A revoked device kept working.
//
// Revoking an agent, from the fleet console or from a user's own device list,
// sets enrolled_agents.status to 'revoked' and leaves auth_token_hash alone.
// The shared credential check compared the hash and never read the status, so
// the revoked device's token went on passing on every agent route: it could
// file posture reports, which move its compliance verdict and its Ziti tier,
// answer remote-support consent, open the remote-support socket and post
// Windows-app discovery. Only /agent/config refused it, with its own check.
//
// These tests drive the real handlers through gin against the migrated schema.
// A revoked agent holding its correct token is refused with 403 agent_revoked
// on every route, which is what the Go agent reads as revoked. A wrong token is
// still 401, whatever the agent's status. An active agent is let through, and
// a suspended one still gets its config, because that config is what tells it
// to block, and its reports are how it recovers.
func TestARevokedAgentIsRefusedOnEveryAgentRoute(t *testing.T) {
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

	// The agents live in a tenant that is not the default one, so the audit
	// check below can tell the agent's tenant from the fallback.
	var orgID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('revoked-agent-org', 'revoked-agent-org') RETURNING id::text`).
		Scan(&orgID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	const (
		activeAgent    = "agent-still-active"
		activeToken    = "token-of-the-active-agent"
		revokedAgent   = "agent-revoked-by-admin"
		revokedToken   = "token-of-the-revoked-agent"
		suspendedAgent = "agent-suspended"
		suspendedToken = "token-of-the-suspended-agent"
	)
	for _, a := range []struct{ id, token, status string }{
		{activeAgent, activeToken, "active"},
		{revokedAgent, revokedToken, "revoked"},
		{suspendedAgent, suspendedToken, "suspended"},
	} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO enrolled_agents (agent_id, device_id, platform, status, compliance_status, auth_token_hash, org_id)
			 VALUES ($1, $1, 'linux', $2, 'unknown', $3, $4)`,
			a.id, a.status, sha256Hex(a.token), orgID); err != nil {
			t.Fatalf("seed %s: %v", a.id, err)
		}
	}

	sessionFor := func(agentID string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO remote_support_sessions (agent_id, status, mode, consent_status, org_id)
			VALUES ($1, 'pending', 'interactive', 'pending', $2) RETURNING id::text`,
			agentID, orgID).Scan(&id); err != nil {
			t.Fatalf("seed remote support session for %s: %v", agentID, err)
		}
		return id
	}
	activeSession := sessionFor(activeAgent)
	revokedSession := sessionFor(revokedAgent)

	agentH := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	remoteH := NewRemoteSupportHandler(zap.NewNop(), db, agentH)
	svc := &Service{db: db, logger: zap.NewNop(), agentHandler: agentH}

	router := gin.New()
	public := router.Group("/api/v1/access")
	agentH.RegisterAgentPublicRoutes(public)
	public.POST("/agent/windows-apps/report", svc.handleAgentWindowsAppReport)
	// The remote-support handlers find the session in the tenant on the
	// request, which in the service the tenant resolver puts there. This group
	// stands in for it, as the consent test does.
	remote := router.Group("/api/v1/access", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
		c.Next()
	})
	remoteH.RegisterRemoteSupportPublicRoutes(remote)

	call := func(method, path, agentID, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Agent-ID", agentID)
		req.Header.Set("X-Auth-Token", token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	report := func(agentID, token string) *httptest.ResponseRecorder {
		return call(http.MethodPost, "/api/v1/access/agent/report", agentID, token,
			`{"results":[{"check_type":"firewall","severity":"low","result":{"status":"pass","score":1}}]}`)
	}
	config := func(agentID, token string) *httptest.ResponseRecorder {
		return call(http.MethodGet, "/api/v1/access/agent/config", agentID, token, "")
	}
	consent := func(sessionID, agentID, token string) *httptest.ResponseRecorder {
		return call(http.MethodPost, "/api/v1/access/agent/remote-support/sessions/"+sessionID+"/consent",
			agentID, token, `{"decision":"grant"}`)
	}
	postureRows := func(agentID string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT count(*) FROM agent_posture_results WHERE agent_id = $1`, agentID).Scan(&n); err != nil {
			t.Fatalf("count posture rows for %s: %v", agentID, err)
		}
		return n
	}
	assertRevoked := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusForbidden {
			t.Fatalf("answered %d, want 403: %s", w.Code, w.Body.String())
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("the refusal is not JSON: %s", w.Body.String())
		}
		if body["code"] != "agent_revoked" || body["error"] != "agent revoked" {
			t.Errorf("refusal body = %v, want error %q and code %q", body, "agent revoked", "agent_revoked")
		}
	}

	t.Run("an active agent's report is accepted", func(t *testing.T) {
		if w := report(activeAgent, activeToken); w.Code != http.StatusAccepted {
			t.Fatalf("answered %d: %s", w.Code, w.Body.String())
		}
		if n := postureRows(activeAgent); n != 1 {
			t.Errorf("the accepted report wrote %d posture rows, want 1", n)
		}
	})

	t.Run("a revoked agent's report is refused and writes nothing", func(t *testing.T) {
		assertRevoked(t, report(revokedAgent, revokedToken))
		if n := postureRows(revokedAgent); n != 0 {
			t.Errorf("a revoked device recorded %d posture row(s)", n)
		}
		var n int
		if err := db.Pool.QueryRow(ctx, `
			SELECT count(*) FROM unified_audit_events
			 WHERE event_type = 'agent.auth_failed' AND org_id::text = $1
			   AND details->>'agent_id' = $2 AND details->>'detail' = 'agent revoked'`,
			orgID, revokedAgent).Scan(&n); err != nil {
			t.Fatalf("read the audit trail: %v", err)
		}
		if n == 0 {
			t.Error("the refusal was not audited in the agent's own tenant")
		}
	})

	t.Run("a revoked agent's config is refused with 403, which the Go agent reads as revoked", func(t *testing.T) {
		assertRevoked(t, config(revokedAgent, revokedToken))
	})

	t.Run("a revoked agent cannot answer remote-support consent or open the socket", func(t *testing.T) {
		assertRevoked(t, consent(revokedSession, revokedAgent, revokedToken))
		var consentStatus string
		if err := db.Pool.QueryRow(ctx,
			`SELECT consent_status FROM remote_support_sessions WHERE id = $1::uuid`, revokedSession).
			Scan(&consentStatus); err != nil {
			t.Fatalf("read the session back: %v", err)
		}
		if consentStatus != "pending" {
			t.Errorf("a revoked device moved consent to %q", consentStatus)
		}
		assertRevoked(t, call(http.MethodGet,
			"/api/v1/access/agent/remote-support/sessions/"+revokedSession+"/ws", revokedAgent, revokedToken, ""))
	})

	t.Run("an active agent can still answer remote-support consent", func(t *testing.T) {
		if w := consent(activeSession, activeAgent, activeToken); w.Code != http.StatusOK {
			t.Fatalf("answered %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("a revoked agent cannot post Windows-app discovery", func(t *testing.T) {
		assertRevoked(t, call(http.MethodPost, "/api/v1/access/agent/windows-apps/report",
			revokedAgent, revokedToken, `{"apps":[]}`))
		// The active agent gets past authentication and is told it is not
		// linked to a host, which shows the 403 above is the status at work.
		if w := call(http.MethodPost, "/api/v1/access/agent/windows-apps/report",
			activeAgent, activeToken, `{"apps":[]}`); w.Code != http.StatusPreconditionFailed {
			t.Errorf("an active, unlinked agent answered %d, want 412: %s", w.Code, w.Body.String())
		}
	})

	t.Run("a wrong token is 401, and does not reveal that an agent was revoked", func(t *testing.T) {
		for _, agentID := range []string{activeAgent, revokedAgent} {
			if w := report(agentID, "not-the-token"); w.Code != http.StatusUnauthorized {
				t.Errorf("report for %s with a wrong token answered %d: %s", agentID, w.Code, w.Body.String())
			}
			if w := config(agentID, "not-the-token"); w.Code != http.StatusUnauthorized {
				t.Errorf("config for %s with a wrong token answered %d: %s", agentID, w.Code, w.Body.String())
			}
		}
		if w := consent(revokedSession, revokedAgent, "not-the-token"); w.Code != http.StatusUnauthorized {
			t.Errorf("consent with a wrong token answered %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("a suspended agent still gets its config and can still report", func(t *testing.T) {
		w := config(suspendedAgent, suspendedToken)
		if w.Code != http.StatusOK {
			t.Fatalf("config answered %d: %s", w.Code, w.Body.String())
		}
		var cfg agentConfigResponse
		if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
			t.Fatalf("config is not a config: %s", w.Body.String())
		}
		if cfg.EnforcementPolicy != "block" || cfg.EnrollmentStatus != "suspended" {
			t.Errorf("suspended config = policy %q status %q, want block/suspended",
				cfg.EnforcementPolicy, cfg.EnrollmentStatus)
		}
		if w := report(suspendedAgent, suspendedToken); w.Code != http.StatusAccepted {
			t.Errorf("a suspended agent's report answered %d: %s", w.Code, w.Body.String())
		}
	})
}
