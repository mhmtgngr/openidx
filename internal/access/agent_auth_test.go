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
)

// The posture endpoint decides network access, and it never checked a credential.
//
// POST /api/v1/access/agent/report is registered outside the JWT middleware
// (service.go:1068) because an agent has no tenant JWT. It took the agent id out
// of the request — JSON body first, X-Agent-ID header as a fallback — and wrote
// posture rows, moved enrolled_agents.compliance_score/compliance_status, and
// called applyPostureDeviceTrust, which with POSTURE_DEVICE_TRUST_GATE=enforce
// adds or removes the `device-trusted` Ziti role attribute: the Tier-2 gate for
// the remote/PAM and admin surfaces.
//
// So an unauthenticated HTTP request decided a device's network tier. A forged
// compliant report grants it; a forged critical failure takes it away from
// somebody else's laptop. Proven against the running service before the fix, on
// an agent id that had never been enrolled:
//
//	$ curl -X POST .../api/v1/access/agent/report -d '{"agent_id":"j4-forged-...",...}'
//	HTTP 202 {"compliance_score":1,"enforcement_actions":[...],"status":"accepted"}
//	# and the row was in agent_posture_results
//
// Both shipped agents send the credential — the Android one as X-Auth-Token,
// the Go one as `Authorization: Bearer` — and access-service.yaml has always
// documented a 401 for these two paths. Only the server never looked.
//
// The tests above this one drive the handlers with a nil database, where any
// non-empty token is accepted (the dev-mode behaviour the other agent surfaces
// have always had), so they prove only that an anonymous caller is refused.
// These drive it against a real enrolled_agents row, which is where the
// credential is actually compared.

func TestAgentReportRequiresTheAgentsOwnCredential(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE enrolled_agents (
			agent_id          VARCHAR(64) PRIMARY KEY,
			auth_token_hash   VARCHAR(128) NOT NULL,
			status            VARCHAR(20) NOT NULL DEFAULT 'active',
			platform          VARCHAR(32),
			compliance_status VARCHAR(20) NOT NULL DEFAULT 'unknown',
			compliance_score  DOUBLE PRECISION DEFAULT 0.0,
			last_report_at    TIMESTAMPTZ
		)`); err != nil {
		t.Fatalf("create enrolled_agents: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE agent_posture_results (
			agent_id           VARCHAR(64) NOT NULL,
			check_type         VARCHAR(64) NOT NULL,
			status             VARCHAR(20),
			score              DOUBLE PRECISION,
			severity           VARCHAR(20),
			details            JSONB,
			message            TEXT,
			reported_at        TIMESTAMPTZ,
			expires_at         TIMESTAMPTZ,
			enforced           BOOLEAN,
			enforcement_action VARCHAR(32)
		)`); err != nil {
		t.Fatalf("create agent_posture_results: %v", err)
	}

	const (
		theAgent      = "agent-with-a-credential"
		theToken      = "the-token-enrollment-issued"
		anotherAgent  = "agent-next-to-it"
		anotherToken  = "a-different-agents-token"
		forgedAgentID = "never-enrolled-anywhere"
	)
	for _, a := range []struct{ id, token string }{
		{theAgent, theToken}, {anotherAgent, anotherToken},
	} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO enrolled_agents (agent_id, auth_token_hash) VALUES ($1, $2)`,
			a.id, sha256Hex(a.token)); err != nil {
			t.Fatalf("seed %s: %v", a.id, err)
		}
	}

	gin.SetMode(gin.TestMode)
	handler := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	router := gin.New()
	router.POST("/agent/report", handler.HandleReport)
	router.GET("/agent/config", handler.HandleConfig)

	report := func(agentID string, headers map[string]string, bodyAgentID string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{
			"agent_id": bodyAgentID,
			"results": []map[string]any{{
				"check_type": "disk_encryption",
				"severity":   "critical",
				"result":     map[string]any{"status": "pass", "score": 1.0},
			}},
		})
		req := httptest.NewRequest(http.MethodPost, "/agent/report", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if agentID != "" {
			req.Header.Set("X-Agent-ID", agentID)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	countFor := func(agentID string) int {
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT count(*) FROM agent_posture_results WHERE agent_id = $1`, agentID).Scan(&n); err != nil {
			t.Fatalf("count rows for %s: %v", agentID, err)
		}
		return n
	}

	t.Run("no credential at all is refused", func(t *testing.T) {
		if w := report(theAgent, nil, theAgent); w.Code != http.StatusUnauthorized {
			t.Fatalf("answered %d: %s", w.Code, w.Body.String())
		}
		if n := countFor(theAgent); n != 0 {
			t.Errorf("a refused report wrote %d posture row(s)", n)
		}
	})

	t.Run("an agent id nobody enrolled is refused", func(t *testing.T) {
		w := report(forgedAgentID, map[string]string{"X-Auth-Token": "anything"}, forgedAgentID)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("answered %d for an agent that does not exist: %s", w.Code, w.Body.String())
		}
		if n := countFor(forgedAgentID); n != 0 {
			t.Errorf("posture was recorded for an agent that was never enrolled (%d row(s))", n)
		}
	})

	t.Run("the wrong token is refused", func(t *testing.T) {
		w := report(theAgent, map[string]string{"X-Auth-Token": "not-the-right-token"}, theAgent)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("answered %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("another agent's token is refused", func(t *testing.T) {
		w := report(theAgent, map[string]string{"X-Auth-Token": anotherToken}, theAgent)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("agent %s reported as %s using its own token: %d %s",
				anotherAgent, theAgent, w.Code, w.Body.String())
		}
	})

	t.Run("X-Auth-Token is accepted", func(t *testing.T) {
		w := report(theAgent, map[string]string{"X-Auth-Token": theToken}, theAgent)
		if w.Code != http.StatusAccepted {
			t.Fatalf("answered %d: %s", w.Code, w.Body.String())
		}
		if n := countFor(theAgent); n != 1 {
			t.Errorf("accepted report wrote %d posture rows, want 1", n)
		}
	})

	t.Run("Authorization Bearer is accepted, because the Go agent sends that", func(t *testing.T) {
		w := report(anotherAgent, map[string]string{"Authorization": "Bearer " + anotherToken}, anotherAgent)
		if w.Code != http.StatusAccepted {
			t.Fatalf("answered %d for the spelling agent/internal/transport/client.go:103 sends: %s",
				w.Code, w.Body.String())
		}
		if n := countFor(anotherAgent); n != 1 {
			t.Errorf("accepted report wrote %d posture rows, want 1", n)
		}
	})

	t.Run("a body naming a different agent is refused", func(t *testing.T) {
		// The credential is theAgent's and it is valid. The body claims the
		// report belongs to anotherAgent. Before the id came from the
		// credential, this is how an enrolled agent would have written posture
		// against any other agent in the fleet.
		w := report(theAgent, map[string]string{"X-Auth-Token": theToken}, anotherAgent)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("answered %d: %s", w.Code, w.Body.String())
		}
		if n := countFor(anotherAgent); n != 1 {
			t.Errorf("%s now has %d posture rows; the refused report added one", anotherAgent, n)
		}
	})

	t.Run("config is refused without a credential and served with one", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/agent/config?agent_id="+theAgent, nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("the agent_id query parameter alone was enough to read an agent's "+
				"configuration: %d %s", w.Code, w.Body.String())
		}

		w = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/agent/config", nil)
		req.Header.Set("X-Agent-ID", theAgent)
		req.Header.Set("X-Auth-Token", theToken)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("an enrolled agent could not read its own configuration: %d %s",
				w.Code, w.Body.String())
		}
	})
}
