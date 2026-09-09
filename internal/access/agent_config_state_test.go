package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// A device could not tell "enrolled and waiting for an admin" from "enrolled
// and working".
//
// GET /agent/config has always branched on the agent's status to decide which
// checks to send — pending gets one, suspended gets none, active gets the real
// list — and never told the device which of those it was. So the client had no
// way to render the design's first rule, that a device earns access by proving
// things and its user always sees which of those it has. A client that cannot
// show the difference makes controlled access read as broken.
//
// These cases pin the two fields that carry it, on every branch that answers.

var agentStateSchema = []string{
	`CREATE TABLE IF NOT EXISTS known_devices (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID,
		fingerprint VARCHAR(128), name VARCHAR(255), device_type VARCHAR(50),
		trusted BOOLEAN DEFAULT false, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
	`CREATE TABLE IF NOT EXISTS enrolled_agents (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(), agent_id VARCHAR(64) UNIQUE,
		auth_token_hash VARCHAR(128), status VARCHAR(20) DEFAULT 'pending',
		platform VARCHAR(32), known_device_id UUID, enrolled_by_user_id UUID)`,
	`CREATE TABLE IF NOT EXISTS posture_checks (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(), check_type VARCHAR(64),
		parameters JSONB, severity VARCHAR(10), enabled BOOLEAN DEFAULT true,
		platforms JSONB)`,
}

func TestAgentConfig_TellsTheDeviceItsOwnState(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: devOrg})
	for _, stmt := range agentStateSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}

	const trustedKD = "44444444-0000-0000-0000-0000000000b1"
	const untrustedKD = "44444444-0000-0000-0000-0000000000b2"
	tokenHash := sha256Hex("agent-secret")
	for _, seed := range []string{
		`INSERT INTO posture_checks (check_type, severity, enabled) VALUES ('os_version','low',true)`,
		`INSERT INTO known_devices (id, org_id, trusted) VALUES ('` + trustedKD + `','` + devOrg + `',true)`,
		`INSERT INTO known_devices (id, org_id, trusted) VALUES ('` + untrustedKD + `','` + devOrg + `',false)`,
		`INSERT INTO enrolled_agents (agent_id, auth_token_hash, status, known_device_id) VALUES ('agent-waiting','` + tokenHash + `','pending','` + untrustedKD + `')`,
		`INSERT INTO enrolled_agents (agent_id, auth_token_hash, status, known_device_id) VALUES ('agent-tier1','` + tokenHash + `','active','` + untrustedKD + `')`,
		`INSERT INTO enrolled_agents (agent_id, auth_token_hash, status, known_device_id) VALUES ('agent-tier2','` + tokenHash + `','active','` + trustedKD + `')`,
		`INSERT INTO enrolled_agents (agent_id, auth_token_hash, status) VALUES ('agent-unlinked','` + tokenHash + `','active')`,
		`INSERT INTO enrolled_agents (agent_id, auth_token_hash, status, known_device_id) VALUES ('agent-held','` + tokenHash + `','suspended','` + untrustedKD + `')`,
		`INSERT INTO enrolled_agents (agent_id, auth_token_hash, status) VALUES ('agent-gone','` + tokenHash + `','revoked')`,
	} {
		if _, err := db.Pool.Exec(ctx, seed); err != nil {
			t.Fatalf("seed: %v\n%s", err, seed)
		}
	}

	gin.SetMode(gin.TestMode)
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)

	ask := func(t *testing.T, agentID string) (int, agentConfigResponse) {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/agent/config", nil).WithContext(ctx)
		req.Header.Set("X-Agent-ID", agentID)
		req.Header.Set("X-Auth-Token", "agent-secret")
		c.Request = req

		h.HandleConfig(c)

		var cfg agentConfigResponse
		if w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
				t.Fatalf("response is not a config (%d): %s", w.Code, w.Body.String())
			}
		}
		return w.Code, cfg
	}

	for _, tc := range []struct {
		name        string
		agentID     string
		wantCode    int
		wantStatus  string
		wantTrusted bool
		why         string
	}{
		{"waiting for an admin", "agent-waiting", http.StatusOK, "pending", false,
			"the state the client has to be able to show, and could not"},
		{"enrolled, Tier 1", "agent-tier1", http.StatusOK, "active", false,
			"working, but the device has not earned trust"},
		{"trusted, Tier 2", "agent-tier2", http.StatusOK, "active", true,
			"the linked known_devices row is what the overlay's #device-trusted follows"},
		{"active with no linked device", "agent-unlinked", http.StatusOK, "active", false,
			"token-enrolled and legacy agents link no known device; absent is untrusted, not unknown"},
		{"held", "agent-held", http.StatusOK, "suspended", false, "no checks, and it says why"},
		{"revoked", "agent-gone", http.StatusForbidden, "", false,
			"a revoked agent is refused outright, as before"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, cfg := ask(t, tc.agentID)
			if code != tc.wantCode {
				t.Fatalf("status %d, want %d", code, tc.wantCode)
			}
			if tc.wantCode != http.StatusOK {
				return
			}
			if cfg.EnrollmentStatus != tc.wantStatus {
				t.Errorf("enrollment_status = %q, want %q — %s", cfg.EnrollmentStatus, tc.wantStatus, tc.why)
			}
			if cfg.DeviceTrusted != tc.wantTrusted {
				t.Errorf("device_trusted = %v, want %v — %s", cfg.DeviceTrusted, tc.wantTrusted, tc.why)
			}
		})
	}
}

// TestAgentConfig_StateNeedsTheAgentsOwnCredential keeps the new fields behind
// the same door as the rest of the config: a device's approval state and trust
// are not something an unauthenticated caller may enumerate.
func TestAgentConfig_StateNeedsTheAgentsOwnCredential(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: devOrg})
	for _, stmt := range agentStateSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO enrolled_agents (agent_id, auth_token_hash, status) VALUES ('agent-x',$1,'active')`,
		sha256Hex("the-real-secret")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	gin.SetMode(gin.TestMode)
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)

	for _, tc := range []struct{ name, agentID, token string }{
		{"no credentials", "", ""},
		{"an id with no token", "agent-x", ""},
		{"the wrong token", "agent-x", "guessed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req := httptest.NewRequest(http.MethodGet, "/agent/config", nil).WithContext(ctx)
			if tc.agentID != "" {
				req.Header.Set("X-Agent-ID", tc.agentID)
			}
			if tc.token != "" {
				req.Header.Set("X-Auth-Token", tc.token)
			}
			c.Request = req

			h.HandleConfig(c)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401 (body %s)", w.Code, w.Body.String())
			}
		})
	}
}
