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

// A device enrolled with a fleet token belongs to no one. The person who
// enrols it again from their own session claims it; a person who does not
// own a claimed device cannot take it over by re-enrolling it.
//
// Before this, re-enrolment rotated the credential and left
// enrolled_by_user_id as it was, so a token-enrolled machine stayed
// ownerless however its user enrolled it afterwards: it never appeared in
// their My Devices, and the posture bridge (which joins the agent to the
// enrolling user's Ziti identity) never found it, so device trust never
// reached the overlay. The handlers are driven through gin against the
// migrated schema; the OAuth caller is set by a stand-in for the JWT
// middleware, switchable between two users.
func TestReenrolmentClaimsAnOwnerlessDeviceAndOnlyThat(t *testing.T) {
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

	var orgID, alice, bob string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('claim-org', 'claim-org') RETURNING id::text`).
		Scan(&orgID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	for name, id := range map[string]*string{"alice": &alice, "bob": &bob} {
		if err := db.Pool.QueryRow(ctx,
			`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2, $3, true)
			 RETURNING id::text`, orgID, "claim-"+name, "claim-"+name+"@example.test").Scan(id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, description, expires_at, reusable, revoked, org_id)
		VALUES ($1, 'test', NOW() + interval '1 hour', true, false, $2)`, sha256Hex("fleet-token"), orgID); err != nil {
		t.Fatalf("seed enrollment token: %v", err)
	}

	caller := alice
	agentH := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	router := gin.New()
	agentH.RegisterAgentPublicRoutes(router.Group("/api/v1/access"))
	admin := router.Group("/api/v1/access", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
		c.Set("user_id", caller)
		c.Set("scope", "openid offline_access "+enrollScope)
		c.Next()
	})
	agentH.RegisterAgentAdminRoutes(admin, nil)

	type enrolment struct {
		AgentID   string `json:"agent_id"`
		AuthToken string `json:"auth_token"`
	}
	send := func(path string, header map[string]string, fp string) *httptest.ResponseRecorder {
		t.Helper()
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(map[string]any{"hostname": "PC", "platform": "windows", "device_fingerprint": fp})
		req := httptest.NewRequest(http.MethodPost, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	byToken := func(fp string) *httptest.ResponseRecorder {
		return send("/api/v1/access/agent/enroll", map[string]string{"Authorization": "Bearer fleet-token"}, fp)
	}
	byOAuth := func(as, fp string) *httptest.ResponseRecorder {
		caller = as
		return send("/api/v1/access/agent/enroll/oauth", nil, fp)
	}
	enrolled := func(t *testing.T, w *httptest.ResponseRecorder) enrolment {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("enrolment answered %d, want 200: %s", w.Code, w.Body.String())
		}
		var e enrolment
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.AgentID == "" {
			t.Fatalf("enrolment answer has no agent (%v): %s", err, w.Body.String())
		}
		return e
	}
	type row struct{ owner, hash string }
	read := func(t *testing.T, agentID string) row {
		t.Helper()
		var r row
		if err := db.Pool.QueryRow(ctx,
			`SELECT COALESCE(enrolled_by_user_id::text, ''), auth_token_hash FROM enrolled_agents WHERE agent_id = $1`,
			agentID).Scan(&r.owner, &r.hash); err != nil {
			t.Fatalf("read %s: %v", agentID, err)
		}
		return r
	}

	t.Run("a fleet token names no one; the person who enrols it again claims it", func(t *testing.T) {
		const fp = "win:claim-ownerless"
		first := enrolled(t, byToken(fp))
		if got := read(t, first.AgentID).owner; got != "" {
			t.Fatalf("a token-enrolled device has owner %q, want none", got)
		}
		again := enrolled(t, byOAuth(alice, fp))
		if again.AgentID != first.AgentID {
			t.Fatalf("re-enrolment changed the agent: %q -> %q", first.AgentID, again.AgentID)
		}
		if got := read(t, first.AgentID).owner; got != alice {
			t.Errorf("after alice re-enrolled it the owner is %q, want alice (%s)", got, alice)
		}
	})

	t.Run("another person cannot take a claimed device over", func(t *testing.T) {
		const fp = "win:claim-taken"
		first := enrolled(t, byOAuth(alice, fp))
		before := read(t, first.AgentID)

		w := byOAuth(bob, fp)
		if w.Code != http.StatusConflict {
			t.Fatalf("bob re-enrolling alice's device answered %d, want 409: %s", w.Code, w.Body.String())
		}
		var body map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["code"] != "agent_owned_by_another_user" {
			t.Errorf("refusal code %q, want agent_owned_by_another_user", body["code"])
		}
		if _, leaked := body["auth_token"]; leaked {
			t.Errorf("the refusal carries a credential: %s", w.Body.String())
		}
		if after := read(t, first.AgentID); after != before {
			t.Errorf("the refused enrolment changed alice's device: %+v -> %+v", before, after)
		}
		var denied int
		if err := db.Pool.QueryRow(ctx, `
			SELECT count(*) FROM unified_audit_events
			 WHERE event_type = 'agent.enroll_denied' AND org_id::text = $1 AND details->>'agent_id' = $2`,
			orgID, first.AgentID).Scan(&denied); err != nil {
			t.Fatalf("read the audit trail: %v", err)
		}
		if denied != 1 {
			t.Errorf("found %d agent.enroll_denied records, want 1", denied)
		}
	})

	t.Run("the owner re-enrols their own device; a fleet token re-enrols it and the owner stays", func(t *testing.T) {
		const fp = "win:claim-own"
		first := enrolled(t, byOAuth(alice, fp))
		enrolled(t, byOAuth(alice, fp))
		enrolled(t, byToken(fp))
		if got := read(t, first.AgentID).owner; got != alice {
			t.Errorf("owner after re-enrolments is %q, want alice (%s)", got, alice)
		}
	})

	t.Run("the fleet names each device's owner and flags an unclaimed or refused one", func(t *testing.T) {
		unclaimed := enrolled(t, byToken("win:fleet-unclaimed"))
		owned := enrolled(t, byOAuth(alice, "win:fleet-owned"))
		if _, err := db.Pool.Exec(ctx,
			`UPDATE enrolled_agents SET auth_fail_count = 4, auth_failed_at = NOW() WHERE agent_id = $1`,
			unclaimed.AgentID); err != nil {
			t.Fatalf("mark refused: %v", err)
		}

		caller = alice
		req := httptest.NewRequest(http.MethodGet, "/api/v1/access/agents", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("list answered %d: %s", w.Code, w.Body.String())
		}
		var list []struct {
			AgentID           string `json:"agent_id"`
			OwnerUserID       string `json:"owner_user_id"`
			OwnerUsername     string `json:"owner_username"`
			CredentialRefused bool   `json:"credential_refused"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
			t.Fatalf("list is not JSON: %v", err)
		}
		seen := 0
		for _, a := range list {
			switch a.AgentID {
			case unclaimed.AgentID:
				seen++
				if a.OwnerUserID != "" || a.OwnerUsername != "" {
					t.Errorf("a token-enrolled device lists owner %q/%q, want none", a.OwnerUserID, a.OwnerUsername)
				}
				if !a.CredentialRefused {
					t.Errorf("a device refused 4 times running is not flagged credential_refused")
				}
			case owned.AgentID:
				seen++
				if a.OwnerUserID != alice || a.OwnerUsername != "claim-alice" {
					t.Errorf("owned device lists owner %q/%q, want %s/claim-alice", a.OwnerUserID, a.OwnerUsername, alice)
				}
				if a.CredentialRefused {
					t.Errorf("a healthy device is flagged credential_refused")
				}
			}
		}
		if seen != 2 {
			t.Fatalf("found %d of the 2 devices in the fleet list", seen)
		}
	})
}
