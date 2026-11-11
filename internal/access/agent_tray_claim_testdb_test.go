package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// claimHarness drives POST /agent/claim against the migrated schema. The
// person's org, id and session stand in for the JWT middleware.
type claimHarness struct {
	t                 *testing.T
	router            *gin.Engine
	orgID, otherOrgID string
	alice, bob, eve   string // eve is a user of the other organization
	callerOrg, caller string
	callerSession     string
	ctx               context.Context
	h                 *AgentAPIHandler
}

func newClaimHarness(t *testing.T) (*claimHarness, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil
	}
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		cleanup()
		t.Fatalf("migrate to latest: %v", err)
	}
	ch := &claimHarness{t: t, ctx: ctx}
	slug := "claim-" + uuid.NewString()[:8]
	for _, o := range []struct {
		dst  *string
		slug string
	}{{&ch.orgID, slug}, {&ch.otherOrgID, slug + "-x"}} {
		if err := db.Pool.QueryRow(ctx, `INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
			o.slug).Scan(o.dst); err != nil {
			t.Fatalf("seed org: %v", err)
		}
	}
	for _, u := range []struct {
		dst  *string
		org  string
		name string
		src  string
	}{{&ch.alice, ch.orgID, "alice", "ldap"}, {&ch.bob, ch.orgID, "bob", "local"}, {&ch.eve, ch.otherOrgID, "eve", "local"}} {
		if err := db.Pool.QueryRow(ctx,
			`INSERT INTO users (org_id, username, email, enabled, source) VALUES ($1::uuid, $2, $3, true, $4) RETURNING id::text`,
			u.org, slug+"-"+u.name, slug+"-"+u.name+"@example.test", u.src).Scan(u.dst); err != nil {
			t.Fatalf("seed user %s: %v", u.name, err)
		}
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, description, expires_at, reusable, revoked, org_id)
		VALUES ($1, 'fleet', NOW() + interval '1 hour', true, false, $2)`, sha256Hex(slug+"-fleet"), ch.orgID); err != nil {
		t.Fatalf("seed fleet token: %v", err)
	}
	ch.h = NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	ch.router = gin.New()
	ch.h.RegisterAgentPublicRoutes(ch.router.Group("/api/v1/access"))
	authed := ch.router.Group("/api/v1/access", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: ch.callerOrg}))
		c.Set("user_id", ch.caller)
		c.Set("session_id", ch.callerSession)
		c.Next()
	})
	ch.h.RegisterAgentAdminRoutes(authed, nil, nil, nil)
	return ch, cleanup
}

type fleetDevice struct {
	AgentID   string `json:"agent_id"`
	AuthToken string `json:"auth_token"`
}

func (ch *claimHarness) enrolByFleetToken(fp string) fleetDevice {
	ch.t.Helper()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(map[string]any{"hostname": "PC-" + fp, "platform": "windows", "device_fingerprint": fp})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/agent/enroll", &buf)
	req.Header.Set("Content-Type", "application/json")
	var slug string
	_ = ch.h.db.Pool.QueryRow(ch.ctx, `SELECT slug FROM organizations WHERE id = $1`, ch.orgID).Scan(&slug)
	req.Header.Set("Authorization", "Bearer "+slug+"-fleet")
	w := httptest.NewRecorder()
	ch.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		ch.t.Fatalf("fleet enrolment answered %d: %s", w.Code, w.Body.String())
	}
	var d fleetDevice
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || d.AgentID == "" {
		ch.t.Fatalf("fleet enrolment has no agent: %s", w.Body.String())
	}
	return d
}

func (ch *claimHarness) claim(d fleetDevice, org, user, session string) *httptest.ResponseRecorder {
	ch.t.Helper()
	ch.callerOrg, ch.caller, ch.callerSession = org, user, session
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/agent/claim", nil)
	req.Header.Set("X-Agent-ID", d.AgentID)
	req.Header.Set("X-Auth-Token", d.AuthToken)
	w := httptest.NewRecorder()
	ch.router.ServeHTTP(w, req)
	return w
}

func (ch *claimHarness) owner(agentID string) string {
	ch.t.Helper()
	var owner string
	if err := ch.h.db.Pool.QueryRow(ch.ctx,
		`SELECT COALESCE(enrolled_by_user_id::text,'') FROM enrolled_agents WHERE agent_id = $1`, agentID).Scan(&owner); err != nil {
		ch.t.Fatalf("read owner: %v", err)
	}
	return owner
}

func (ch *claimHarness) audits(event, agentID string) int {
	ch.t.Helper()
	var n int
	_ = ch.h.db.Pool.QueryRow(ch.ctx, `SELECT count(*) FROM unified_audit_events
		WHERE event_type = $1 AND details->>'agent_id' = $2`, event, agentID).Scan(&n)
	return n
}

func TestTrayLoginClaimsUnclaimedFleetDevice(t *testing.T) {
	ch, cleanup := newClaimHarness(t)
	if ch == nil {
		return
	}
	defer cleanup()
	d := ch.enrolByFleetToken("win:tray-claim")
	if got := ch.owner(d.AgentID); got != "" {
		t.Fatalf("a fleet-enrolled device has owner %q, want none", got)
	}
	w := ch.claim(d, ch.orgID, ch.alice, "")
	if w.Code != http.StatusOK {
		t.Fatalf("claim answered %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := ch.owner(d.AgentID); got != ch.alice {
		t.Errorf("owner after claim is %q, want alice (%s)", got, ch.alice)
	}
	var linked string
	_ = ch.h.db.Pool.QueryRow(ch.ctx, `SELECT COALESCE(known_device_id::text,'') FROM enrolled_agents WHERE agent_id = $1`,
		d.AgentID).Scan(&linked)
	if linked == "" {
		t.Error("the claimed device is not linked to a known_devices row")
	}
	if n := ch.audits("agent.claimed", d.AgentID); n != 1 {
		t.Errorf("found %d agent.claimed records, want 1", n)
	}
	// Signing in again is idempotent and writes no second claim.
	if w := ch.claim(d, ch.orgID, ch.alice, ""); w.Code != http.StatusOK {
		t.Errorf("a second sign-in by the owner answered %d: %s", w.Code, w.Body.String())
	}
	if n := ch.audits("agent.claimed", d.AgentID); n != 1 {
		t.Errorf("after a second sign-in found %d agent.claimed records, want 1", n)
	}
	// Without the device's own credential there is no claim.
	bad := d
	bad.AuthToken = "wrong"
	if w := ch.claim(bad, ch.orgID, ch.bob, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("a claim with a wrong device credential answered %d, want 401", w.Code)
	}
}

func TestClaimRefusesOwnedByAnother(t *testing.T) {
	ch, cleanup := newClaimHarness(t)
	if ch == nil {
		return
	}
	defer cleanup()
	d := ch.enrolByFleetToken("win:owned")
	if w := ch.claim(d, ch.orgID, ch.alice, ""); w.Code != http.StatusOK {
		t.Fatalf("alice's claim answered %d: %s", w.Code, w.Body.String())
	}
	w := ch.claim(d, ch.orgID, ch.bob, "")
	if w.Code != http.StatusConflict {
		t.Fatalf("bob claiming alice's device answered %d, want 409: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["code"] != "agent_owned_by_another_user" {
		t.Errorf("refusal code %v, want agent_owned_by_another_user", body["code"])
	}
	if got := ch.owner(d.AgentID); got != ch.alice {
		t.Errorf("owner after bob's refused claim is %q, want alice", got)
	}
	if n := ch.audits("agent.claim_denied", d.AgentID); n != 1 {
		t.Errorf("found %d agent.claim_denied records, want 1", n)
	}
}

func TestClaimRefusesCrossOrgUserToken(t *testing.T) {
	ch, cleanup := newClaimHarness(t)
	if ch == nil {
		return
	}
	defer cleanup()
	d := ch.enrolByFleetToken("win:cross-org")
	w := ch.claim(d, ch.otherOrgID, ch.eve, "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("a user of another organization claiming answered %d, want 403: %s", w.Code, w.Body.String())
	}
	if got := ch.owner(d.AgentID); got != "" {
		t.Errorf("owner after a cross-org claim is %q, want none", got)
	}
}

func TestClaimBindsRefreshFamily(t *testing.T) {
	ch, cleanup := newClaimHarness(t)
	if ch == nil {
		return
	}
	defer cleanup()
	d := ch.enrolByFleetToken("win:bind")
	session := uuid.NewString()
	other := uuid.NewString()
	for _, q := range []struct{ tok, sess string }{{"rt-tray-" + session, session}, {"rt-other-" + other, other}} {
		if _, err := ch.h.db.Pool.Exec(ch.ctx, `
			INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, expires_at)
			VALUES ($1, 'openidx-desktop', $2, $3::uuid, $4, NOW() + interval '1 day')`,
			q.tok, ch.alice, q.sess, ch.orgID); err != nil {
			t.Fatalf("seed refresh token: %v", err)
		}
	}
	if w := ch.claim(d, ch.orgID, ch.alice, session); w.Code != http.StatusOK {
		t.Fatalf("claim answered %d: %s", w.Code, w.Body.String())
	}
	bound := func(tok string) string {
		var a string
		_ = ch.h.db.Pool.QueryRow(ch.ctx, `SELECT COALESCE(agent_id,'') FROM oauth_refresh_tokens WHERE token = $1`, tok).Scan(&a)
		return a
	}
	if got := bound("rt-tray-" + session); got != d.AgentID {
		t.Errorf("the tray session's refresh token is bound to %q, want %q", got, d.AgentID)
	}
	if got := bound("rt-other-" + other); got != "" {
		t.Errorf("another session's refresh token was bound to %q", got)
	}
}

// claim_mode logged_on_user: the report's session user claims an ownerless
// device only when the organization opted in and the name is a
// directory-sourced user; a local account never does.
func TestLoggedOnUserClaimsOnlyDirectoryUsers(t *testing.T) {
	ch, cleanup := newClaimHarness(t)
	if ch == nil {
		return
	}
	defer cleanup()
	var aliceEmail, bobEmail string
	_ = ch.h.db.Pool.QueryRow(ch.ctx, `SELECT email FROM users WHERE id = $1`, ch.alice).Scan(&aliceEmail)
	_ = ch.h.db.Pool.QueryRow(ch.ctx, `SELECT email FROM users WHERE id = $1`, ch.bob).Scan(&bobEmail)
	report := func(d fleetDevice, user string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"agent_id": d.AgentID, "results": []any{}, "logged_on_user": user})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/access/agent/report", bytes.NewReader(body))
		req.Header.Set("X-Agent-ID", d.AgentID)
		req.Header.Set("Authorization", "Bearer "+d.AuthToken)
		w := httptest.NewRecorder()
		ch.router.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("report answered %d: %s", w.Code, w.Body.String())
		}
	}
	d := ch.enrolByFleetToken("win:logon")
	report(d, aliceEmail)
	if got := ch.owner(d.AgentID); got != "" {
		t.Fatalf("under claim_mode login a report claimed the device for %q", got)
	}
	if _, err := ch.h.db.Pool.Exec(ch.ctx,
		`INSERT INTO org_agent_settings (org_id, claim_mode) VALUES ($1, 'logged_on_user')`, ch.orgID); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	report(d, bobEmail) // local account
	if got := ch.owner(d.AgentID); got != "" {
		t.Fatalf("a local account claimed the device (%q)", got)
	}
	report(d, "CORP\\"+aliceEmail)
	if got := ch.owner(d.AgentID); got != ch.alice {
		t.Errorf("owner after alice's logon is %q, want alice", got)
	}
}
