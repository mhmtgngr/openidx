package access

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE CONSOLE'S OPERATOR PAGES, THROUGH THE ROUTES BEHIND THEM.
//
// Remote Support, Agent Fleet, Devices, Users, the Ops Cockpit and Network
// Topology are operator pages in the console. Every route below backs one of
// them, and each is driven through RegisterRoutes:
//
//   - a plain user, an auditor and a compliance_reader are refused with 403,
//     and nothing the writes aimed at changes;
//   - an operator -- the lowest role the console shows these pages to -- gets
//     through, the writes land and the reads return the organization's data;
//   - an admin gets through as well.
func TestOperatorPagesNeedTheOperatorTier(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	e := f.serveWith(t, f.db, &config.Config{Environment: "production", RecordingsStoragePath: t.TempDir()})

	pending := f.seedAgent(t, f.orgA, "pending", "pending")
	active := f.seedAgent(t, f.orgA, "active", "active")
	toRevoke := f.seedAgent(t, f.orgA, "revoke", "active")
	toStart := f.seedAgent(t, f.orgA, "start", "active")
	session := f.seedRemoteSession(t, f.orgA, active)
	var token, identity string
	if err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, description, expires_at, org_id)
		VALUES ($1, 'seeded', NOW() + INTERVAL '1 day', $2::uuid) RETURNING id::text`,
		"hash-"+f.suffix, f.orgA).Scan(&token); err != nil {
		t.Fatalf("seed enrollment token: %v", err)
	}
	if err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO ziti_identities (ziti_id, name, user_id, org_id)
		VALUES ($1, $2, $3::uuid, $4::uuid) RETURNING id::text`,
		"zid-"+f.suffix, "identity-"+f.suffix, f.userA, f.orgA).Scan(&identity); err != nil {
		t.Fatalf("seed ziti identity: %v", err)
	}
	fingerprint := "fp-" + f.suffix
	if _, err := f.db.Pool.Exec(f.ctx, `
		INSERT INTO known_devices (user_id, fingerprint, name, org_id)
		VALUES ($1::uuid, $2, 'laptop', $3::uuid)`, f.userA, fingerprint, f.orgA); err != nil {
		t.Fatalf("seed known device: %v", err)
	}

	rs := "/api/v1/access/remote-support/sessions"
	routes := []struct{ method, path, body string }{
		// Remote Support.
		{http.MethodGet, rs, ""},
		{http.MethodPost, rs, `{"agent_id":"` + toStart + `","mode":"view"}`},
		{http.MethodGet, rs + "/" + session, ""},
		{http.MethodPost, rs + "/" + session + "/end", `{"reason":"tier test"}`},
		{http.MethodGet, rs + "/" + session + "/ws", ""},
		{http.MethodPost, rs + "/" + session + "/recording/chunk", "recorded-" + f.suffix},
		{http.MethodPost, rs + "/" + session + "/recording/finalize", ""},
		{http.MethodGet, rs + "/" + session + "/recording", ""},
		// Agent Fleet.
		{http.MethodPost, "/api/v1/access/agent/tokens", `{"description":"minted-` + f.suffix + `"}`},
		{http.MethodGet, "/api/v1/access/agent/tokens", ""},
		{http.MethodDelete, "/api/v1/access/agent/tokens/" + token, ""},
		{http.MethodGet, "/api/v1/access/agents", ""},
		{http.MethodGet, "/api/v1/access/agents/" + active + "/posture", ""},
		{http.MethodDelete, "/api/v1/access/agents/" + toRevoke, ""},
		{http.MethodPost, "/api/v1/access/agents/" + pending + "/approve", ""},
		{http.MethodPost, "/api/v1/access/agent/qr", `{"description":"qr-` + f.suffix + `"}`},
		// Users, Devices, the Ops Cockpit, Network Topology, and the Ziti
		// pages that show one identity at a time or the organization's part of
		// the fabric (ziti_org_scope_testdb_test.go drives what each one shows).
		{http.MethodGet, "/api/v1/access/ziti/identities", ""},
		{http.MethodGet, "/api/v1/access/ziti/sessions", ""},
		{http.MethodGet, "/api/v1/access/ziti/sync/status", ""},
		{http.MethodGet, "/api/v1/access/ziti/sync/unsynced", ""},
		{http.MethodGet, "/api/v1/access/ziti/sync/user-map", ""},
		{http.MethodGet, "/api/v1/access/ziti/posture/identities/" + identity, ""},
		{http.MethodPost, "/api/v1/access/ziti/posture/identities/" + identity + "/evaluate", ""},
		{http.MethodGet, "/api/v1/access/ziti/services", ""},
		{http.MethodGet, "/api/v1/access/ziti/fabric/overview", ""},
		{http.MethodGet, "/api/v1/access/ziti/fabric/health", ""},
		{http.MethodGet, "/api/v1/access/ziti/fabric/service-policies", ""},
		{http.MethodGet, "/api/v1/access/ziti/configs", ""},
		{http.MethodGet, "/api/v1/access/ziti/terminators", ""},
		{http.MethodGet, "/api/v1/access/ziti/terminators/term-" + f.suffix, ""},
		{http.MethodGet, "/api/v1/access/ziti/posture/checks", ""},
		{http.MethodGet, "/api/v1/access/ziti/posture/summary", ""},
		{http.MethodGet, "/api/v1/access/ziti/certificates", ""},
		{http.MethodGet, "/api/v1/access/ziti/certificates/expiry-alerts", ""},
		{http.MethodGet, "/api/v1/access/devices/enriched", ""},
	}

	type state struct {
		sessionStatus         string
		recordingFinalized    bool
		started, minted, qr   int
		tokenRevoked          bool
		revokedAgent, pending string
	}
	read := func() state {
		t.Helper()
		var s state
		if err := f.db.Pool.QueryRow(f.ctx, `
			SELECT (SELECT status FROM remote_support_sessions WHERE id = $1::uuid),
			       (SELECT recording_finalized_at IS NOT NULL FROM remote_support_sessions WHERE id = $1::uuid),
			       (SELECT COUNT(*) FROM remote_support_sessions WHERE agent_id = $2),
			       (SELECT COUNT(*) FROM agent_enrollment_tokens WHERE description = $3),
			       (SELECT COUNT(*) FROM agent_enrollment_tokens WHERE description = $4),
			       (SELECT revoked FROM agent_enrollment_tokens WHERE id = $5::uuid),
			       (SELECT status FROM enrolled_agents WHERE agent_id = $6),
			       (SELECT status FROM enrolled_agents WHERE agent_id = $7)`,
			session, toStart, "minted-"+f.suffix, "qr-"+f.suffix, token, toRevoke, pending,
		).Scan(&s.sessionStatus, &s.recordingFinalized, &s.started, &s.minted, &s.qr,
			&s.tokenRevoked, &s.revokedAgent, &s.pending); err != nil {
			t.Fatalf("read back: %v", err)
		}
		return s
	}
	untouched := state{sessionStatus: "active", revokedAgent: "active", pending: "pending"}

	for _, who := range []struct{ name, key string }{
		{"a plain user", e.caller(f.userA, f.orgA, "user")},
		{"an auditor", e.caller(f.userA, f.orgA, "auditor")},
		{"a compliance_reader", e.caller(f.userA, f.orgA, "compliance_reader")},
	} {
		for _, rq := range routes {
			code, body := e.do(who.key, rq.method, rq.path, rq.body)
			if code != http.StatusForbidden || !strings.Contains(body, "operator access required") {
				t.Errorf("%s %s as %s: %d %s, want 403 operator access required", rq.method, rq.path, who.name, code, body)
			}
		}
	}
	if s := read(); s != untouched {
		t.Fatalf("refused requests changed something: %+v, want %+v", s, untouched)
	}

	operator := e.caller(f.operatorA, f.orgA, "operator")
	for _, rq := range routes {
		if code, body := e.do(operator, rq.method, rq.path, rq.body); code == http.StatusForbidden && strings.Contains(body, "access required") {
			t.Errorf("%s %s as an operator was refused: %s", rq.method, rq.path, body)
		}
	}
	want := state{sessionStatus: "ended", recordingFinalized: true, started: 1, minted: 1, qr: 1,
		tokenRevoked: true, revokedAgent: "revoked", pending: "active"}
	if s := read(); s != want {
		t.Errorf("an operator's writes did not all land: %+v, want %+v", s, want)
	}
	for _, rd := range []struct{ path, shows string }{
		{rs, session},
		{rs + "/" + session + "/recording", "recorded-" + f.suffix},
		{"/api/v1/access/agents", active},
		{"/api/v1/access/ziti/identities", "identity-" + f.suffix},
		{"/api/v1/access/ziti/sync/user-map", f.userA},
		{"/api/v1/access/devices/enriched", fingerprint},
	} {
		if code, body := e.do(operator, http.MethodGet, rd.path, ""); code != http.StatusOK || !strings.Contains(body, rd.shows) {
			t.Errorf("GET %s as an operator: %d %s, want 200 showing %s", rd.path, code, body, rd.shows)
		}
	}

	admin := e.caller(f.adminA, f.orgA, "admin")
	for _, rq := range routes {
		if code, body := e.do(admin, rq.method, rq.path, rq.body); code == http.StatusForbidden && strings.Contains(body, "access required") {
			t.Errorf("%s %s as an admin was refused: %s", rq.method, rq.path, body)
		}
	}
}

// The unified audit trail is the console's Unified Audit page, an auditor
// page in its audit domain, where compliance_reader counts as an auditor. A
// plain user and a role the console does not rank are refused; the auditor
// tier and everything above it read the organization's events.
func TestTheAuditTrailNeedsTheAuditTier(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	e := f.serve(t, f.db)
	event := "probe-" + f.suffix
	if _, err := f.db.Pool.Exec(f.ctx, `
		INSERT INTO unified_audit_events (org_id, source, event_type, user_id, route_id)
		VALUES ($1::uuid, 'access-service', $2, $3::uuid, $4::uuid)`, f.orgA, event, f.userA, f.routeA); err != nil {
		t.Fatalf("seed audit event: %v", err)
	}
	routes := []string{
		"/api/v1/access/audit/unified",
		"/api/v1/access/audit/unified/services/" + f.routeA,
		"/api/v1/access/audit/unified/summary",
	}
	for _, roles := range [][]string{{"user"}, {"manager"}} {
		key := e.caller(f.userA, f.orgA, roles...)
		for _, path := range routes {
			if code, body := e.do(key, http.MethodGet, path, ""); code != http.StatusForbidden || !strings.Contains(body, "auditor access required") {
				t.Errorf("GET %s as %v: %d %s, want 403 auditor access required", path, roles, code, body)
			}
		}
	}
	for _, roles := range [][]string{{"compliance_reader"}, {"auditor"}, {"operator"}, {"admin"}} {
		key := e.caller(f.userA, f.orgA, roles...)
		for _, path := range routes {
			if code, body := e.do(key, http.MethodGet, path, ""); code != http.StatusOK {
				t.Errorf("GET %s as %v: %d %s, want 200", path, roles, code, body)
			}
		}
		if _, body := e.do(key, http.MethodGet, routes[0], ""); !strings.Contains(body, event) {
			t.Errorf("GET %s as %v did not return the organization's event: %s", routes[0], roles, body)
		}
	}
}

// Network Setup is an admin page, and its payload names every Ziti route's
// upstream -- the route internals the route list keeps to admins -- and the
// install-wide user counts. An operator is refused along with a plain user.
func TestNetworkSetupNeedsAnAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	e := f.serve(t, f.db)
	const path = "/api/v1/access/ziti/setup/status"
	for _, roles := range [][]string{{"user"}, {"operator"}} {
		if code, body := e.do(e.caller(f.userA, f.orgA, roles...), http.MethodGet, path, ""); code != http.StatusForbidden || !strings.Contains(body, "admin access required") {
			t.Errorf("GET %s as %v: %d %s, want 403 admin access required", path, roles, code, body)
		}
	}
	if code, body := e.do(e.caller(f.adminA, f.orgA, "admin"), http.MethodGet, path, ""); code != http.StatusOK {
		t.Errorf("GET %s as an admin: %d %s, want 200", path, code, body)
	}
}

// What the tiers leave alone: a user's own devices, enrollment and reach, and
// the status probes that say whether the overlay is up and carry nothing but
// the organization's own counts. A plain user is refused by none of the tier
// gates here.
func TestSelfServiceAndConfigurationReadsStayOpen(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	e := f.serve(t, f.db)
	session := f.seedRemoteSession(t, f.orgA, f.seedAgent(t, f.orgA, "open", "active"))
	user := e.caller(f.userA, f.orgA, "user")
	for _, rq := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/access/my-devices"},
		{http.MethodGet, "/api/v1/access/my/resources"},
		{http.MethodGet, "/api/v1/access/my/ziti/services"},
		{http.MethodGet, "/api/v1/access/ziti/sync/my-identity"},
		{http.MethodPost, "/api/v1/access/agent/enroll/session"},
		{http.MethodGet, "/api/v1/access/agent/enroll/session/00000000-0000-0000-0000-000000000000/status"},
		{http.MethodGet, "/api/v1/access/agent/apk-info"},
		{http.MethodGet, "/api/v1/access/ziti/status"},
		{http.MethodGet, "/api/v1/access/ziti/browzer/status"},
		{http.MethodGet, "/api/v1/access/health/ziti"},
		{http.MethodGet, "/api/v1/access/health/integrations"},
		{http.MethodGet, "/api/v1/access/remote-support/sessions/" + session + "/legal-holds"},
		{http.MethodGet, "/api/v1/access/recording-retention-policy"},
		{http.MethodGet, "/api/v1/access/kiosk/policies"},
	} {
		if code, body := e.do(user, rq.method, rq.path, ""); code == http.StatusForbidden && strings.Contains(body, "access required") {
			t.Errorf("%s %s as a plain user was refused by a tier gate: %s", rq.method, rq.path, body)
		}
	}
}

// REMOTE SUPPORT STAYS INSIDE THE CALLER'S ORGANIZATION.
//
// The recording store is keyed by session id alone, and the device finds its
// session by agent id alone, so the organization has to be checked where the
// operator's request comes in. An operator of the first organization:
//
//   - downloads their own organization's recording and not the other's, which
//     used to be served to anyone who knew the session id;
//   - cannot end the other organization's session;
//   - cannot open a session on the other organization's device, which that
//     device would otherwise have picked up.
//
// Run twice: as the superuser, where the handlers' own predicates are all that
// scopes the lookups, and as a member of openidx_app under FORCE'd RLS.
func TestRemoteSupportStaysInsideTheOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	run := func(t *testing.T, db *database.PostgresDB, tag string) {
		e := f.serveWith(t, db, &config.Config{Environment: "production", RecordingsStoragePath: t.TempDir()})
		agentA := f.seedAgent(t, f.orgA, "own-"+tag, "active")
		agentB := f.seedAgent(t, f.orgB, "other-"+tag, "active")
		sessionA := f.seedRemoteSession(t, f.orgA, agentA)
		sessionB := f.seedRemoteSession(t, f.orgB, agentB)
		store := e.svc.remoteSupportHandler.recordingStore
		for id, content := range map[string]string{sessionA: "screen-a-" + tag, sessionB: "screen-b-" + tag} {
			if _, err := store.Append(id, 0, strings.NewReader(content)); err != nil {
				t.Fatalf("store a recording: %v", err)
			}
		}
		status := func(id string) string {
			t.Helper()
			var s string
			if err := f.db.Pool.QueryRow(f.ctx, `SELECT status FROM remote_support_sessions WHERE id = $1::uuid`, id).Scan(&s); err != nil {
				t.Fatalf("read session %s: %v", id, err)
			}
			return s
		}
		operator := e.caller(f.operatorA, f.orgA, "operator")
		rs := "/api/v1/access/remote-support/sessions/"

		if code, body := e.do(operator, http.MethodGet, rs+sessionA+"/recording", ""); code != http.StatusOK || body != "screen-a-"+tag {
			t.Errorf("download the organization's own recording: %d %q", code, body)
		}
		if code, body := e.do(operator, http.MethodGet, rs+sessionB+"/recording", ""); code != http.StatusNotFound || strings.Contains(body, "screen-b-") {
			t.Errorf("download another organization's recording: %d %q, want 404 and none of it", code, body)
		}

		if code, body := e.do(operator, http.MethodPost, rs+sessionB+"/end", `{"reason":"cross-tenant"}`); code != http.StatusNotFound {
			t.Errorf("end another organization's session: %d %s, want 404", code, body)
		}
		if got := status(sessionB); got != "active" {
			t.Errorf("another organization's session was ended: status %q", got)
		}
		if code, body := e.do(operator, http.MethodPost, rs+sessionA+"/end", `{"reason":"done"}`); code != http.StatusOK || status(sessionA) != "ended" {
			t.Errorf("end the organization's own session: %d %s, status %q", code, body, status(sessionA))
		}

		if code, body := e.do(operator, http.MethodPost, strings.TrimSuffix(rs, "/"), `{"agent_id":"`+agentB+`"}`); code != http.StatusNotFound {
			t.Errorf("open a session on another organization's device: %d %s, want 404", code, body)
		}
		var opened int
		if err := f.db.Pool.QueryRow(f.ctx, `SELECT COUNT(*) FROM remote_support_sessions WHERE agent_id = $1`, agentB).Scan(&opened); err != nil || opened != 1 {
			t.Errorf("sessions naming the other organization's device: %d (err %v), want only the seeded one", opened, err)
		}
		if code, body := e.do(operator, http.MethodPost, strings.TrimSuffix(rs, "/"), `{"agent_id":"`+agentA+`","mode":"view"}`); code != http.StatusCreated {
			t.Errorf("open a session on the organization's own device: %d %s", code, body)
		}
	}

	t.Run("through the handlers' own predicates", func(t *testing.T) { run(t, f.db, "p") })
	t.Run("under the RLS belt", func(t *testing.T) {
		appDB := f.connectAsAppRole(t)
		probe := f.seedRemoteSession(t, f.orgB, f.seedAgent(t, f.orgB, "probe", "active"))
		var visible int
		if err := appDB.Pool.QueryRow(orgctx.With(context.Background(), orgctx.Org{ID: f.orgA}),
			`SELECT COUNT(*) FROM remote_support_sessions WHERE id = $1::uuid`, probe).Scan(&visible); err != nil {
			t.Fatalf("scoped read: %v", err)
		}
		if visible != 0 {
			t.Fatal("a read scoped to one organization saw another's session; RLS is not in force for this role")
		}
		run(t, appDB, "b")
	})
}

// seedAgent enrolls an agent in org with the given status and returns its id.
func (f *adminGateFixture) seedAgent(t *testing.T, org, name, status string) string {
	t.Helper()
	id := "agent-" + name + "-" + f.suffix
	if _, err := f.db.Pool.Exec(f.ctx, `
		INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash, org_id)
		VALUES ($1, $1, $2, 'not-a-real-hash', $3::uuid)`, id, status, org); err != nil {
		t.Fatalf("seed agent %s: %v", id, err)
	}
	return id
}

// seedRemoteSession opens an active, recorded remote-support session on agent.
func (f *adminGateFixture) seedRemoteSession(t *testing.T, org, agent string) string {
	t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO remote_support_sessions (agent_id, status, mode, org_id, recording_enabled)
		VALUES ($1, 'active', 'interactive', $2::uuid, true) RETURNING id::text`, agent, org).Scan(&id); err != nil {
		t.Fatalf("seed remote-support session: %v", err)
	}
	return id
}
