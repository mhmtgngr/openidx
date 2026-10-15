package access

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// One device revoke, whichever page it is pressed on.
//
// Agent Fleet's revoke used to set the row's status and delete the Ziti
// identity, and stop: the device's refresh-token families went on refreshing,
// its known device stayed trusted and its live circuits were not severed,
// while the same device revoked from the user's page lost all of them. Both
// now call deviceRevoker, and so does the kill switch under revoke_devices.

const (
	onePathKnownDevice = "22222222-0000-0000-0000-00000000000e"
	onePathSessA       = "33333333-0000-0000-0000-0000000000b1"
	onePathSessB       = "33333333-0000-0000-0000-0000000000b2"
	onePathSessLaptop  = "33333333-0000-0000-0000-0000000000b3"
)

// seedOnePathFleet writes one user with a phone (bound tokens and sessions, a
// trusted known device) and a laptop, and another tenant's device.
func seedOnePathFleet(t *testing.T, s *Service) {
	t.Helper()
	ctx := orgctx.With(t.Context(), orgctx.Org{ID: devOrg})
	hour := time.Now().Add(time.Hour).Format(time.RFC3339)
	seeds := []string{
		`INSERT INTO users (id, org_id, username, email) VALUES ('` + devUser + `','` + devOrg + `','dana','dana@x.io')`,
		`INSERT INTO known_devices (id, user_id, org_id, fingerprint, name, trusted) VALUES ('` + onePathKnownDevice + `','` + devUser + `','` + devOrg + `','agent:phone','Dana Phone',true)`,
		`INSERT INTO enrolled_agents (org_id, agent_id, ziti_identity_id, status, enrolled_by_user_id, known_device_id) VALUES ('` + devOrg + `','agent-phone','zid-p','active','` + devUser + `','` + onePathKnownDevice + `')`,
		`INSERT INTO enrolled_agents (org_id, agent_id, ziti_identity_id, status, enrolled_by_user_id) VALUES ('` + devOrg + `','agent-laptop','zid-l','active','` + devUser + `')`,
		`INSERT INTO enrolled_agents (org_id, agent_id, ziti_identity_id, status) VALUES ('` + revOtherOrg + `','agent-elsewhere','zid-e','active')`,
		`INSERT INTO sessions (id, user_id, client_id, org_id, expires_at) VALUES ('` + onePathSessA + `','` + devUser + `','openidx-mobile','` + devOrg + `','` + hour + `')`,
		`INSERT INTO sessions (id, user_id, client_id, org_id, expires_at) VALUES ('` + onePathSessB + `','` + devUser + `','openidx-mobile','` + devOrg + `','` + hour + `')`,
		`INSERT INTO sessions (id, user_id, client_id, org_id, expires_at) VALUES ('` + onePathSessLaptop + `','` + devUser + `','openidx-desktop','` + devOrg + `','` + hour + `')`,
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, agent_id, expires_at) VALUES ('rt-phone-a','openidx-mobile','` + devUser + `','` + onePathSessA + `','` + devOrg + `','agent-phone','` + hour + `')`,
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, agent_id, expires_at) VALUES ('rt-phone-b','openidx-mobile','` + devUser + `','` + onePathSessB + `','` + devOrg + `','agent-phone','` + hour + `')`,
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, agent_id, expires_at) VALUES ('rt-laptop','openidx-desktop','` + devUser + `','` + onePathSessLaptop + `','` + devOrg + `','agent-laptop','` + hour + `')`,
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, org_id, expires_at) VALUES ('rt-console','openidx-console','` + devUser + `','` + devOrg + `','` + hour + `')`,
	}
	for _, seed := range seeds {
		if _, err := s.db.Pool.Exec(ctx, seed); err != nil {
			t.Fatalf("seed: %v\n%s", err, seed)
		}
	}
}

type onePathState struct {
	status             string
	zitiID             string
	knownDeviceTrusted bool
	tokensRevoked      int
	sessionsRevoked    int
}

func readOnePathState(t *testing.T, s *Service, agentID string) onePathState {
	t.Helper()
	ctx := orgctx.With(t.Context(), orgctx.Org{ID: devOrg})
	var st onePathState
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT status, COALESCE(ziti_identity_id,'') FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`,
		agentID, devOrg).Scan(&st.status, &st.zitiID); err != nil {
		t.Fatalf("read %s: %v", agentID, err)
	}
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_refresh_tokens WHERE agent_id = $1 AND org_id = $2 AND revoked_at IS NOT NULL`,
		agentID, devOrg).Scan(&st.tokensRevoked); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE revoked = true AND id IN (SELECT session_id FROM oauth_refresh_tokens WHERE agent_id = $1)`,
		agentID).Scan(&st.sessionsRevoked); err != nil {
		t.Fatal(err)
	}
	_ = s.db.Pool.QueryRow(ctx, `SELECT trusted FROM known_devices WHERE id = $1`, onePathKnownDevice).Scan(&st.knownDeviceTrusted)
	return st
}

func TestFleetRevokeIsTheDeviceRevoke(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, db, mini, _ := newDeviceRevokeService(t)
	seedOnePathFleet(t, s)

	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	h.SetRevocationRedis(s.redis.RevocationDB())
	router := gin.New()
	admin := router.Group("/api/v1/access", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: devOrg}))
		c.Next()
	})
	h.RegisterAgentAdminRoutes(admin, nil)
	revoke := func(agentID string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/access/agents/"+agentID, nil))
		return w
	}

	w := revoke("agent-phone")
	if w.Code != http.StatusOK {
		t.Fatalf("fleet revoke answered %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Status string             `json:"status"`
		Revoke DeviceRevokeResult `json:"revoke"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("answer is not JSON: %s", w.Body.String())
	}
	if body.Status != "revoked" || !body.Revoke.AgentRevoked {
		t.Errorf("answer = %s, want status revoked and agent_revoked", w.Body.String())
	}
	if body.Revoke.RefreshTokensRevoked < 2 || body.Revoke.OAuthSessionsRevoked != 2 || !body.Revoke.KnownDeviceUntrusted {
		t.Errorf("the fleet revoke did less than the device revoke: %+v", body.Revoke)
	}

	phone := readOnePathState(t, s, "agent-phone")
	if phone.status != "revoked" || phone.zitiID != "" {
		t.Errorf("phone row = %+v, want revoked with its identity cleared", phone)
	}
	if phone.tokensRevoked != 2 || phone.sessionsRevoked != 2 {
		t.Errorf("phone tokens revoked %d (want 2), sessions revoked %d (want 2)", phone.tokensRevoked, phone.sessionsRevoked)
	}
	if phone.knownDeviceTrusted {
		t.Error("the phone's known device is still trusted")
	}
	for _, sid := range []string{onePathSessA, onePathSessB} {
		if !mini.Exists("revoked_session:" + sid) {
			t.Errorf("no revocation marker for session %s", sid)
		}
	}
	// The same user's laptop, and their browser session, are not this device.
	laptop := readOnePathState(t, s, "agent-laptop")
	if laptop.status != "active" || laptop.tokensRevoked != 0 || laptop.sessionsRevoked != 0 {
		t.Errorf("the laptop was touched by the phone's revoke: %+v", laptop)
	}
	var consoleRevoked bool
	if err := db.Pool.QueryRow(t.Context(), `SELECT revoked_at IS NOT NULL FROM oauth_refresh_tokens WHERE token = 'rt-console'`).Scan(&consoleRevoked); err != nil || consoleRevoked {
		t.Errorf("the browser's refresh token was revoked by a device revoke (err %v)", err)
	}

	// Another tenant's device is not found, and not revoked.
	if w := revoke("agent-elsewhere"); w.Code != http.StatusNotFound {
		t.Errorf("another tenant's device answered %d, want 404", w.Code)
	}
	var elsewhere string
	if err := db.Pool.QueryRow(t.Context(), `SELECT status FROM enrolled_agents WHERE agent_id = 'agent-elsewhere'`).Scan(&elsewhere); err != nil || elsewhere != "active" {
		t.Errorf("another tenant's device is %q (err %v), want active", elsewhere, err)
	}

	// Revoking again is idempotent.
	if w := revoke("agent-phone"); w.Code != http.StatusOK {
		t.Errorf("a second revoke answered %d: %s", w.Code, w.Body.String())
	}
}

func TestKillSwitchRevokesDevicesOnlyWhenAsked(t *testing.T) {
	s, _, _, ctx := newDeviceRevokeService(t)
	seedOnePathFleet(t, s)

	res := s.executeKillSwitchWith(ctx, devOrg, devUser, "dana", testActor, "contain", killSwitchOptions{})
	if res.DevicesRevoked != 0 {
		t.Errorf("the kill switch revoked %d devices without being asked", res.DevicesRevoked)
	}
	for _, id := range []string{"agent-phone", "agent-laptop"} {
		if st := readOnePathState(t, s, id); st.status != "active" || st.zitiID == "" {
			t.Errorf("%s after a plain kill switch = %+v, want active with its identity", id, st)
		}
	}

	res = s.executeKillSwitchWith(ctx, devOrg, devUser, "dana", testActor, "leaver", killSwitchOptions{RevokeDevices: true})
	if res.DevicesRevoked != 2 {
		t.Errorf("devices_revoked = %d, want 2", res.DevicesRevoked)
	}
	for _, id := range []string{"agent-phone", "agent-laptop"} {
		st := readOnePathState(t, s, id)
		if st.status != "revoked" || st.zitiID != "" {
			t.Errorf("%s after revoke_devices = %+v, want revoked with its identity cleared", id, st)
		}
		if st.tokensRevoked == 0 {
			t.Errorf("%s keeps its refresh tokens after revoke_devices", id)
		}
	}
	if st := readOnePathState(t, s, "agent-phone"); st.knownDeviceTrusted {
		t.Error("the phone's known device is still trusted after revoke_devices")
	}
	var elsewhere string
	if err := s.db.Pool.QueryRow(ctx, `SELECT status FROM enrolled_agents WHERE agent_id = 'agent-elsewhere'`).Scan(&elsewhere); err != nil || elsewhere != "active" {
		t.Errorf("another tenant's device is %q (err %v), want active", elsewhere, err)
	}
}
