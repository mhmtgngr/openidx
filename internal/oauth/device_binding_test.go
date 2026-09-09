package oauth

import (
	"net/http"
	"testing"
	"time"
)

// The device binding is the routing key a device revoke follows to find the
// tokens a phone is holding. These cases pin the two halves that make it work:
// the server checks the client's claim against its own record of who enrolled
// the agent, and rotation carries the binding forward.
//
// The second half is the one that would rot silently. A binding that only ever
// landed on the FIRST token of a chain would look correct in every manual test
// — bind, revoke, gone — and be defeated in production by the client refreshing
// once, which it does every hour.

// agentSchema is the shape agentBindingForUser reads: the fleet table, which
// carries no org_id by an explicit decision recorded in v43/v120/v165.
const agentSchema = `
CREATE TABLE enrolled_agents (
    agent_id            VARCHAR(64) PRIMARY KEY,
    status              VARCHAR(20) NOT NULL DEFAULT 'active',
    enrolled_by_user_id UUID
);`

func TestAgentBindingForUser(t *testing.T) {
	s, db, ctx := newRefreshReuseService(t)

	if _, err := db.Pool.Exec(ctx, agentSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const otherUser = "77777777-0000-0000-0000-0000000000ff"
	for _, seed := range []string{
		`INSERT INTO enrolled_agents (agent_id, status, enrolled_by_user_id) VALUES ('agent-mine','active','` + reuseUser + `')`,
		`INSERT INTO enrolled_agents (agent_id, status, enrolled_by_user_id) VALUES ('agent-pending','pending','` + reuseUser + `')`,
		`INSERT INTO enrolled_agents (agent_id, status, enrolled_by_user_id) VALUES ('agent-revoked','revoked','` + reuseUser + `')`,
		`INSERT INTO enrolled_agents (agent_id, status, enrolled_by_user_id) VALUES ('agent-theirs','active','` + otherUser + `')`,
		`INSERT INTO enrolled_agents (agent_id, status, enrolled_by_user_id) VALUES ('agent-orphan','active',NULL)`,
	} {
		if _, err := db.Pool.Exec(ctx, seed); err != nil {
			t.Fatalf("seed: %v\n%s", err, seed)
		}
	}

	for _, tc := range []struct {
		name    string
		claimed string
		user    string
		want    string
		why     string
	}{
		{"the user's own active device", "agent-mine", reuseUser, "agent-mine",
			"the ordinary case: a native client naming the device it runs on"},
		{"a device still awaiting approval", "agent-pending", reuseUser, "agent-pending",
			"pending is enrolled-but-untrusted; its tokens must still be revocable"},
		{"a revoked device", "agent-revoked", reuseUser, "",
			"binding here would hand a revoked device a chain the revoke that already ran cannot reach"},
		{"somebody else's device", "agent-theirs", reuseUser, "",
			"revoking my phone must not be able to cut a stranger's session"},
		{"a device with no enrolling user", "agent-orphan", reuseUser, "",
			"token-enrolled/legacy agents name no owner, so no claim can be checked"},
		{"a device that does not exist", "agent-ghost", reuseUser, "", "nothing to check the claim against"},
		{"no claim at all", "", reuseUser, "", "the browser clients, and every pre-v185 client"},
		{"no user", "agent-mine", "", "", "there is no owner to compare against"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.agentBindingForUser(ctx, tc.claimed, tc.user)
			if got != tc.want {
				t.Errorf("agentBindingForUser(%q, %q) = %q, want %q — %s",
					tc.claimed, tc.user, got, tc.want, tc.why)
			}
		})
	}
}

// TestRefreshRotationCarriesTheDeviceBinding is the anti-rot case, and it drives
// the real grant rather than building the successor itself: the binding is
// carried forward by handleRefreshTokenGrant, so a test that constructs the new
// token by hand proves only that CreateRefreshToken stores what it is given.
// (It did, and passed with the carry-forward deleted. That is the failure this
// version exists to make impossible.)
//
// The property: a chain that has rotated is still findable by the device
// revoke. Without it the control is defeated by the client refreshing once,
// which it does every hour.
func TestRefreshRotationCarriesTheDeviceBinding(t *testing.T) {
	f := newRefreshGrantFixture(t)

	f.mintRefresh(t, "dev-tok-1", "app", grantUser, "openid offline_access", "", "", time.Now().Add(time.Hour))
	if _, err := f.db.Pool.Exec(f.ctx,
		`UPDATE oauth_refresh_tokens SET agent_id = 'agent-bound' WHERE token = 'dev-tok-1'`); err != nil {
		t.Fatalf("bind: %v", err)
	}

	w, body := f.post(t, creds("app", "s3cret", "refresh_token", "dev-tok-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("refresh grant status %d, body %v", w.Code, body)
	}
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" || rotated == "dev-tok-1" {
		t.Fatalf("no rotated refresh token in the response: %v", body)
	}

	var agentID *string
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT agent_id FROM oauth_refresh_tokens WHERE token = $1`, rotated).Scan(&agentID); err != nil {
		t.Fatalf("read rotated token: %v", err)
	}
	if agentID == nil || *agentID != "agent-bound" {
		got := "NULL"
		if agentID != nil {
			got = *agentID
		}
		t.Errorf("rotated token's agent_id = %s, want agent-bound — one refresh and the device revoke can no longer find this chain", got)
	}
}

// TestUnboundTokenStoresNull keeps the column honest: a browser client's token
// must record "no device", not the empty string, so the partial index the
// revoke reads holds only real bindings.
func TestUnboundTokenStoresNull(t *testing.T) {
	s, db, ctx := newRefreshReuseService(t)

	if err := s.CreateRefreshToken(ctx, &RefreshToken{
		Token:     "console-tok",
		ClientID:  "openidx-console",
		UserID:    reuseUser,
		Scope:     "openid offline_access",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	var isNull bool
	if err := db.Pool.QueryRow(ctx,
		`SELECT agent_id IS NULL FROM oauth_refresh_tokens WHERE token = 'console-tok'`).Scan(&isNull); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !isNull {
		t.Error("an unbound token stored a non-NULL agent_id")
	}
}
