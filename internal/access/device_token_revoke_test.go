package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Revoking a device used to leave its tokens alive.
//
// executeDeviceRevoke deleted the Ziti identity, terminated the overlay
// sessions and untrusted the known device — every pillar except the one the
// user's phone actually talks to. The native clients hold a 30-day refresh
// token, so the revoked device could not dial a service and went on acting as
// the user over plain HTTP for a month, including approving push-MFA
// challenges. Nothing failed; there was simply no column saying which device a
// token belonged to.
//
// These cases run against a real Postgres because the property is a database
// one: which rows a revoke reaches, and which rows it must not.

// tokenSchema is the OAuth half the device revoke now touches. Shapes match the
// live tables: sessions.id is a UUID, oauth_refresh_tokens.session_id is a UUID
// (v31) and agent_id is VARCHAR(64) (v185).
var tokenSchema = []string{
	`CREATE TABLE IF NOT EXISTS sessions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL,
		client_id VARCHAR(255) NOT NULL, org_id UUID,
		started_at TIMESTAMPTZ DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL,
		revoked BOOLEAN DEFAULT false, revoked_at TIMESTAMPTZ)`,
	`CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
		token VARCHAR(500) PRIMARY KEY, client_id VARCHAR(255) NOT NULL,
		user_id UUID NOT NULL, scope TEXT, session_id UUID,
		expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW(),
		org_id UUID NOT NULL, family_id UUID, used_at TIMESTAMPTZ,
		revoked_at TIMESTAMPTZ, agent_id VARCHAR(64))`,
}

const (
	revOtherOrg  = "00000000-0000-0000-0000-0000000000e0"
	revSessMine  = "33333333-0000-0000-0000-0000000000a1"
	revSessAlso  = "33333333-0000-0000-0000-0000000000a2"
	revSessOther = "33333333-0000-0000-0000-0000000000a3"
)

func newDeviceRevokeService(t *testing.T) (*Service, *database.PostgresDB, *miniredis.Miniredis, context.Context) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: devOrg})
	for _, stmt := range append(append([]string{}, deviceSchema...), tokenSchema...) {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	mini := miniredis.RunT(t)
	s := &Service{
		db:     db,
		logger: zap.NewNop(),
		redis:  &database.RedisClient{Client: redis.NewClient(&redis.Options{Addr: mini.Addr()})},
	}
	return s, db, mini, ctx
}

func TestDeviceRevoke_RevokesTheTokensTheDeviceHolds(t *testing.T) {
	s, db, mini, ctx := newDeviceRevokeService(t)

	hour := time.Now().Add(time.Hour).Format(time.RFC3339)
	seeds := []string{
		`INSERT INTO users (id, org_id, username, email) VALUES ('` + devUser + `','` + devOrg + `','dana','dana@x.io')`,
		`INSERT INTO enrolled_agents (agent_id, ziti_identity_id, status, enrolled_by_user_id) VALUES ('agent-phone','zid-p','active','` + devUser + `')`,
		// Two sign-ins on the phone, each with its own session and chain; the
		// second has rotated once, so the family has two rows.
		`INSERT INTO sessions (id, user_id, client_id, org_id, expires_at) VALUES ('` + revSessMine + `','` + devUser + `','openidx-mobile','` + devOrg + `','` + hour + `')`,
		`INSERT INTO sessions (id, user_id, client_id, org_id, expires_at) VALUES ('` + revSessAlso + `','` + devUser + `','openidx-mobile','` + devOrg + `','` + hour + `')`,
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, agent_id, expires_at) VALUES ('rt-phone-1','openidx-mobile','` + devUser + `','` + revSessMine + `','` + devOrg + `','agent-phone','` + hour + `')`,
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, agent_id, expires_at, used_at) VALUES ('rt-phone-2a','openidx-mobile','` + devUser + `','` + revSessAlso + `','` + devOrg + `','agent-phone','` + hour + `', NOW())`,
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, agent_id, expires_at) VALUES ('rt-phone-2b','openidx-mobile','` + devUser + `','` + revSessAlso + `','` + devOrg + `','agent-phone','` + hour + `')`,
		// The same user's laptop, and their browser: neither is this device.
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, agent_id, expires_at) VALUES ('rt-laptop','openidx-desktop','` + devUser + `','` + revSessOther + `','` + devOrg + `','agent-laptop','` + hour + `')`,
		`INSERT INTO sessions (id, user_id, client_id, org_id, expires_at) VALUES ('` + revSessOther + `','` + devUser + `','openidx-desktop','` + devOrg + `','` + hour + `')`,
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, org_id, expires_at) VALUES ('rt-console','openidx-console','` + devUser + `','` + devOrg + `','` + hour + `')`,
		// Another tenant's device that happens to share the agent id: the
		// revoke must not reach across the org predicate.
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, org_id, agent_id, expires_at) VALUES ('rt-othertenant','openidx-mobile','` + devUser + `','` + revOtherOrg + `','agent-phone','` + hour + `')`,
	}

	for _, seed := range seeds {
		if _, err := db.Pool.Exec(ctx, seed); err != nil {
			t.Fatalf("seed: %v\n%s", err, seed)
		}
	}

	res := s.executeDeviceRevoke(ctx, devOrg, "agent-phone", "", "")

	if res.RefreshTokensRevoked != 3 {
		t.Errorf("revoked %d refresh tokens, want 3 (both chains, including the rotated predecessor)", res.RefreshTokensRevoked)
	}
	if res.OAuthSessionsRevoked != 2 {
		t.Errorf("revoked %d sessions, want 2", res.OAuthSessionsRevoked)
	}

	for _, tok := range []string{"rt-phone-1", "rt-phone-2a", "rt-phone-2b"} {
		var revoked bool
		if err := db.Pool.QueryRow(ctx,
			`SELECT revoked_at IS NOT NULL FROM oauth_refresh_tokens WHERE token=$1`, tok).Scan(&revoked); err != nil {
			t.Fatalf("read %s: %v", tok, err)
		}
		if !revoked {
			t.Errorf("%s survived the device revoke — the phone can still mint access tokens", tok)
		}
	}
	// Everything that is not this device is untouched. A revoke that signed the
	// user out everywhere would be a different (and much worse) control.
	for _, tok := range []string{"rt-laptop", "rt-console", "rt-othertenant"} {
		var revoked bool
		if err := db.Pool.QueryRow(orgctx.With(context.Background(), orgctx.Org{ID: revOtherOrg}),
			`SELECT revoked_at IS NOT NULL FROM oauth_refresh_tokens WHERE token=$1`, tok).Scan(&revoked); err != nil {
			// The org-scoped read of another tenant's row may return no rows
			// under the belt; re-read without a predicate mismatch.
			if err = db.Pool.QueryRow(ctx,
				`SELECT revoked_at IS NOT NULL FROM oauth_refresh_tokens WHERE token=$1`, tok).Scan(&revoked); err != nil {
				t.Fatalf("read %s: %v", tok, err)
			}
		}
		if revoked {
			t.Errorf("%s was revoked; a device revoke must cut this device only", tok)
		}
	}

	// The markers are what the refresh grant reads (internal/oauth's
	// handleRefreshTokenGrant): without them a chain revoked in Postgres would
	// still pass the session check.
	for _, sid := range []string{revSessMine, revSessAlso} {
		if !mini.Exists("revoked_session:" + sid) {
			t.Errorf("no revoked_session marker for %s; the refresh grant would not know", sid)
		}
	}
	if mini.Exists("revoked_session:" + revSessOther) {
		t.Error("the laptop's session was marked revoked")
	}

	var revoked bool
	if err := db.Pool.QueryRow(ctx, `SELECT revoked FROM sessions WHERE id=$1`, revSessMine).Scan(&revoked); err != nil || !revoked {
		t.Errorf("session row not marked revoked (revoked=%v err=%v)", revoked, err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT revoked FROM sessions WHERE id=$1`, revSessOther).Scan(&revoked); err != nil || revoked {
		t.Errorf("the laptop's session row was revoked (revoked=%v err=%v)", revoked, err)
	}
}

// TestDeviceRevoke_UnboundDeviceIsHonest pins the pre-v185 case that will exist
// on every upgraded install: an agent enrolled before the binding existed has
// no bound tokens, and the result must report zero rather than imply a
// severance that did not happen.
func TestDeviceRevoke_UnboundDeviceIsHonest(t *testing.T) {
	s, db, mini, ctx := newDeviceRevokeService(t)

	hour := time.Now().Add(time.Hour).Format(time.RFC3339)
	for _, seed := range []string{
		`INSERT INTO users (id, org_id, username, email) VALUES ('` + devUser + `','` + devOrg + `','dana','dana@x.io')`,
		`INSERT INTO enrolled_agents (agent_id, status, enrolled_by_user_id) VALUES ('agent-old','active','` + devUser + `')`,
		`INSERT INTO sessions (id, user_id, client_id, org_id, expires_at) VALUES ('` + revSessMine + `','` + devUser + `','openidx-mobile','` + devOrg + `','` + hour + `')`,
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, expires_at) VALUES ('rt-legacy','openidx-mobile','` + devUser + `','` + revSessMine + `','` + devOrg + `','` + hour + `')`,
	} {
		if _, err := db.Pool.Exec(ctx, seed); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	res := s.executeDeviceRevoke(ctx, devOrg, "agent-old", "", "")

	if res.RefreshTokensRevoked != 0 || res.OAuthSessionsRevoked != 0 {
		t.Errorf("reported %d tokens / %d sessions for a device with no bound chain",
			res.RefreshTokensRevoked, res.OAuthSessionsRevoked)
	}
	if mini.Exists("revoked_session:" + revSessMine) {
		t.Error("an unbound session was marked revoked; the revoke guessed")
	}
	var revoked bool
	if err := db.Pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM oauth_refresh_tokens WHERE token='rt-legacy'`).Scan(&revoked); err != nil || revoked {
		t.Errorf("an unbound token was revoked (revoked=%v err=%v)", revoked, err)
	}
}

// TestEnrollOAuth_BindsTheEnrollingSession covers the Android path, where the
// server knows both halves: the session comes from the bearer's sid claim and
// the agent from the row it has just written. It must bind that session's own
// unbound chain and nothing else.
func TestEnrollOAuth_BindsTheEnrollingSession(t *testing.T) {
	_, db, _, ctx := newDeviceRevokeService(t)

	hour := time.Now().Add(time.Hour).Format(time.RFC3339)
	const otherUser = "11111111-0000-0000-0000-0000000000ff"
	for _, seed := range []string{
		`INSERT INTO users (id, org_id, username, email) VALUES ('` + devUser + `','` + devOrg + `','dana','dana@x.io')`,
		`INSERT INTO users (id, org_id, username, email) VALUES ('` + otherUser + `','` + devOrg + `','sam','sam@x.io')`,
		// The enrolling session's own chain.
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, expires_at) VALUES ('rt-enrolling','openidx-agent-android','` + devUser + `','` + revSessMine + `','` + devOrg + `','` + hour + `')`,
		// A different session of the same user: not this enrolment's.
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, expires_at) VALUES ('rt-elsewhere','openidx-mobile','` + devUser + `','` + revSessAlso + `','` + devOrg + `','` + hour + `')`,
		// Same session id, different user — impossible in practice, and the
		// query must still refuse it.
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, expires_at) VALUES ('rt-notmine','openidx-mobile','` + otherUser + `','` + revSessMine + `','` + devOrg + `','` + hour + `')`,
		// Already bound to another device: re-enrolling must not steal it.
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, agent_id, expires_at) VALUES ('rt-bound','openidx-mobile','` + devUser + `','` + revSessMine + `','` + devOrg + `','agent-earlier','` + hour + `')`,
	} {
		if _, err := db.Pool.Exec(ctx, seed); err != nil {
			t.Fatalf("seed: %v\n%s", err, seed)
		}
	}

	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	h.bindSessionTokensToAgent(ctx, revSessMine, devUser, devOrg, "agent-new")

	for _, tc := range []struct {
		token string
		want  string
	}{
		{"rt-enrolling", "agent-new"},
		{"rt-elsewhere", ""},
		{"rt-notmine", ""},
		{"rt-bound", "agent-earlier"},
	} {
		var got *string
		if err := db.Pool.QueryRow(ctx,
			`SELECT agent_id FROM oauth_refresh_tokens WHERE token=$1`, tc.token).Scan(&got); err != nil {
			t.Fatalf("read %s: %v", tc.token, err)
		}
		have := ""
		if got != nil {
			have = *got
		}
		if have != tc.want {
			t.Errorf("%s bound to %q, want %q", tc.token, have, tc.want)
		}
	}
}

// TestEnrollOAuth_BindingNeedsASession keeps the no-op cases no-ops: a bearer
// with no sid claim (or a handler with no database) must change nothing rather
// than bind every unbound row it can see.
func TestEnrollOAuth_BindingNeedsASession(t *testing.T) {
	_, db, _, ctx := newDeviceRevokeService(t)

	hour := time.Now().Add(time.Hour).Format(time.RFC3339)
	for _, seed := range []string{
		`INSERT INTO users (id, org_id, username, email) VALUES ('` + devUser + `','` + devOrg + `','dana','dana@x.io')`,
		`INSERT INTO oauth_refresh_tokens (token, client_id, user_id, session_id, org_id, expires_at) VALUES ('rt-any','openidx-mobile','` + devUser + `','` + revSessMine + `','` + devOrg + `','` + hour + `')`,
	} {
		if _, err := db.Pool.Exec(ctx, seed); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	h.bindSessionTokensToAgent(ctx, "", devUser, devOrg, "agent-new")   // no sid claim
	h.bindSessionTokensToAgent(ctx, "not-a-uuid", devUser, devOrg, "x") // malformed sid: no match, not an error

	var got *string
	if err := db.Pool.QueryRow(ctx, `SELECT agent_id FROM oauth_refresh_tokens WHERE token='rt-any'`).Scan(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != nil {
		t.Errorf("a binding with no session id stamped %q", *got)
	}
}

// TestEnrollOAuth_NoDatabaseIsSafe covers the handler shape the scope test uses
// (no database at all): the enrolment path must not panic on the binding step.
func TestEnrollOAuth_NoDatabaseIsSafe(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewAgentAPIHandler(zap.NewNop(), nil, nil, nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/agent/enroll/oauth", nil)
	c.Set("user_id", "user-1")
	c.Set("scope", "agent.enroll")
	c.Set("session_id", revSessMine)

	h.HandleEnrollOAuth(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (body %s)", w.Code, w.Body.String())
	}
}
