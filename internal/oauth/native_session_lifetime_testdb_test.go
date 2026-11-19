package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// A NATIVE CLIENT'S SESSION FOLLOWS THE CLIENT.
//
// The desktop tray and the phone apps hold a device-bound refresh chain of 30
// days (14 on the phone) capped at 90 (v187). Their session row, though, was
// ended by the sweeps written for a person at a browser, which read the
// global policy for every row whatever its client: idle 30 minutes, absolute
// 24 hours. A native client touches its session only when it refreshes a token,
// an hour apart at best, so every tray and phone session was ended thirty
// minutes after sign-in, before the first refresh, and the person was asked to
// sign in again all day while the device's network access (which does not
// depend on the session) went on working.
//
// These drive the sweep processExpiredSessions, the refresh grant, the policy
// and the browser-session lookup on the migrated schema. The fixture's own
// client stands in for the native one (lifetimes set as v187 sets them), and a
// second client with no family cap stands in for the console.
type nativeSessionWorld struct {
	*sessionEndFixture
	user    string
	browser string // a client with no family cap: the console's shape
}

func newNativeSessionWorld(t *testing.T) *nativeSessionWorld {
	t.Helper()
	f := newSessionEndFixture(t)
	w := &nativeSessionWorld{sessionEndFixture: f, user: f.seedUser(t, "native")}
	// The fixture's client is the native one: 30 days per token, 90 for the family.
	w.exec(t, `UPDATE oauth_clients SET refresh_token_lifetime = 2592000, refresh_token_max_lifetime = 7776000 WHERE client_id = $1`, f.clientID)
	w.browser = "console-" + f.suffix
	w.exec(t, `INSERT INTO oauth_clients (client_id, client_secret, name, type, allow_refresh_token, api_access, org_id, refresh_token_lifetime)
		VALUES ($1, 's', $1, 'confidential', true, true, $2::uuid, 86400)`, w.browser, sessionEndOrg)
	return w
}

func (w *nativeSessionWorld) exec(t *testing.T, sql string, args ...interface{}) {
	t.Helper()
	if _, err := w.db.Pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// session inserts a live session of client, started startedAgo and last seen
// seenAgo ago, the way login creates one (expires_at in the future).
func (w *nativeSessionWorld) session(t *testing.T, client string, startedAgo, seenAgo time.Duration) string {
	t.Helper()
	id := uuid.NewString()
	w.exec(t, `INSERT INTO sessions (id, user_id, client_id, started_at, last_seen_at, expires_at, org_id)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, NOW() + interval '1 hour', $6::uuid)`,
		id, w.user, client, time.Now().Add(-startedAgo), time.Now().Add(-seenAgo), sessionEndOrg)
	return id
}

// token gives the session a refresh token of client that is live.
func (w *nativeSessionWorld) token(t *testing.T, client, sessionID string) string {
	t.Helper()
	tok := "rt-" + uuid.NewString()
	if err := w.svc.CreateRefreshToken(w.orgCtx, &RefreshToken{
		Token: tok, ClientID: client, UserID: w.user, Scope: "openid offline_access",
		SessionID: sessionID, ExpiresAt: time.Now().Add(24 * time.Hour), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("mint refresh token: %v", err)
	}
	return tok
}

func (w *nativeSessionWorld) sweep() {
	w.svc.processExpiredSessions(orgctx.WithBypassRLS(context.Background()))
}

func (w *nativeSessionWorld) live(t *testing.T, id string) bool {
	t.Helper()
	var revoked bool
	if err := w.db.Pool.QueryRow(context.Background(),
		`SELECT COALESCE(revoked, false) FROM sessions WHERE id = $1::uuid`, id).Scan(&revoked); err != nil {
		t.Fatalf("read session: %v", err)
	}
	return !revoked
}

func TestNativeSessionFollowsItsClientNotTheBrowserPolicy(t *testing.T) {
	w := newNativeSessionWorld(t)
	native := w.clientID

	type c struct {
		name        string
		client      string
		started     time.Duration
		seen        time.Duration
		withToken   bool
		stillLive   bool
		explanation string
	}
	day := 24 * time.Hour
	cases := []c{
		// Browser policy for a client with no cap: idle 30 minutes, absolute 24 hours.
		{"console, idle two hours", w.browser, 3 * time.Hour, 2 * time.Hour, true, false, "the browser idle timeout"},
		{"console, signed in 25 hours ago, active", w.browser, 25 * time.Hour, time.Minute, true, false, "the browser absolute timeout"},
		// The same ages on a native client are nothing.
		{"native, idle two hours", native, 3 * time.Hour, 2 * time.Hour, true, true, "idle for less than a refresh token's lifetime"},
		{"native, idle three days", native, 3 * day, 3 * day, true, true, "a laptop closed over a weekend"},
		{"native, signed in 40 days ago, active", native, 40 * day, time.Minute, true, true, "inside the 90-day family cap"},
		// And its own limits end it.
		{"native, idle 31 days", native, 40 * day, 31 * day, true, false, "past one refresh token's unused lifetime (30 days)"},
		{"native, signed in 91 days ago, active", native, 91 * day, time.Minute, true, false, "past the 90-day family cap"},
	}
	ids := make([]string, len(cases))
	for i, tc := range cases {
		ids[i] = w.session(t, tc.client, tc.started, tc.seen)
		if tc.withToken {
			w.token(t, tc.client, ids[i])
		}
	}
	w.sweep()
	for i, tc := range cases {
		if got := w.live(t, ids[i]); got != tc.stillLive {
			t.Errorf("%s: live after the sweep = %v, want %v (%s)", tc.name, got, tc.stillLive, tc.explanation)
		}
	}
}

func TestNativeSessionEndsWhenNoRefreshTokenCanKeepItGoing(t *testing.T) {
	w := newNativeSessionWorld(t)
	native := w.clientID
	m := time.Minute

	signedOut := w.session(t, native, 20*m, 20*m) // sign-out revokes the token, not the row
	tok := w.token(t, native, signedOut)
	w.exec(t, `UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE token = $1`, tok)

	signingIn := w.session(t, native, 10*m, 10*m) // the code exchange has not yet minted a token

	abandoned := w.session(t, native, 20*m, 20*m)
	at := w.token(t, native, abandoned)
	w.exec(t, `UPDATE oauth_refresh_tokens SET used_at = NOW() - interval '30 minutes', revoked_at = NOW() WHERE token = $1`, at)

	healthy := w.session(t, native, 20*m, time.Minute)
	w.token(t, native, healthy)

	w.sweep()
	for _, tc := range []struct {
		name string
		id   string
		want bool
	}{
		{"signed out (token revoked), 20 minutes in", signedOut, false},
		{"still signing in (10 minutes, no token yet)", signingIn, true},
		{"abandoned chain (nothing live, last used 30 minutes ago)", abandoned, false},
		{"a live refresh token", healthy, true},
	} {
		if got := w.live(t, tc.id); got != tc.want {
			t.Errorf("%s: live = %v, want %v", tc.name, got, tc.want)
		}
	}
	// A token rotated within the last 10 minutes still counts as the chain's:
	// the grant is between its two writes. Here the token is also revoked, so
	// this row ends: what the case pins is that rotation alone never ends it.
	live := w.session(t, native, 20*m, m)
	lt := w.token(t, native, live)
	w.exec(t, `UPDATE oauth_refresh_tokens SET used_at = NOW() - interval '5 minutes' WHERE token = $1`, lt)
	w.sweep()
	if !w.live(t, live) {
		t.Error("a session whose only token was rotated 5 minutes ago was ended: the rotation gap is not tolerated")
	}
}

func TestSessionOfAnUnknownClientKeepsTheBrowserPolicy(t *testing.T) {
	w := newNativeSessionWorld(t)
	gone := w.session(t, "deleted-client-"+w.suffix, 3*time.Hour, 2*time.Hour)
	empty := w.session(t, "", 3*time.Hour, 2*time.Hour)
	w.sweep()
	if w.live(t, gone) || w.live(t, empty) {
		t.Errorf("a session with no client row stayed past the browser idle timeout (gone live=%v, empty live=%v)",
			w.live(t, gone), w.live(t, empty))
	}
}

func TestNativeSessionLimitsHoldWhenTheBrowserTimeoutsAreOff(t *testing.T) {
	w := newNativeSessionWorld(t)
	w.exec(t, `UPDATE system_settings SET value = jsonb_set(jsonb_set(value, '{security,idle_timeout}', '0'), '{security,absolute_timeout}', '0') WHERE key = 'system'`)
	t.Cleanup(func() {
		_, _ = w.db.Pool.Exec(context.Background(), `UPDATE system_settings SET value = value #- '{security,idle_timeout}' #- '{security,absolute_timeout}' WHERE key = 'system'`)
	})
	day := 24 * time.Hour
	old := w.session(t, w.clientID, 91*day, time.Minute)
	w.token(t, w.clientID, old)
	idle := w.session(t, w.clientID, 40*day, 31*day)
	w.token(t, w.clientID, idle)
	console := w.session(t, w.browser, 40*day, 31*day) // browser timeouts off: untouched
	w.sweep()
	if w.live(t, old) || w.live(t, idle) {
		t.Errorf("native sessions past their own limits survived with the browser timeouts off (old live=%v, idle live=%v)",
			w.live(t, old), w.live(t, idle))
	}
	if !w.live(t, console) {
		t.Error("with the browser timeouts off, the console's session was ended")
	}
}

func TestEffectiveSessionPolicyOfANativeClient(t *testing.T) {
	w := newNativeSessionWorld(t)
	n := w.svc.getEffectiveSessionPolicy(w.orgCtx, w.clientID)
	if n.IdleTimeout != 2592000 || n.AbsoluteTimeout != 7776000 {
		t.Errorf("native policy idle/absolute = %d/%d, want 2592000/7776000", n.IdleTimeout, n.AbsoluteTimeout)
	}
	b := w.svc.getEffectiveSessionPolicy(w.orgCtx, w.browser)
	if b.IdleTimeout != 1800 || b.AbsoluteTimeout != 86400 {
		t.Errorf("browser policy idle/absolute = %d/%d, want 1800/86400", b.IdleTimeout, b.AbsoluteTimeout)
	}
	if g := w.svc.getEffectiveSessionPolicy(w.orgCtx, ""); g.IdleTimeout != 1800 {
		t.Errorf("the global policy changed: idle %d", g.IdleTimeout)
	}
}

// A refresh is what keeps a native session alive, and it slides expires_at by
// the client's own lifetime; the console's slides by a day.
func TestARefreshSlidesANativeSessionByItsClientsLifetime(t *testing.T) {
	w := newNativeSessionWorld(t)
	sid, device := w.newSession(t, w.user) // fixture client = native
	w.exec(t, `UPDATE sessions SET expires_at = NOW() + interval '1 hour', last_seen_at = NOW() - interval '20 minutes' WHERE id = $1::uuid`, sid)
	w.refreshes(t, device, "a native client's live session")

	deadline := time.Now().Add(8 * time.Second)
	for {
		var days float64
		if err := w.db.Pool.QueryRow(context.Background(),
			`SELECT EXTRACT(EPOCH FROM (expires_at - NOW())) / 86400 FROM sessions WHERE id = $1::uuid`, sid).Scan(&days); err != nil {
			t.Fatalf("read session: %v", err)
		}
		if days > 29 && days <= 30.01 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expires_at is %.2f days away after a refresh, want about 30", days)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// A native client's session is its own: no browser cookie may resolve to it.
func TestANativeSessionIsNeverABrowserSession(t *testing.T) {
	w := newNativeSessionWorld(t)
	native := w.session(t, w.clientID, time.Hour, time.Minute)
	console := w.session(t, w.browser, time.Hour, time.Minute)
	for _, tc := range []struct {
		name   string
		id     string
		usable bool
	}{{"native", native, false}, {"console", console, true}} {
		token := GenerateRandomToken(32)
		if err := w.rc.Client.Set(context.Background(), ssoRedisPrefix+token, tc.id, time.Hour).Err(); err != nil {
			t.Fatal(err)
		}
		_, usable, err := w.svc.resolveBrowserSession(w.orgCtx, token)
		if err != nil || usable != tc.usable {
			t.Errorf("%s session behind a browser cookie: usable=%v err=%v, want usable=%v", tc.name, usable, err, tc.usable)
		}
	}
}

// terminate_oldest must not make the long-lived native session the first victim
// of the concurrent-session limit just because it is the oldest row.
func TestTerminateOldestSpendsABrowserSessionBeforeANativeOne(t *testing.T) {
	w := newNativeSessionWorld(t)
	native := w.session(t, w.clientID, 10*24*time.Hour, time.Minute)
	w.token(t, w.clientID, native)
	browsers := make([]string, 9)
	for i := range browsers {
		browsers[i] = w.session(t, w.browser, time.Duration(9-i)*time.Hour, time.Minute) // oldest first
	}
	if _, _, err := w.svc.checkConcurrentSessions(w.orgCtx, w.user, w.browser); err != nil {
		t.Fatal(err)
	}
	if !w.live(t, native) {
		t.Error("terminate_oldest ended the native session, the oldest row, before any browser session")
	}
	if w.live(t, browsers[0]) {
		t.Error("terminate_oldest did not end the oldest browser session")
	}
}
