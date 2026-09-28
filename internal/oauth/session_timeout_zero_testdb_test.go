package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// A TIMEOUT OF ZERO TURNS IT OFF.
//
// The Security tab documents the idle and absolute timeouts as "0 = disabled",
// the sweep skips a timeout of zero, and so does the console's idle lock. The
// session policy read zero as "not set" and served the 30-minute and 24-hour
// defaults in its place, to the sweep and to /oauth/session-info alike. Driven
// through the settings document the policy reads (system_settings, key
// 'system'), the sweep processExpiredSessions runs, and /oauth/session-info
// through the route table cmd/oauth-service serves:
//
//   - a document without the keys, as seeded, keeps the defaults: the sweep
//     ends a session idle for two hours and one signed in 25 hours ago, and
//     keeps a session idle for ten minutes;
//   - zero turns each timeout off: session-info answers 0, and the sweep ends
//     neither the idle session nor the old one;
//   - other values apply as set: at an hour's idle timeout a session idle for
//     45 minutes stays and one idle for two hours ends;
//   - per application, a zero idle timeout is off and NULL inherits.
func TestATimeoutOfZeroTurnsItOff(t *testing.T) {
	h := newTokenHarness(t)
	sweepCtx := orgctx.WithBypassRLS(context.Background())
	org := h.seedOrg("timeout")
	user := h.seedUser(org.ID, "timeout-user")
	client := h.consoleClient(org)
	api := h.oauthRouteTable(nil)
	token := h.tokenFor(org, user, client)

	setTimeouts := func(idle, absolute interface{}) {
		t.Helper()
		h.exec(`UPDATE system_settings SET value = value #- '{security,idle_timeout}' #- '{security,absolute_timeout}' WHERE key = 'system'`)
		for key, v := range map[string]interface{}{"idle_timeout": idle, "absolute_timeout": absolute} {
			if v != nil {
				h.exec(`UPDATE system_settings SET value = jsonb_set(value, ARRAY['security', $1::text], to_jsonb($2::int)) WHERE key = 'system'`, key, v)
			}
		}
	}
	session := func(idle, age time.Duration) string {
		t.Helper()
		id := uuid.NewString()
		h.exec(`INSERT INTO sessions (id, user_id, client_id, started_at, last_seen_at, expires_at, org_id)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, NOW() + interval '1 hour', $6::uuid)`,
			id, user, client, time.Now().Add(-age), time.Now().Add(-idle), org.ID)
		return id
	}
	live := func(id string) bool {
		return h.scalar(`SELECT (NOT COALESCE(revoked, false))::text FROM sessions WHERE id = $1::uuid`, id) == "true"
	}
	info := func() (idle, absolute float64) {
		t.Helper()
		w := serve(api, http.MethodGet, "/oauth/session-info", "", "", "Authorization", "Bearer "+token, "X-Org-Slug", org.Slug)
		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
			t.Fatalf("session-info: %d %s", w.Code, w.Body.String())
		}
		idle, _ = body["idle_timeout"].(float64)
		absolute, _ = body["absolute_timeout"].(float64)
		return idle, absolute
	}
	type expect struct {
		name  string
		idle  time.Duration
		age   time.Duration
		lives bool
	}
	sweepAndCheck := func(cases []expect) {
		t.Helper()
		ids := make([]string, len(cases))
		for i, c := range cases {
			ids[i] = session(c.idle, c.age)
		}
		h.issuer.processExpiredSessions(sweepCtx)
		for i, c := range cases {
			if got := live(ids[i]); got != c.lives {
				t.Errorf("%s: live after the sweep = %v, want %v", c.name, got, c.lives)
			}
		}
	}

	t.Run("not set: the defaults", func(t *testing.T) {
		setTimeouts(nil, nil)
		if idle, absolute := info(); idle != 1800 || absolute != 86400 {
			t.Errorf("session-info %v / %v, want the defaults 1800 / 86400", idle, absolute)
		}
		sweepAndCheck([]expect{
			{"idle for two hours", 2 * time.Hour, 3 * time.Hour, false},
			{"signed in 25 hours ago, active", time.Minute, 25 * time.Hour, false},
			{"idle for ten minutes", 10 * time.Minute, time.Hour, true},
		})
	})
	t.Run("zero: off", func(t *testing.T) {
		setTimeouts(0, 0)
		if idle, absolute := info(); idle != 0 || absolute != 0 {
			t.Errorf("session-info %v / %v, want 0 / 0", idle, absolute)
		}
		sweepAndCheck([]expect{
			{"idle for two hours", 2 * time.Hour, 3 * time.Hour, true},
			{"signed in 25 hours ago, active", time.Minute, 25 * time.Hour, true},
		})
	})
	t.Run("a value: as set", func(t *testing.T) {
		setTimeouts(3600, 2*86400)
		if idle, absolute := info(); idle != 3600 || absolute != 2*86400 {
			t.Errorf("session-info %v / %v, want 3600 / 172800", idle, absolute)
		}
		sweepAndCheck([]expect{
			{"idle for 45 minutes", 45 * time.Minute, time.Hour, true},
			{"idle for two hours", 2 * time.Hour, 3 * time.Hour, false},
			{"signed in 25 hours ago, active", time.Minute, 25 * time.Hour, true},
			{"signed in 49 hours ago, active", time.Minute, 49 * time.Hour, false},
		})
	})
	t.Run("per application: zero is off, NULL inherits", func(t *testing.T) {
		setTimeouts(3600, nil)
		app := h.scalar(`INSERT INTO applications (client_id, name, type, org_id) VALUES ($1, $1, 'web', $2::uuid) RETURNING id::text`, client, org.ID)
		h.exec(`INSERT INTO application_sso_settings (application_id, idle_timeout, absolute_timeout, org_id)
			VALUES ($1::uuid, 0, NULL, $2::uuid)`, app, org.ID)
		if idle, absolute := info(); idle != 0 || absolute != 86400 {
			t.Errorf("session-info %v / %v, want the application's 0 and the inherited default 86400", idle, absolute)
		}
		h.exec(`UPDATE application_sso_settings SET idle_timeout = NULL WHERE application_id = $1::uuid`, app)
		if idle, _ := info(); idle != 3600 {
			t.Errorf("session-info idle %v, want the inherited 3600", idle)
		}
	})
}
