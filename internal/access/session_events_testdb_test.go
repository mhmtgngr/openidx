package access

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/vault"
)

// fakeWebhooks stands in for internal/webhooks and keeps what it was given,
// with the tenancy of the context it was given it under.
type fakeWebhooks struct {
	mu     sync.Mutex
	events []fakeWebhookEvent
}

type fakeWebhookEvent struct {
	Type    string
	Org     string
	Bypass  bool
	Payload map[string]interface{}
}

func (f *fakeWebhooks) Publish(ctx context.Context, eventType string, payload interface{}) error {
	org, _ := orgctx.From(ctx)
	p, _ := payload.(map[string]interface{})
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, fakeWebhookEvent{Type: eventType, Org: org.ID, Bypass: orgctx.IsBypassRLS(ctx), Payload: p})
	return nil
}

// of returns the events of one type whose payload names the session or entry.
func (f *fakeWebhooks) of(eventType, key, id string) []fakeWebhookEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeWebhookEvent
	for _, e := range f.events {
		if e.Type == eventType && e.Payload[key] == id {
			out = append(out, e)
		}
	}
	return out
}

func (f *fakeWebhooks) all() []fakeWebhookEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeWebhookEvent(nil), f.events...)
}

// Section 6.10 of the third-party access framework: the tenant's SIEM hears
// when a privileged session starts, when it ends and why, and when a
// credential is revealed by break-glass. On the migrated schema, through the
// real handlers, sweeps and stand-in broker:
//
//   - a launch publishes pam.session.started, saying whether the user is
//     external and whether the session is recorded;
//   - every path that ends a session publishes pam.session.ended once, with
//     its reason, and with who when someone asked: the sponsor, the user, the
//     kill switch, a disabled account, an external session's maximum length,
//     the risk scorer, a closed browser terminal;
//   - an end that is refused publishes nothing, and a Windows app launch's
//     replace ends only the caller's own session;
//   - break-glass publishes pam.break_glass with its justification;
//   - every event is published under the session's own organization and no
//     row-level-security bypass, the sweeps' included.
func TestPrivilegedSessionsArePublishedToTheTenantsSubscribers(t *testing.T) {
	f := newExternalPamFixture(t)
	hooks := &fakeWebhooks{}
	f.svc.webhooks = hooks
	maint := f.entry("maint", "ssh", "ziti", 22, `{}`)
	user := func(name string) string {
		t.Helper()
		id := f.scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			f.org, name+"-"+f.suffix)
		f.exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1, $2, 'user', $3, '{view,connect}')`, f.org, maint, id)
		return id
	}
	// The kill switch expires its target's grants, and the disabled-account
	// step disables one, so each has a user of its own.
	bystander, victim, leaver := user("ev-bystander"), user("ev-victim"), user("ev-leaver")
	sweep := orgctx.WithBypassRLS(context.Background())

	launch := func(userID string) string {
		t.Helper()
		if userID == f.external {
			f.approval(maint)
		}
		code, body := f.call(userID, http.MethodPost, "/pam/entries/"+maint+"/connect", "{}")
		id, _ := body["session_id"].(string)
		if code != http.StatusOK || id == "" {
			t.Fatalf("launch as %s: %d %v", userID, code, body)
		}
		return id
	}
	// endedOnce checks the one pam.session.ended event of a session.
	endedOnce := func(sessionID, reason, actor string) {
		t.Helper()
		got := hooks.of("pam.session.ended", "session_id", sessionID)
		if len(got) != 1 {
			t.Errorf("pam.session.ended published %d times for the %s session, want 1", len(got), reason)
			return
		}
		p := got[0].Payload
		if p["reason"] != reason || p["entry_id"] != maint || p["ended_at"] == nil {
			t.Errorf("pam.session.ended for the %s session carries %v", reason, p)
		}
		if a, _ := p["actor_id"].(string); a != actor {
			t.Errorf("pam.session.ended for the %s session names actor %q, want %q", reason, a, actor)
		}
	}
	endOwn := func(userID, sessionID string) int {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
			c.Set("user_id", userID)
			c.Set("roles", []string{})
			c.Next()
		})
		r.POST("/pam/sessions/:id/end", f.svc.handlePamEndSession)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/pam/sessions/"+sessionID+"/end", strings.NewReader("{}")))
		return w.Code
	}

	// Started: who, and whether it is recorded.
	external := launch(f.external)
	if got := hooks.of("pam.session.started", "session_id", external); len(got) != 1 {
		t.Fatalf("pam.session.started published %d times for the external session, want 1", len(got))
	} else if p := got[0].Payload; p["external"] != true || p["recorded"] != true || p["user_id"] != f.external || p["entry_id"] != maint {
		t.Errorf("pam.session.started for the external session carries %v, want an external, recorded session", p)
	}
	internal := launch(f.operator)
	if got := hooks.of("pam.session.started", "session_id", internal); len(got) != 1 {
		t.Fatalf("pam.session.started published %d times for the internal session, want 1", len(got))
	} else if p := got[0].Payload; p["external"] != false || p["recorded"] != false || p["user_id"] != f.operator {
		t.Errorf("pam.session.started for the internal session carries %v, want an internal session the entry does not record", p)
	}

	// Ended by the sponsor.
	if code, body := f.call(f.admin, http.MethodPost, "/pam/sponsored/sessions/"+external+"/end", "{}"); code != http.StatusOK {
		t.Fatalf("the sponsor ends the session: %d %v", code, body)
	}
	endedOnce(external, "sponsor_ended", f.admin)
	if p := hooks.of("pam.session.ended", "session_id", external); len(p) == 1 && p[0].Payload["external"] != true {
		t.Errorf("pam.session.ended for the external session does not say it was external: %v", p[0].Payload)
	}

	// Ended by its user; another user's attempt ends nothing and says nothing.
	if code := endOwn(bystander, internal); code != http.StatusNotFound {
		t.Errorf("another user ends the session: %d, want 404", code)
	}
	if n := len(hooks.of("pam.session.ended", "session_id", internal)); n != 0 {
		t.Errorf("a refused end published %d events", n)
	}
	if code := endOwn(f.operator, internal); code != http.StatusOK {
		t.Fatalf("the user ends their session: %d", code)
	}
	endedOnce(internal, "ended", f.operator)

	// Ended by the kill switch.
	killed := launch(victim)
	f.svc.executeKillSwitch(f.octx(), f.org, victim, "ev-victim", f.admin, "suspected compromise", false)
	endedOnce(killed, "kill_switch", f.admin)

	// Ended because the account was disabled.
	disabled := launch(leaver)
	f.exec(`UPDATE users SET enabled = false WHERE id = $1`, leaver)
	f.svc.endPamEntrySessionsOfDisabledUsers(sweep)
	endedOnce(disabled, "account_disabled", "")

	// Ended at an external session's maximum length.
	long := launch(f.external)
	f.exec(`UPDATE pam_entry_sessions SET started_at = NOW() - INTERVAL '9 hours' WHERE id = $1`, long)
	f.svc.endLapsedPamEntrySessions(sweep)
	endedOnce(long, "max_duration", "")

	// Ended by a closed browser terminal, once.
	terminal := f.scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol)
		VALUES ($1, $2, $3, 'ssh') RETURNING id::text`, f.org, maint, f.operator)
	f.svc.endPamTerminalRow(f.org, terminal)
	f.svc.endPamTerminalRow(f.org, terminal)
	endedOnce(terminal, "closed", "")

	// Suspended by the risk scorer. It is the only live session now, so the
	// scorer, which scores every live session, judges this one alone.
	risky := launch(f.operator)
	f.exec(`UPDATE pam_entry_sessions SET started_at = NOW() - INTERVAL '5 hours' WHERE id = $1`, risky)
	if live := f.scalar(`SELECT count(*)::text FROM pam_entry_sessions WHERE status = 'active'`); live != "1" {
		t.Fatalf("%s live sessions before the risk scorer runs, want 1", live)
	}
	NewPAMSessionRiskScorer(f.svc, time.Minute, "enforce", 20, zap.NewNop()).scoreActiveSessions(sweep)
	endedOnce(risky, "risk_suspended", "")

	// A Windows app launch's replace ends the caller's own session only.
	host := f.entry("apphost", "rdp", "ziti", 3389, `{}`)
	app := f.scalar(`INSERT INTO windows_apps (org_id, host_entry_id, alias, display_name)
		VALUES ($1, $2, 'notepad', 'Notepad') RETURNING id::text`, f.org, host)
	replaced := launch(f.operator)
	f.call(bystander, http.MethodPost, "/pam/apps/"+app+"/launch?replace="+replaced, "{}")
	if got := f.scalar(`SELECT status FROM pam_entry_sessions WHERE id = $1`, replaced); got != "active" {
		t.Errorf("another user's app launch replaced the session: it is %s", got)
	}
	if n := len(hooks.of("pam.session.ended", "session_id", replaced)); n != 0 {
		t.Errorf("a refused replace published %d events", n)
	}
	f.call(f.operator, http.MethodPost, "/pam/apps/"+app+"/launch?replace="+replaced, "{}")
	if got := f.scalar(`SELECT status FROM pam_entry_sessions WHERE id = $1`, replaced); got != "ended" {
		t.Errorf("the user's own replace left the session %s", got)
	}
	endedOnce(replaced, "ended", f.operator)

	// Break-glass.
	ring, err := vault.KeyringFromConfig(vault.KeyConfig{
		KEK: base64.StdEncoding.EncodeToString([]byte("session-events-test-kek-01234567")),
	})
	if err != nil {
		t.Fatalf("vault keyring: %v", err)
	}
	vaultSvc, err := vault.NewService(f.db, ring, nil, time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("vault service: %v", err)
	}
	f.svc.SetVaultService(vaultSvc)
	secret, err := vaultSvc.Store(f.octx(), vault.StoreInput{
		Name: "maint-root-" + f.suffix, Type: "password", CreatedBy: f.admin, OwnerID: f.admin, Value: []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("store the entry's secret: %v", err)
	}
	f.exec(`UPDATE pam_entries SET vault_secret_id = $1 WHERE id = $2`, secret.ID, maint)
	const why = "production is down and the operator account is locked"
	if code, body := f.call(f.operator, http.MethodPost, "/pam/entries/"+maint+"/break-glass", `{"reason":"`+why+`"}`); code != http.StatusOK {
		t.Fatalf("break-glass: %d %v", code, body)
	}
	if got := hooks.of("pam.break_glass", "entry_id", maint); len(got) != 1 {
		t.Errorf("pam.break_glass published %d times, want 1", len(got))
	} else if p := got[0].Payload; p["user_id"] != f.operator || p["reason"] != why || p["entry_name"] != "maint-"+f.suffix {
		t.Errorf("pam.break_glass carries %v", p)
	}

	// A launch request's requester is told what was decided.
	gated := f.entry("gated", "ssh", "ziti", 22, `{}`)
	f.exec(`UPDATE pam_entries SET require_approval = true WHERE id = $1`, gated)
	ask := func(userID string) string {
		t.Helper()
		code, body := f.call(userID, http.MethodPost, "/pam/entries/"+gated+"/request", `{"reason":"patching"}`)
		id, _ := body["request_id"].(string)
		if code != http.StatusCreated || id == "" {
			t.Fatalf("ask for a launch approval as %s: %d %v", userID, code, body)
		}
		return id
	}
	toldOf := func(userID, requestID, kind string) string {
		return f.scalar(`SELECT count(*)::text FROM notifications
			 WHERE user_id = $1 AND type = 'request_update' AND metadata->>'request_id' = $2 AND metadata->>'kind' = $3`,
			userID, requestID, kind)
	}
	approved := ask(f.external)
	if n := toldOf(f.external, approved, "launch_approved"); n != "0" {
		t.Errorf("the requester was told of a decision before it was made: %s notifications", n)
	}
	if code, body := f.call(f.admin, http.MethodPost, "/pam/sponsored/entry-requests/"+approved+"/approve", "{}"); code != http.StatusOK {
		t.Fatalf("the sponsor approves: %d %v", code, body)
	}
	if n := toldOf(f.external, approved, "launch_approved"); n != "1" {
		t.Errorf("the requester holds %s launch_approved notifications, want 1", n)
	}
	denied := ask(f.operator)
	if code, body := f.call(f.admin, http.MethodPost, "/pam/entry-requests/"+denied+"/deny", "{}", "admin"); code != http.StatusOK {
		t.Fatalf("an administrator denies: %d %v", code, body)
	}
	if n := toldOf(f.operator, denied, "launch_denied"); n != "1" {
		t.Errorf("the requester holds %s launch_denied notifications, want 1", n)
	}

	// Every event went to this organization's subscribers, and no bypass.
	for _, e := range hooks.all() {
		if e.Org != f.org || e.Bypass {
			t.Errorf("%s published under org %q (bypass %v), want %s and no bypass", e.Type, e.Org, e.Bypass, f.org)
		}
	}
}
