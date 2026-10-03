package access

import (
	"net/http"
	"strings"
	"testing"
)

// Invariant I6 and section 6.10 of the third-party access framework: when an
// external (vendor) user's privileged session starts, their sponsor is told,
// and the sponsor can watch it read-only and end it. On the migrated schema,
// through the real handlers and a broker that serves the session:
//
//   - the external user's launch notifies the sponsor and stamps the session's
//     sponsor_notified_at; an internal user's launch does neither, and a
//     sponsor who switched the notification type off is not told and the row
//     says so;
//   - the sponsor's list holds their external user's live session and no one
//     else's, and no one else's list holds it;
//   - the sponsor gets a share key minted on the session's own connection as
//     its own broker account; anyone else is told it does not exist;
//   - the sponsor ends it: the broker no longer serves it, the row is ended,
//     and both are audited; a second end finds nothing to end.
func TestTheSponsorIsToldWhenAnExternalSessionStartsAndCanWatchAndEndIt(t *testing.T) {
	f := newExternalPamFixture(t)
	maint := f.entry("maint", "ssh", "ziti", 22, `{}`)
	otherAdmin := f.scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		f.org, "sw-admin-"+f.suffix)

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
	notified := func(sessionID string) string {
		return f.scalar(`SELECT (sponsor_notified_at IS NOT NULL)::text || ' ' ||
			(SELECT count(*) FROM notifications WHERE type = 'sponsored_access' AND metadata->>'session_id' = $1)::text
			FROM pam_entry_sessions WHERE id = $1::uuid`, sessionID)
	}

	session := launch(f.external)
	if got := notified(session); got != "true 1" {
		t.Errorf("the external user's session: stamped and notifications %q, want \"true 1\"", got)
	}
	if n := f.scalar(`SELECT count(*)::text FROM notifications WHERE user_id = $1 AND metadata->>'session_id' = $2`, f.admin, session); n != "1" {
		t.Errorf("the sponsor holds %s notifications of the session, want 1", n)
	}
	internal := launch(f.operator)
	if got := notified(internal); got != "false 0" {
		t.Errorf("an internal user's session: %q, want \"false 0\"", got)
	}

	listed := func(userID, sessionID string) bool {
		t.Helper()
		code, body := f.call(userID, http.MethodGet, "/pam/sponsored/sessions", "")
		if code != http.StatusOK {
			t.Fatalf("the sponsor's sessions as %s: %d %v", userID, code, body)
		}
		sessions, _ := body["sessions"].([]interface{})
		for _, s := range sessions {
			if m, _ := s.(map[string]interface{}); m["id"] == sessionID {
				return m["recorded"] == true
			}
		}
		return false
	}
	if !listed(f.admin, session) {
		t.Error("the sponsor's list does not hold the external user's recorded session")
	}
	if listed(f.admin, internal) || listed(otherAdmin, session) || listed(f.operator, session) {
		t.Error("a sponsor's list holds a session that is not their external user's, or another list holds this one")
	}

	own := f.broker.conn("pam-" + maint + "-x-" + f.external)
	if own == nil {
		t.Fatal("the external session has no connection of its own")
	}
	active := f.broker.serving(own.ID, f.externalAccount)
	for _, who := range []string{otherAdmin, f.operator} {
		if code, body := f.call(who, http.MethodPost, "/pam/sponsored/sessions/"+session+"/watch", "{}", "admin"); code != http.StatusNotFound {
			t.Errorf("watch as someone who does not sponsor the user: %d %v, want 404", code, body)
		}
	}
	code, body := f.call(f.admin, http.MethodPost, "/pam/sponsored/sessions/"+session+"/watch", "{}")
	if url, _ := body["share_url"].(string); code != http.StatusOK || !strings.Contains(url, "key=share-key") || body["read_only"] != true {
		t.Errorf("the sponsor watches: %d %v, want 200 with a read-only share URL", code, body)
	}
	if !f.audit.has("pam.session_watched", "success", map[string]interface{}{"session_id": session, "as": "sponsor"}) {
		t.Error("no pam.session_watched event reached the audit service")
	}

	if code, body := f.call(otherAdmin, http.MethodPost, "/pam/sponsored/sessions/"+session+"/end", "{}", "admin"); code != http.StatusNotFound {
		t.Errorf("end as someone who does not sponsor the user: %d %v, want 404", code, body)
	}
	if !f.broker.isServing(active) {
		t.Fatal("a refused end ended the session")
	}
	if code, body := f.call(f.admin, http.MethodPost, "/pam/sponsored/sessions/"+session+"/end", "{}"); code != http.StatusOK {
		t.Errorf("the sponsor ends the session: %d %v, want 200", code, body)
	}
	if f.broker.isServing(active) {
		t.Error("the broker still serves the session the sponsor ended")
	}
	if got := f.scalar(`SELECT status FROM pam_entry_sessions WHERE id = $1`, session); got != "ended" {
		t.Errorf("the ended session's row is %s", got)
	}
	if !f.audit.has("pam.session_ended", "success", map[string]interface{}{"session_id": session, "reason": "sponsor_ended"}) {
		t.Error("no pam.session_ended event with reason sponsor_ended reached the audit service")
	}
	if code, body := f.call(f.admin, http.MethodPost, "/pam/sponsored/sessions/"+session+"/end", "{}"); code != http.StatusNotFound {
		t.Errorf("ending an ended session: %d %v, want 404", code, body)
	}

	// A sponsor who switched the type off is not told, and the row says so.
	f.exec(`INSERT INTO notification_preferences (user_id, channel, event_type, enabled) VALUES ($1, 'in_app', 'sponsored_access', false)`, f.admin)
	quiet := launch(f.external)
	if got := notified(quiet); got != "false 0" {
		t.Errorf("a session whose sponsor switched the notification off: %q, want \"false 0\"", got)
	}
}
