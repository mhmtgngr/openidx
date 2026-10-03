package access

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Section 6.10 of the third-party access framework: moderation, which only a
// route-based Guacamole connection could ask for, holds for PAM entries. On the
// migrated schema, through the real handlers, sweeps and a broker that serves
// the session:
//
//   - an entry requires a moderator through the entry API. An update that
//     leaves the field out keeps it, and an entry that opens no session cannot
//     require one;
//   - its launch answers 428 until a moderator joins. Only a user who may
//     connect can ask for a moderator, and nobody moderates their own session;
//   - one moderation admits one session, which names it. The moderator, and
//     nobody else, watches that session, and their end ends it on the broker;
//   - a moderation that ended without reaching the broker leaves the session
//     to the lifecycle sweep, and so does a moderation the kill switch ended;
//   - an external user's sponsor is told of their request, lists it, and
//     joins it as their moderator, and nobody else's sponsor can;
//   - the browser terminal, an SSH certificate, a temporary access link and
//     the Windows app launch run no unmoderated session on a moderated entry.
func TestAModeratedEntryOpensOnlyWhileItsModeratorWatches(t *testing.T) {
	f := newExternalPamFixture(t)
	sweep := orgctx.WithBypassRLS(context.Background())
	user := func(name string) string {
		return f.scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			f.org, name+"-"+f.suffix)
	}
	bystander, otherAdmin, deputy := user("md-bystander"), user("md-other-admin"), user("md-deputy")

	// The entry API.
	code, body := f.call(f.admin, http.MethodPost, "/pam/entries",
		`{"name":"md-db-`+f.suffix+`","entry_type":"ssh","hostname":"md-db.example.test","username":"deploy","require_moderator":true}`, "admin")
	mod, _ := body["id"].(string)
	if code != http.StatusCreated || mod == "" {
		t.Fatalf("create a moderated entry: %d %v", code, body)
	}
	f.exec(`UPDATE pam_entries SET reach_mode = 'ziti' WHERE id = $1`, mod)
	for _, u := range []string{f.operator, f.external} {
		f.exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1, $2, 'user', $3, '{view,connect}')`, f.org, mod, u)
	}
	required := func() string {
		return f.scalar(`SELECT require_moderator::text FROM pam_entries WHERE id = $1`, mod)
	}
	if code, body := f.call(f.admin, http.MethodPut, "/pam/entries/"+mod,
		`{"name":"md-db-`+f.suffix+`","entry_type":"ssh","hostname":"md-db.example.test","username":"deploy"}`, "admin"); code != http.StatusOK || required() != "true" {
		t.Errorf("an update that leaves require_moderator out: %d %v, and the entry requires a moderator: %s, want true", code, body, required())
	}
	if code, body := f.call(f.admin, http.MethodPost, "/pam/entries",
		`{"name":"md-site-`+f.suffix+`","entry_type":"website","url":"https://md.example.test","require_moderator":true}`, "admin"); code != http.StatusBadRequest {
		t.Errorf("a website entry that requires a moderator: %d %v, want 400", code, body)
	}
	plain := f.entry("md-plain", "ssh", "ziti", 22, `{}`)

	connect := func(userID, entryID string) (int, map[string]interface{}) {
		t.Helper()
		if userID == f.external {
			f.approval(entryID)
		}
		return f.call(userID, http.MethodPost, "/pam/entries/"+entryID+"/connect", "{}")
	}
	ask := func(userID, entryID string) (int, map[string]interface{}) {
		t.Helper()
		return f.call(userID, http.MethodPost, "/pam/moderation/request", fmt.Sprintf(`{"entry_id":%q,"reason":"patching"}`, entryID))
	}
	requested := func(userID string) string {
		t.Helper()
		code, body := ask(userID, mod)
		id, _ := body["id"].(string)
		if code != http.StatusCreated || id == "" {
			t.Fatalf("ask for a moderator as %s: %d %v", userID, code, body)
		}
		return id
	}
	join := func(moderatorID, moderationID string) {
		t.Helper()
		if code, body := f.call(moderatorID, http.MethodPost, "/pam/moderation/"+moderationID+"/join", "{}", "admin"); code != http.StatusOK {
			t.Fatalf("join as %s: %d %v", moderatorID, code, body)
		}
	}
	launched := func(userID string) string {
		t.Helper()
		code, body := connect(userID, mod)
		id, _ := body["session_id"].(string)
		if code != http.StatusOK || id == "" {
			t.Fatalf("launch as %s: %d %v", userID, code, body)
		}
		return id
	}
	status := func(sessionID string) string {
		return f.scalar(`SELECT status FROM pam_entry_sessions WHERE id = $1`, sessionID)
	}
	// served makes the broker serve the session as its own broker account,
	// as a browser that opened the connect URL would.
	served := func(sessionID string) string {
		t.Helper()
		var connID, account string
		if err := f.db.Pool.QueryRow(f.octx(), `SELECT guac_connection_id, guac_username FROM pam_entry_sessions WHERE id = $1`,
			sessionID).Scan(&connID, &account); err != nil {
			t.Fatal(err)
		}
		return f.broker.serving(connID, account)
	}

	// No moderator yet.
	if code, body := connect(f.operator, mod); code != http.StatusPreconditionRequired || body["code"] != "moderation_required" {
		t.Errorf("connect with no moderator: %d %v, want 428 moderation_required", code, body)
	}
	if code, body := ask(bystander, mod); code != http.StatusNotFound {
		t.Errorf("a user who may not connect asks for a moderator: %d %v, want 404", code, body)
	}
	if code, body := ask(f.operator, plain); code != http.StatusConflict || body["code"] != "moderation_not_required" {
		t.Errorf("a moderator for an unmoderated entry: %d %v, want 409 moderation_not_required", code, body)
	}
	first := requested(f.operator)
	if code, body := ask(f.operator, mod); code != http.StatusOK || body["id"] != first || body["reused"] != true {
		t.Errorf("asking again: %d %v, want the same request back", code, body)
	}
	if code, body := f.call(f.admin, http.MethodGet, "/pam/moderation/pending", "", "admin"); code != http.StatusOK ||
		!strings.Contains(fmt.Sprint(body), mod) || !strings.Contains(fmt.Sprint(body), "xp-operator-"+f.suffix) {
		t.Errorf("the administrators' queue does not name the entry and who asked: %d %v", code, body)
	}
	if code, body := f.call(f.operator, http.MethodPost, "/pam/moderation/"+first+"/join", "{}", "admin"); code != http.StatusConflict {
		t.Errorf("the requester moderates their own session: %d %v, want 409", code, body)
	}
	join(f.admin, first)
	// moderating lists what the caller moderates, and whether its session is
	// live yet.
	moderating := func(userID string) string {
		t.Helper()
		code, body := f.call(userID, http.MethodGet, "/pam/moderation/moderating", "")
		if code != http.StatusOK {
			t.Fatalf("the moderations held by %s: %d %v", userID, code, body)
		}
		for _, m := range body["moderations"].([]interface{}) {
			if row := m.(map[string]interface{}); row["id"] == first {
				return fmt.Sprint(row["session_live"])
			}
		}
		return "absent"
	}
	if got := moderating(f.admin); got != "false" {
		t.Errorf("the moderator's list before the launch: %s, want the moderation, not yet live", got)
	}
	if got := moderating(otherAdmin); got != "absent" {
		t.Errorf("someone who does not moderate it lists the moderation: %s", got)
	}

	// One moderation, one session.
	session := launched(f.operator)
	if got := moderating(f.admin); got != "true" {
		t.Errorf("the moderator's list after the launch: %s, want the session live", got)
	}
	if got := f.scalar(`SELECT COALESCE(moderation_id::text, '') FROM pam_entry_sessions WHERE id = $1`, session); got != first {
		t.Errorf("the session names moderation %q, want %q", got, first)
	}
	if code, body := connect(f.operator, mod); code != http.StatusPreconditionRequired {
		t.Errorf("a second launch on a spent moderation: %d %v, want 428", code, body)
	}
	active := served(session)
	if code, body := f.call(otherAdmin, http.MethodPost, "/pam/moderation/"+first+"/watch", "{}", "admin"); code != http.StatusNotFound {
		t.Errorf("an administrator who is not the moderator watches: %d %v, want 404", code, body)
	}
	if code, body := f.call(f.admin, http.MethodPost, "/pam/moderation/"+first+"/watch", "{}", "admin"); code != http.StatusOK || body["read_only"] != true {
		t.Errorf("the moderator watches: %d %v, want a read-only share", code, body)
	}
	if !f.audit.has("pam.session_watched", "success", map[string]interface{}{"session_id": session, "as": "moderator"}) {
		t.Error("the moderator's watch was not audited")
	}
	if code, body := f.call(f.admin, http.MethodPost, "/pam/moderation/"+first+"/end", "{}", "admin"); code != http.StatusOK {
		t.Fatalf("the moderator ends the moderation: %d %v", code, body)
	}
	if f.broker.isServing(active) || status(session) != "ended" {
		t.Errorf("the moderation ended and its session runs on: serving %v, row %s", f.broker.isServing(active), status(session))
	}
	if !f.audit.has("pam.session_ended", "success", map[string]interface{}{"session_id": session, "reason": "moderation_ended"}) {
		t.Error("the session's end was not audited with reason moderation_ended")
	}

	// A moderator who joined longer ago than the wait window admits nothing.
	late := requested(f.operator)
	join(f.admin, late)
	f.exec(`UPDATE guacamole_moderation_sessions SET joined_at = NOW() - INTERVAL '20 minutes' WHERE id = $1`, late)
	if code, body := connect(f.operator, mod); code != http.StatusPreconditionRequired {
		t.Errorf("a launch on a moderation joined 20 minutes ago: %d %v, want 428", code, body)
	}
	f.exec(`UPDATE guacamole_moderation_sessions SET status = 'ended' WHERE id = $1`, late)

	// An end that did not reach the broker: the sweep ends the session.
	second := requested(f.operator)
	join(f.admin, second)
	stranded := launched(f.operator)
	f.exec(`UPDATE guacamole_moderation_sessions SET status = 'ended', ended_at = NOW() WHERE id = $1`, second)
	f.svc.endLapsedPamEntrySessions(sweep)
	if got := status(stranded); got != "ended" {
		t.Errorf("a session whose moderation ended is %s after the sweep, want ended", got)
	}
	// The sweep audits through the unified trail.
	if got := f.scalar(`SELECT COALESCE(string_agg(details->>'reason', ','), '') FROM unified_audit_events
			WHERE event_type = 'pam.session_ended' AND details->>'session_id' = $1`, stranded); got != "moderation_ended" {
		t.Errorf("the sweep audited the session's end with reason %q, want moderation_ended", got)
	}

	// The kill switch on the moderator ends the moderation, and the sweep the
	// session it admitted.
	third := requested(f.operator)
	join(deputy, third)
	watched := launched(f.operator)
	res := f.svc.executeKillSwitch(f.octx(), f.org, deputy, "md-deputy", f.admin, "suspected compromise", false)
	if res.ModerationsEnded != 1 {
		t.Errorf("the kill switch on the moderator ended %d moderations, want 1", res.ModerationsEnded)
	}
	f.svc.endLapsedPamEntrySessions(sweep)
	if got := status(watched); got != "ended" {
		t.Errorf("the session of a severed moderator is %s after the sweep, want ended", got)
	}

	// An external user's sponsor moderates them. Waiting for the moderator
	// spends no approval.
	approval := f.approval(mod)
	if code, body := f.call(f.external, http.MethodPost, "/pam/entries/"+mod+"/connect", "{}"); code != http.StatusPreconditionRequired {
		t.Errorf("an external user's connect with no moderator: %d %v, want 428", code, body)
	}
	if got := f.scalar(`SELECT status FROM pam_entry_access_requests WHERE id = $1`, approval); got != "approved" {
		t.Errorf("waiting for a moderator spent the launch approval: it is %s", got)
	}
	vendorAsk := requested(f.external)
	if n := f.scalar(`SELECT count(*)::text FROM notifications WHERE user_id = $1 AND type = 'sponsored_access'
			AND metadata->>'moderation_id' = $2`, f.admin, vendorAsk); n != "1" {
		t.Errorf("the sponsor holds %s notifications of the moderation request, want 1", n)
	}
	queued := func(userID string) bool {
		t.Helper()
		code, body := f.call(userID, http.MethodGet, "/pam/sponsored/moderation", "")
		if code != http.StatusOK {
			t.Fatalf("the sponsor's moderation queue as %s: %d %v", userID, code, body)
		}
		return strings.Contains(fmt.Sprint(body["pending"]), vendorAsk)
	}
	if !queued(f.admin) || queued(otherAdmin) {
		t.Errorf("the sponsor's queue: sponsor %v, someone else %v; want true, false", queued(f.admin), queued(otherAdmin))
	}
	if code, body := f.call(otherAdmin, http.MethodPost, "/pam/sponsored/moderation/"+vendorAsk+"/join", "{}"); code != http.StatusNotFound {
		t.Errorf("someone who does not sponsor the user joins as their sponsor: %d %v, want 404", code, body)
	}
	if code, body := f.call(f.admin, http.MethodPost, "/pam/sponsored/moderation/"+vendorAsk+"/join", "{}"); code != http.StatusOK {
		t.Fatalf("the sponsor joins: %d %v", code, body)
	}
	if !f.audit.has("pam.moderation.joined", "success", map[string]interface{}{"as": "sponsor"}) {
		t.Error("the sponsor's join was not audited as the sponsor's")
	}
	launched(f.external)

	// The paths that run no session a moderator could watch.
	if code, body := f.call(f.operator, http.MethodGet, "/pam/entries/"+mod+"/ws", ""); code != http.StatusForbidden || body["code"] != "moderated_entry_needs_broker" {
		t.Errorf("the browser terminal on a moderated entry: %d %v, want 403 moderated_entry_needs_broker", code, body)
	}
	if code, body := f.call(f.operator, http.MethodPost, "/pam/connect/ssh",
		`{"host":"md-db.example.test","principal":"deploy"}`); code != http.StatusForbidden || body["code"] != "moderated_entry_needs_broker" {
		t.Errorf("an SSH certificate for a moderated entry: %d %v, want 403 moderated_entry_needs_broker", code, body)
	}
	if code, body := f.call(f.admin, http.MethodPost, "/temp-access",
		fmt.Sprintf(`{"name":"md-link","pam_entry_id":%q,"duration_mins":30}`, mod), "admin"); code != http.StatusBadRequest || body["code"] != "moderated_entry_needs_broker" {
		t.Errorf("a temporary access link to a moderated entry: %d %v, want 400 moderated_entry_needs_broker", code, body)
	}
	host := f.entry("md-apphost", "rdp", "ziti", 3389, `{}`)
	f.exec(`UPDATE pam_entries SET require_moderator = true, require_approval = true WHERE id = $1`, host)
	hostApproval := f.scalar(`INSERT INTO pam_entry_access_requests (org_id, entry_id, requester_id, reason, status, expires_at)
		VALUES ($1, $2, $3, 'maintenance', 'approved', NOW() + interval '1 hour') RETURNING id::text`, f.org, host, f.operator)
	app := f.scalar(`INSERT INTO windows_apps (org_id, host_entry_id, alias, display_name)
		VALUES ($1, $2, 'notepad', 'Notepad') RETURNING id::text`, f.org, host)
	if code, body := f.call(f.operator, http.MethodPost, "/pam/apps/"+app+"/launch", "{}"); code != http.StatusPreconditionRequired || body["code"] != "moderation_required" {
		t.Errorf("an app on a moderated host with no moderator: %d %v, want 428 moderation_required", code, body)
	}
	if got := f.scalar(`SELECT status FROM pam_entry_access_requests WHERE id = $1`, hostApproval); got != "approved" {
		t.Errorf("an app launch waiting for a moderator spent the approval: it is %s", got)
	}
}
