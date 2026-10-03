package access

import (
	"net/http"
	"testing"
)

// Section 5.6 of the third-party access framework at the launch approval: an
// external (vendor) user's launch is approved by their sponsor. On the
// migrated schema, through the real handlers:
//
//   - filing the request tells the sponsor, and it is in the sponsor's queue
//     and no one else's;
//   - an administrator who is not the sponsor cannot approve it but can deny
//     it; a user who is not the sponsor cannot decide it on the sponsor's
//     route at all; the sponsor approves it, and the approval opens one launch;
//   - an internal user's launch request is decided by administrators as
//     before, and is not on any sponsor's route.
func TestAnExternalUsersLaunchIsApprovedByTheirSponsor(t *testing.T) {
	f := newExternalPamFixture(t)
	maint := f.entry("maint", "ssh", "ziti", 22, `{}`)
	gated := f.entry("gated", "ssh", "ziti", 22, `{}`)
	f.exec(`UPDATE pam_entries SET require_approval = true WHERE id = $1`, gated)
	otherAdmin := f.scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		f.org, "sl-admin-"+f.suffix)

	ask := func(userID, entryID string) string {
		t.Helper()
		code, body := f.call(userID, http.MethodPost, "/pam/entries/"+entryID+"/request", `{"reason":"patching"}`)
		id, _ := body["request_id"].(string)
		if code != http.StatusCreated || id == "" {
			t.Fatalf("ask for a launch approval: %d %v", code, body)
		}
		return id
	}
	status := func(requestID string) string {
		return f.scalar(`SELECT status FROM pam_entry_access_requests WHERE id = $1`, requestID)
	}
	queued := func(userID, requestID string) bool {
		t.Helper()
		code, body := f.call(userID, http.MethodGet, "/pam/sponsored/entry-requests", "")
		if code != http.StatusOK {
			t.Fatalf("the sponsor's queue: %d %v", code, body)
		}
		requests, _ := body["requests"].([]interface{})
		for _, r := range requests {
			if m, _ := r.(map[string]interface{}); m["id"] == requestID {
				// The queue names who asked, and that they are a vendor user.
				if m["requester"] != f.externalAccount || m["external"] != true {
					t.Errorf("the sponsor's queue names the requester %v (external %v), want %s, external",
						m["requester"], m["external"], f.externalAccount)
				}
				return true
			}
		}
		return false
	}

	request := ask(f.external, maint)
	if n := f.scalar(`SELECT count(*)::text FROM notifications WHERE user_id = $1 AND type = 'sponsored_access'
		AND metadata->>'request_id' = $2`, f.admin, request); n != "1" {
		t.Errorf("the sponsor has %s notifications of the request, want 1", n)
	}
	if !queued(f.admin, request) {
		t.Error("the request is not in the sponsor's queue")
	}
	if queued(otherAdmin, request) || queued(f.operator, request) {
		t.Error("the request is in the queue of someone who does not sponsor its requester")
	}

	if code, body := f.call(otherAdmin, http.MethodPost, "/pam/entry-requests/"+request+"/approve", "{}", "admin"); code != http.StatusForbidden || body["code"] != "external_launch_needs_sponsor" {
		t.Errorf("an administrator who is not the sponsor approves: %d %v, want 403 external_launch_needs_sponsor", code, body)
	}
	if code, body := f.call(f.operator, http.MethodPost, "/pam/sponsored/entry-requests/"+request+"/approve", "{}"); code != http.StatusNotFound {
		t.Errorf("a user who is not the sponsor, on the sponsor's route: %d %v, want 404", code, body)
	}
	if code, body := f.call(f.operator, http.MethodPost, "/pam/sponsored/entry-requests/"+request+"/deny", "{}"); code != http.StatusNotFound {
		t.Errorf("a user who is not the sponsor denies on the sponsor's route: %d %v, want 404", code, body)
	}
	if status(request) != "pending" {
		t.Fatalf("the refused decisions moved the request to %s", status(request))
	}
	if code, body := f.call(f.admin, http.MethodPost, "/pam/sponsored/entry-requests/"+request+"/approve", "{}"); code != http.StatusOK {
		t.Fatalf("the sponsor approves: %d %v, want 200", code, body)
	}
	if status(request) != "approved" || !f.audit.has("pam.access_approved", "success", map[string]interface{}{"request_id": request, "as": "sponsor"}) {
		t.Errorf("the sponsor's approval: status %s, and the audit event names the sponsor: %v", status(request),
			f.audit.has("pam.access_approved", "success", map[string]interface{}{"request_id": request, "as": "sponsor"}))
	}
	if code, body := f.call(f.external, http.MethodPost, "/pam/entries/"+maint+"/connect", "{}"); code != http.StatusOK {
		t.Errorf("the external user's launch on the sponsor's approval: %d %v, want 200", code, body)
	}
	if status(request) != "consumed" {
		t.Errorf("the approval is %s after the launch, want consumed", status(request))
	}

	denied := ask(f.external, maint)
	if code, body := f.call(otherAdmin, http.MethodPost, "/pam/entry-requests/"+denied+"/deny", "{}", "admin"); code != http.StatusOK || status(denied) != "denied" {
		t.Errorf("an administrator denies an external user's request: %d %v, status %s", code, body, status(denied))
	}
	withdrawn := ask(f.external, maint)
	if code, body := f.call(f.admin, http.MethodPost, "/pam/sponsored/entry-requests/"+withdrawn+"/deny", "{}"); code != http.StatusOK || status(withdrawn) != "denied" {
		t.Errorf("the sponsor denies: %d %v, status %s", code, body, status(withdrawn))
	}

	internal := ask(f.operator, gated)
	if n := f.scalar(`SELECT count(*)::text FROM notifications WHERE type = 'sponsored_access' AND metadata->>'request_id' = $1`, internal); n != "0" {
		t.Errorf("an internal user's request notified %s sponsors", n)
	}
	if code, body := f.call(f.admin, http.MethodPost, "/pam/sponsored/entry-requests/"+internal+"/approve", "{}"); code != http.StatusNotFound {
		t.Errorf("an internal user's request on the sponsor's route: %d %v, want 404", code, body)
	}
	if code, body := f.call(otherAdmin, http.MethodPost, "/pam/entry-requests/"+internal+"/approve", "{}", "admin"); code != http.StatusOK || status(internal) != "approved" {
		t.Errorf("an administrator approves an internal user's request: %d %v, status %s", code, body, status(internal))
	}
}
