package access

import (
	"net/http"
	"testing"
)

// An entry whose sessions are recorded is opened only where something
// records: the session broker. The browser terminal and an SSH certificate
// record nothing, and they used to open such an entry for an internal user
// all the same, so the entry's setting promised a recording these sessions
// never had. On the migrated schema, through the handlers:
//
//   - the browser terminal and an SSH certificate refuse a recorded entry
//     (recorded_entry_needs_broker), and the broker still opens it;
//   - an entry that is not recorded opens on the browser terminal's checks
//     as before, and an SSH certificate for a host and principal that a
//     recorded and an unrecorded entry both name is for the unrecorded one.
func TestARecordedEntryOpensOnlyWhereSomethingRecords(t *testing.T) {
	f := newExternalPamFixture(t)
	create := func(name string, recorded bool) string {
		t.Helper()
		rec := "false"
		if recorded {
			rec = "true"
		}
		code, body := f.call(f.admin, http.MethodPost, "/pam/entries",
			`{"name":"`+name+`-`+f.suffix+`","entry_type":"ssh","hostname":"`+name+`.example.test","username":"deploy","record_session":`+rec+`}`, "admin")
		id, _ := body["id"].(string)
		if code != http.StatusCreated || id == "" {
			t.Fatalf("create %s: %d %v", name, code, body)
		}
		f.exec(`UPDATE pam_entries SET reach_mode = 'ziti' WHERE id = $1`, id)
		f.exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1, $2, 'user', $3, '{view,connect}')`, f.org, id, f.operator)
		return id
	}
	recorded := create("rec-db", true)

	// An entry cannot be both recorded and set to open in the browser
	// terminal, nor moderated and set to open there.
	for _, extra := range []string{`"record_session":true`, `"require_moderator":true`} {
		if code, body := f.call(f.admin, http.MethodPost, "/pam/entries",
			`{"name":"term-`+f.suffix+`","entry_type":"ssh","hostname":"term.example.test","username":"deploy","renderer":"wasm-ssh",`+extra+`}`, "admin"); code != http.StatusBadRequest {
			t.Errorf("a browser-terminal entry with %s: %d %v, want 400", extra, code, body)
		}
	}

	if code, body := f.call(f.operator, http.MethodGet, "/pam/entries/"+recorded+"/ws", ""); code != http.StatusForbidden || body["code"] != "recorded_entry_needs_broker" {
		t.Errorf("the browser terminal on a recorded entry: %d %v, want 403 recorded_entry_needs_broker", code, body)
	}
	if code, body := f.call(f.operator, http.MethodPost, "/pam/connect/ssh",
		`{"host":"rec-db.example.test","principal":"deploy"}`); code != http.StatusForbidden || body["code"] != "recorded_entry_needs_broker" {
		t.Errorf("an SSH certificate for a recorded entry: %d %v, want 403 recorded_entry_needs_broker", code, body)
	}
	if !f.audit.has("pam.ssh_cert_denied", "failure", map[string]interface{}{"code": "recorded_entry_needs_broker"}) {
		t.Error("the refused certificate was not audited")
	}
	if code, body := f.call(f.operator, http.MethodPost, "/pam/entries/"+recorded+"/connect", "{}"); code != http.StatusOK {
		t.Errorf("the broker on a recorded entry: %d %v, want 200", code, body)
	}

	plain := create("plain-db", false)
	if code, body := f.call(f.operator, http.MethodGet, "/pam/entries/"+plain+"/ws", ""); body["code"] == "recorded_entry_needs_broker" {
		t.Errorf("the browser terminal refused an unrecorded entry as recorded: %d %v", code, body)
	}

	// A second entry for the recorded entry's host and principal, unrecorded:
	// the certificate is for it.
	twin := create("rec-db-twin", false)
	f.exec(`UPDATE pam_entries SET hostname = 'rec-db.example.test' WHERE id = $1`, twin)
	if code, body := f.call(f.operator, http.MethodPost, "/pam/connect/ssh",
		`{"host":"rec-db.example.test","principal":"deploy"}`); body["code"] == "recorded_entry_needs_broker" {
		t.Errorf("an SSH certificate for a pair an unrecorded entry also names was refused as recorded: %d %v", code, body)
	}
}
