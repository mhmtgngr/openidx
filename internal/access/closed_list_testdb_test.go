package access

import (
	"net/http"
	"testing"
)

// Invariant I11 of the third-party access framework at the PAM launch paths
// and the lists, on the migrated schema and through the real handlers: an
// external user whose vendor is on a closed list launches, and is shown, only
// the entries opened to the vendor, whatever grant they hold. An internal
// user with the same grants is held to no list.
func TestAnExternalUserOnAClosedListLaunchesOnlyWhatIsOpen(t *testing.T) {
	f := newExternalPamFixture(t)
	opened := f.entry("opened", "ssh", "ziti", 22, `{}`)
	closed := f.entry("closed", "ssh", "ziti", 22, `{}`)
	vendor := f.scalar(`SELECT vendor_org_id::text FROM users WHERE id = $1`, f.external)
	f.exec(`UPDATE vendor_organizations SET closed_list = true WHERE id = $1`, vendor)
	f.exec(`INSERT INTO vendor_org_targets (org_id, vendor_org_id, target_type, target_id) VALUES ($1, $2, 'pam_entry', $3)`,
		f.org, vendor, opened)

	connect := func(userID, entryID string) (int, map[string]interface{}) {
		t.Helper()
		return f.call(userID, http.MethodPost, "/pam/entries/"+entryID+"/connect", "{}")
	}
	if code, body := connect(f.external, closed); code != http.StatusForbidden || body["code"] != "external_target_not_open" {
		t.Errorf("an external user launches an entry not open to their vendor: %d %v, want 403 external_target_not_open", code, body)
	}
	if code, body := connect(f.external, opened); code != http.StatusForbidden || body["approval_required"] != true {
		t.Errorf("an external user launches an entry open to their vendor: %d %v, want the launch approval asked next", code, body)
	}
	if code, body := connect(f.operator, closed); code != http.StatusOK {
		t.Errorf("an internal user launches the same entry: %d %v, want 200", code, body)
	}
	if !f.audit.has("pam.launch_denied", "failure", map[string]interface{}{"code": "external_target_not_open", "entry_id": closed}) {
		t.Error("no pam.launch_denied event for the closed entry reached the audit service")
	}

	listed := func(userID string) map[string]bool {
		t.Helper()
		code, body := f.call(userID, http.MethodGet, "/pam/entries", "")
		if code != http.StatusOK {
			t.Fatalf("list as %s: %d %v", userID, code, body)
		}
		out := map[string]bool{}
		entries, _ := body["entries"].([]interface{})
		for _, e := range entries {
			if m, _ := e.(map[string]interface{}); m != nil {
				id, _ := m["id"].(string)
				out[id] = true
			}
		}
		return out
	}
	if seen := listed(f.external); !seen[opened] || seen[closed] {
		t.Errorf("the list shows an external user opened=%v closed=%v, want only the opened entry", seen[opened], seen[closed])
	}
	if seen := listed(f.operator); !seen[opened] || !seen[closed] {
		t.Errorf("the list shows an internal user opened=%v closed=%v, want both", seen[opened], seen[closed])
	}
	if code, _ := f.call(f.external, http.MethodGet, "/pam/entries/"+closed, ""); code != http.StatusNotFound {
		t.Errorf("an external user reads an entry not open to their vendor: %d, want 404", code)
	}
	if code, _ := f.call(f.external, http.MethodGet, "/pam/entries/"+opened, ""); code != http.StatusOK {
		t.Errorf("an external user reads an entry open to their vendor: %d, want 200", code)
	}

	// My Privileged Access lists a route-backed entry only when it is open.
	route := f.scalar(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled)
		VALUES ($1, $2, $3, 'ssh://198.51.100.9:22', true) RETURNING id::text`,
		f.org, "cl-bastion-"+f.suffix, "https://cl-bastion-"+f.suffix+".example.test")
	f.exec(`INSERT INTO guacamole_connections (route_id, org_id, guacamole_connection_id, protocol, hostname, port, require_approval, record_session)
		VALUES ($1, $2, $3, 'ssh', '198.51.100.9', 22, false, false)`, route, f.org, "guac-cl-"+f.suffix)
	routeEntry := f.scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port, proxy_route_id)
		VALUES ($1, $2, 'ssh', '198.51.100.9', 22, $3) RETURNING id::text`, f.org, "cl-bastion-"+f.suffix, route)
	for _, u := range []string{f.operator, f.external} {
		f.exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1, $2, 'user', $3, '{connect}')`, f.org, routeEntry, u)
	}
	routeListed := func(userID string) bool {
		t.Helper()
		_, body := f.call(userID, http.MethodGet, "/guacamole/my-connections", "")
		conns, _ := body["connections"].([]interface{})
		for _, c := range conns {
			if m, _ := c.(map[string]interface{}); m["route_id"] == route {
				return true
			}
		}
		return false
	}
	if routeListed(f.external) || !routeListed(f.operator) {
		t.Errorf("My Privileged Access lists a route not open to the vendor: external %v, internal %v; want false, true",
			routeListed(f.external), routeListed(f.operator))
	}

	host := f.entry("apphost", "rdp", "ziti", 3389, `{}`)
	app := f.scalar(`INSERT INTO windows_apps (org_id, host_entry_id, alias, display_name)
		VALUES ($1, $2, 'notepad', 'Notepad') RETURNING id::text`, f.org, host)
	if code, body := f.call(f.external, http.MethodPost, "/pam/apps/"+app+"/launch", "{}"); code != http.StatusForbidden || body["code"] != "external_target_not_open" {
		t.Errorf("an external user's app on a host not open to their vendor: %d %v, want 403 external_target_not_open", code, body)
	}

	// With the list off, nothing is hidden or refused for it.
	f.exec(`UPDATE vendor_organizations SET closed_list = false WHERE id = $1`, vendor)
	if code, body := connect(f.external, closed); code != http.StatusForbidden || body["approval_required"] != true {
		t.Errorf("with the list off, an external user launches the entry: %d %v, want the launch approval asked next", code, body)
	}
	if seen := listed(f.external); !seen[closed] {
		t.Error("with the list off, the list hides an entry from an external user")
	}
}
