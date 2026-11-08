package access

import (
	"net/http"
	"strings"
	"testing"
)

// The session policy (v239) end to end through the entry routes and the
// launch: what an administrator sets is what the broker connection carries,
// a stored setting cannot override it, an editor may tighten it and not
// loosen it, a client that leaves the fields out keeps them, and every
// change is audited.
func TestPamSessionPolicyReachesTheBroker(t *testing.T) {
	f := newExternalPamFixture(t)
	const fp = "sha256:eb:45:51:d6:9b:99:39:35:3d:29:f3:49:1b:39:75:8b:fc:2e:c0:83:5b:69:0b:c3:60:c6:65:cc:88:24:85:1b"

	// Settings that try to open everything the policy owns.
	code, body := f.call(f.admin, http.MethodPost, "/pam/entries", `{"name":"policy-rdp-`+f.suffix+`",
		"entry_type":"rdp","hostname":"rdp.example.test","username":"deploy",
		"settings":{"ignore-cert":"true","security":"any","enable-drive":"true","drive-path":"/etc","disable-copy":"false"}}`, "admin")
	entry, _ := body["id"].(string)
	if code != http.StatusCreated || entry == "" {
		t.Fatalf("create: %d %v", code, body)
	}
	f.exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		VALUES ($1, $2, 'user', $3, '{view,connect,edit}')`, f.org, entry, f.operator)

	get := func() map[string]interface{} {
		t.Helper()
		code, body := f.call(f.admin, http.MethodGet, "/pam/entries/"+entry, "", "admin")
		if code != http.StatusOK {
			t.Fatalf("get: %d %v", code, body)
		}
		if e, ok := body["entry"].(map[string]interface{}); ok {
			return e
		}
		return body
	}
	connect := func() map[string]string {
		t.Helper()
		code, body := f.call(f.operator, http.MethodPost, "/pam/entries/"+entry+"/connect", "{}")
		if code != http.StatusOK {
			t.Fatalf("connect: %d %v", code, body)
		}
		c := f.broker.conn("pam-" + entry)
		if c == nil {
			t.Fatal("no broker connection")
		}
		return c.Params
	}
	update := func(userID, policyJSON string, roles ...string) (int, map[string]interface{}) {
		body := `{"name":"policy-rdp-` + f.suffix + `","entry_type":"rdp","hostname":"rdp.example.test","username":"deploy",
			"settings":{"ignore-cert":"true","security":"any","enable-drive":"true","drive-path":"/etc","disable-copy":"false"}`
		if policyJSON != "" {
			body += "," + policyJSON
		}
		return f.call(userID, http.MethodPut, "/pam/entries/"+entry, body+"}", roles...)
	}

	t.Run("a new entry verifies the certificate, keeps the clipboard and has no file transfer", func(t *testing.T) {
		e := get()
		if e["rdp_cert_mode"] != "verify" || e["allow_copy"] != true || e["allow_paste"] != true || e["allow_file_transfer"] != false {
			t.Fatalf("entry = %v", e)
		}
		p := connect()
		if _, ok := p["ignore-cert"]; ok {
			t.Errorf("the settings' ignore-cert reached the broker: %v", p)
		}
		if p["security"] != "nla" {
			t.Errorf("security = %q, want nla (the settings' any would skip the check)", p["security"])
		}
		if p["enable-drive"] != "false" || p["disable-copy"] != "false" || p["disable-paste"] != "false" {
			t.Errorf("channels = drive %q copy-off %q paste-off %q", p["enable-drive"], p["disable-copy"], p["disable-paste"])
		}
		if _, ok := p["drive-path"]; ok {
			t.Errorf("the settings' drive-path reached the broker")
		}
	})

	t.Run("an editor tightens, and cannot loosen", func(t *testing.T) {
		if code, body := update(f.operator, `"allow_copy":false`); code != http.StatusOK {
			t.Fatalf("editor closes copy: %d %v", code, body)
		}
		if !f.audit.has("pam.entry_policy_changed", "success", map[string]interface{}{"loosened": false}) {
			t.Error("tightening was not audited")
		}
		for name, pol := range map[string]string{
			"ignore":        `"rdp_cert_mode":"ignore"`,
			"pin":           `"rdp_cert_mode":"pin","rdp_cert_fingerprints":["` + fp + `"]`,
			"copy back":     `"allow_copy":true`,
			"file transfer": `"allow_file_transfer":true`,
		} {
			code, body := update(f.operator, pol)
			if code != http.StatusForbidden || body["code"] != "session_policy_admin_only" {
				t.Errorf("editor %s: %d %v, want 403 session_policy_admin_only", name, code, body)
			}
		}
		if get()["allow_copy"] != false {
			t.Error("a refused update changed the entry")
		}
	})

	t.Run("a client that leaves the fields out keeps them", func(t *testing.T) {
		if code, body := update(f.admin, `"rdp_cert_mode":"pin","rdp_cert_fingerprints":["`+strings.ToUpper(fp)+`"],"allow_file_transfer":true`, "admin"); code != http.StatusOK {
			t.Fatalf("admin pins: %d %v", code, body)
		}
		if !f.audit.has("pam.entry_policy_changed", "success", map[string]interface{}{"loosened": true}) {
			t.Error("loosening was not audited")
		}
		if code, body := update(f.operator, ""); code != http.StatusOK {
			t.Fatalf("editor saves an old form: %d %v", code, body)
		}
		e := get()
		fps, _ := e["rdp_cert_fingerprints"].([]interface{})
		if e["rdp_cert_mode"] != "pin" || len(fps) != 1 || fps[0] != fp || e["allow_file_transfer"] != true || e["allow_copy"] != false {
			t.Fatalf("after an old form's save: %v", e)
		}
		p := connect()
		if p["cert-fingerprints"] != fp || p["security"] != "nla" {
			t.Errorf("pinned: cert-fingerprints %q security %q", p["cert-fingerprints"], p["security"])
		}
		if p["enable-drive"] != "true" || !strings.HasPrefix(p["drive-path"], "/tmp/guac-drive/") {
			t.Errorf("file transfer: enable-drive %q drive-path %q", p["enable-drive"], p["drive-path"])
		}
		if p["disable-copy"] != "true" {
			t.Errorf("copy was closed and the session has disable-copy %q", p["disable-copy"])
		}
	})

	t.Run("ignore, set by an administrator, is what reaches the broker", func(t *testing.T) {
		if code, body := update(f.admin, `"rdp_cert_mode":"ignore"`, "admin"); code != http.StatusOK {
			t.Fatalf("admin ignores: %d %v", code, body)
		}
		p := connect()
		if p["ignore-cert"] != "true" {
			t.Errorf("ignore-cert = %q", p["ignore-cert"])
		}
		if _, ok := p["cert-fingerprints"]; ok {
			t.Error("an ignore entry still sends its old pin")
		}
	})

	t.Run("bad input is refused", func(t *testing.T) {
		for name, pol := range map[string]string{
			"unknown mode":  `"rdp_cert_mode":"trust"`,
			"pin with none": `"rdp_cert_mode":"pin","rdp_cert_fingerprints":[]`,
			"sha1":          `"rdp_cert_mode":"pin","rdp_cert_fingerprints":["sha1:aa:bb:cc"]`,
		} {
			if code, body := update(f.admin, pol, "admin"); code != http.StatusBadRequest {
				t.Errorf("%s: %d %v, want 400", name, code, body)
			}
		}
	})
}
