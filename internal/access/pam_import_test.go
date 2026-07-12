package access

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRDMExport(t *testing.T) {
	t.Parallel()

	t.Run("connections wrapper", func(t *testing.T) {
		conns, err := parseRDMExport([]byte(`{"Connections":[{"Name":"a"},{"Name":"b"}]}`))
		if err != nil || len(conns) != 2 {
			t.Fatalf("wrapper parse: %v, %d", err, len(conns))
		}
	})
	t.Run("bare array", func(t *testing.T) {
		conns, err := parseRDMExport([]byte(`[{"Name":"a"}]`))
		if err != nil || len(conns) != 1 {
			t.Fatalf("array parse: %v, %d", err, len(conns))
		}
	})
	t.Run("single object", func(t *testing.T) {
		conns, err := parseRDMExport([]byte(`{"Name":"solo","ConnectionType":"SSHShell"}`))
		if err != nil || len(conns) != 1 {
			t.Fatalf("single parse: %v, %d", err, len(conns))
		}
	})
	t.Run("garbage rejected", func(t *testing.T) {
		if _, err := parseRDMExport([]byte(`not json`)); err == nil {
			t.Fatal("garbage accepted")
		}
	})
	t.Run("empty rejected", func(t *testing.T) {
		if _, err := parseRDMExport([]byte("   ")); err == nil {
			t.Fatal("empty accepted")
		}
	})
}

func TestRDMConnectionTypeMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want string
	}{
		{`{"ConnectionType":"RDPConfigured"}`, "rdp"},
		{`{"ConnectionType":"SSHShell"}`, "ssh"},
		{`{"ConnectionType":"VNC"}`, "vnc"},
		{`{"ConnectionType":"Telnet"}`, "telnet"},
		{`{"ConnectionType":"WebBrowser"}`, "website"},
		{`{"ConnectionType":"Credential"}`, "credential"},
		{`{"ConnectionType":"Group"}`, "group"},
		{`{"ConnectionType":1}`, "rdp"},
		{`{"ConnectionType":77}`, "ssh"},
		{`{"ConnectionType":26}`, "credential"},
		{`{"ConnectionType":25}`, "group"},
		{`{"ConnectionTypeName":"SSHShell"}`, "ssh"},
		// Unknown types must still import (as secure_note) so no RDM data is lost.
		{`{"ConnectionType":"TeamViewer"}`, "secure_note"},
		{`{"ConnectionType":424242}`, "secure_note"},
		{`{}`, "secure_note"},
	}
	for _, tc := range cases {
		var conn map[string]interface{}
		if err := json.Unmarshal([]byte(tc.raw), &conn); err != nil {
			t.Fatalf("bad fixture %s: %v", tc.raw, err)
		}
		if got := rdmConnectionType(conn); got != tc.want {
			t.Fatalf("rdmConnectionType(%s) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestMapRDMConnectionRDP(t *testing.T) {
	t.Parallel()

	raw := `{
		"ConnectionType": "RDPConfigured",
		"Name": "DC01",
		"Group": "Prod\\Domain Controllers",
		"Url": "dc01.corp.local",
		"Description": "primary DC",
		"UserName": "administrator",
		"Domain": "CORP",
		"Password": "Sup3r!"
	}`
	var conn map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &conn); err != nil {
		t.Fatal(err)
	}
	item := mapRDMConnection(conn)
	if item == nil {
		t.Fatal("mapRDMConnection returned nil")
	}
	if item.EntryType != "rdp" || item.Hostname != "dc01.corp.local" || item.Port != 3389 {
		t.Fatalf("rdp mapping wrong: %+v", item)
	}
	if item.Username != "administrator" || item.Domain != "CORP" || item.Secret != "Sup3r!" {
		t.Fatalf("identity mapping wrong: %+v", item)
	}
	if item.FolderPath != "Prod\\Domain Controllers" {
		t.Fatalf("folder path wrong: %q", item.FolderPath)
	}
	// The preserved blob keeps RDM data but never the password.
	b, _ := json.Marshal(item.Preserved)
	if string(b) == "" || strings.Contains(string(b), "Sup3r!") {
		t.Fatalf("preserved blob leaks the password: %s", b)
	}
	if !strings.Contains(string(b), "dc01.corp.local") {
		t.Fatalf("preserved blob lost data: %s", b)
	}
}

func TestMapRDMConnectionSSHNestedTerminal(t *testing.T) {
	t.Parallel()

	raw := `{
		"ConnectionType": "SSHShell",
		"Name": "web-01",
		"Terminal": {"Host": "10.0.0.5", "HostPort": 2222, "UserName": "root"},
		"Password": "pw"
	}`
	var conn map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &conn); err != nil {
		t.Fatal(err)
	}
	item := mapRDMConnection(conn)
	if item.EntryType != "ssh" || item.Hostname != "10.0.0.5" || item.Port != 2222 {
		t.Fatalf("ssh nested mapping wrong: %+v", item)
	}
	if item.Username != "root" {
		t.Fatalf("nested username not found: %+v", item)
	}
}

func TestMapRDMConnectionGroupAndWebsite(t *testing.T) {
	t.Parallel()

	var group map[string]interface{}
	_ = json.Unmarshal([]byte(`{"ConnectionType":"Group","Name":"Servers","Group":"Prod\\Servers"}`), &group)
	item := mapRDMConnection(group)
	if item.EntryType != "group" || item.FolderPath != "Prod\\Servers" {
		t.Fatalf("group mapping wrong: %+v", item)
	}

	// A top-level group carries no Group path — its own name is the path.
	var topGroup map[string]interface{}
	_ = json.Unmarshal([]byte(`{"ConnectionType":"Group","Name":"Prod"}`), &topGroup)
	if item := mapRDMConnection(topGroup); item.FolderPath != "Prod" {
		t.Fatalf("top-level group path wrong: %+v", item)
	}

	var web map[string]interface{}
	_ = json.Unmarshal([]byte(`{"ConnectionType":"WebBrowser","Name":"Grafana","WebBrowserUrl":"https://grafana.corp"}`), &web)
	if item := mapRDMConnection(web); item.EntryType != "website" || item.URL != "https://grafana.corp" {
		t.Fatalf("website mapping wrong: %+v", item)
	}

	// Credential entries keep identity but no host.
	var cred map[string]interface{}
	_ = json.Unmarshal([]byte(`{"ConnectionType":"Credential","Name":"svc-sql","Credentials":{"UserName":"svc-sql","Password":"pw"}}`), &cred)
	item = mapRDMConnection(cred)
	if item.EntryType != "credential" || item.Username != "svc-sql" || item.Secret != "pw" {
		t.Fatalf("credential mapping wrong: %+v", item)
	}

	// Unnamed objects are unimportable.
	if mapRDMConnection(map[string]interface{}{"ConnectionType": "SSHShell"}) != nil {
		t.Fatal("unnamed object should map to nil")
	}
}

// SafePassword is RDM-encrypted ciphertext: it must be neither imported as a
// plaintext secret nor preserved in the settings blob.
func TestMapRDMConnectionSafePasswordNotImported(t *testing.T) {
	t.Parallel()

	var conn map[string]interface{}
	_ = json.Unmarshal([]byte(`{"ConnectionType":"RDPConfigured","Name":"x","Url":"h","SafePassword":"ENCRYPTEDBLOB"}`), &conn)
	item := mapRDMConnection(conn)
	if item.Secret != "" {
		t.Fatalf("SafePassword imported as plaintext: %q", item.Secret)
	}
	b, _ := json.Marshal(item.Preserved)
	if strings.Contains(string(b), "ENCRYPTEDBLOB") {
		t.Fatalf("SafePassword preserved: %s", b)
	}
}

func TestSplitRDMGroupPath(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want int
	}{
		{`Prod\Servers\DB`, 3},
		{`Prod/Servers`, 2},
		{`Prod`, 1},
		{``, 0},
		{`  `, 0},
		{`\\Prod\\`, 1},
	} {
		if got := splitRDMGroupPath(tc.in); len(got) != tc.want {
			t.Fatalf("splitRDMGroupPath(%q) = %v, want %d parts", tc.in, got, tc.want)
		}
	}
}

func TestScrubRDMSecrets(t *testing.T) {
	t.Parallel()

	in := map[string]interface{}{
		"Name":         "x",
		"Password":     "p1",
		"SafePassword": "p2",
		"passwordHint": "p3",
		"Passphrase":   "p4",
		"PrivateKey":   "p5",
		"Nested":       map[string]interface{}{"Password": "p6", "Host": "h"},
		"List":         []interface{}{map[string]interface{}{"password": "p7", "Keep": true}},
	}
	out, ok := scrubRDMSecrets(in).(map[string]interface{})
	if !ok {
		t.Fatal("scrub did not return a map")
	}
	b, _ := json.Marshal(out)
	for _, leaked := range []string{"p1", "p2", "p3", "p4", "p5", "p6", "p7"} {
		if strings.Contains(string(b), leaked) {
			t.Fatalf("scrub leaked %q: %s", leaked, b)
		}
	}
	if !strings.Contains(string(b), `"Host":"h"`) || !strings.Contains(string(b), `"Keep":true`) {
		t.Fatalf("scrub dropped non-secret data: %s", b)
	}
}
