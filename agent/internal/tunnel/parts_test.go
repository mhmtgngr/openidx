package tunnel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseIPCStatus(t *testing.T) {
	cases := []struct {
		name, out string
		state     State
		detail    string
		wantErr   bool
	}{
		{name: "healthy", out: healthyStatus, state: StateConnected},
		{name: "inactive tunnel", state: StateDegraded, detail: "inactive",
			out: `{"Success":true,"Data":{"Active":false,"Identities":[{"Name":"d","Active":true,"Loaded":true}]}}`},
		{name: "no identities", state: StateDegraded, detail: "no identity",
			out: `{"Success":true,"Data":{"Active":true,"Identities":[]}}`},
		{name: "identity not loaded", state: StateDegraded, detail: "not loaded",
			out: `{"Success":true,"Data":{"Active":true,"Identities":[{"Name":"d","Active":true,"Loaded":false}]}}`},
		{name: "mfa needed", state: StateDegraded, detail: "authentication",
			out: `{"Success":true,"Data":{"Active":true,"Identities":[{"Name":"d","Active":true,"Loaded":true,"MfaNeeded":true}]}}`},
		{name: "refused", wantErr: true, out: `{"Success":false,"Code":500,"Error":"boom"}`},
		{name: "not json", wantErr: true, out: `cmd socket connect: No such file or directory`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := parseIPCStatus([]byte(c.out))
			if c.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %+v", r)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.State != c.state || !strings.Contains(r.Detail, c.detail) {
				t.Errorf("got %q / %q, want %q / ...%q...", r.State, r.Detail, c.state, c.detail)
			}
		})
	}
}

func TestProvisionIdentityCopiesOnceAndRemovesStaleOnes(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "ziti-identity.json")
	idDir := filepath.Join(dir, "ids")
	writeFile(t, src, `{"ztAPI":"https://c","id":{}}`)
	writeFile(t, filepath.Join(idDir, "dev-old-agent.json"), `{}`)
	writeFile(t, filepath.Join(idDir, "operator-notes.txt"), `keep me`)

	prov := &Provisioner{Source: src, Dir: idDir, AgentID: "agent-1"}
	changed, err := prov.Provision()
	if err != nil || !changed {
		t.Fatalf("first provision: changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(filepath.Join(idDir, "dev-old-agent.json")); !os.IsNotExist(err) {
		t.Error("a stale dev-*.json identity was left for the tunneler to load")
	}
	if _, err := os.Stat(filepath.Join(idDir, "operator-notes.txt")); err != nil {
		t.Error("a file the supervisor did not write was removed")
	}
	if changed, err := prov.Provision(); err != nil || changed {
		t.Fatalf("second provision of the same identity: changed=%v err=%v, want unchanged", changed, err)
	}

	// The tunneler rewrites its own copy (a new controller list, say). That
	// is not a new identity: no rewrite and no restart.
	name, err := IdentityFileName("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(idDir, name)
	writeFile(t, copyPath, `{"ztAPI":"https://c","ztAPIs":["https://c","https://c-ha"],"id":{}}`)
	if changed, err := prov.Provision(); err != nil || changed {
		t.Fatalf("after the tunneler updated its copy: changed=%v err=%v, want unchanged", changed, err)
	}
	if got, _ := os.ReadFile(copyPath); !strings.Contains(string(got), "c-ha") {
		t.Error("the tunneler's own update to its identity was overwritten")
	}

	writeFile(t, src, `{"ztAPI":"https://c2","id":{}}`)
	if changed, _ := prov.Provision(); !changed {
		t.Fatal("a re-enrolled identity was not copied")
	}
	if got, _ := os.ReadFile(copyPath); !strings.Contains(string(got), "c2") {
		t.Error("the re-enrolled identity is not what the tunneler will load")
	}

	missing := &Provisioner{Source: filepath.Join(dir, "none.json"), Dir: idDir, AgentID: "agent-1"}
	if _, err := missing.Provision(); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("missing source: err = %v, want ErrNoIdentity", err)
	}
	if _, err := (&Provisioner{Dir: idDir, AgentID: "agent-1"}).Provision(); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("no source configured: err = %v, want ErrNoIdentity", err)
	}
	writeFile(t, src, `not json`)
	if _, err := prov.Provision(); err == nil {
		t.Error("a corrupt identity was handed to the tunneler")
	}

	if removed, err := prov.Forget(); err != nil || !removed {
		t.Fatalf("Forget: removed=%v err=%v", removed, err)
	}
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Error("the identity copy survived Forget")
	}
}
