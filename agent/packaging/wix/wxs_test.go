// Package wix holds no code: this test reads OpenIDX.wxs, so the properties
// the MSI's safety rests on cannot be dropped without a red build. WiX itself
// runs only on the Windows release job.
package wix

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"
)

type node struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Nodes   []node     `xml:",any"`
}

func (n node) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n node) walk(f func(node)) {
	f(n)
	for _, c := range n.Nodes {
		c.walk(f)
	}
}

func load(t *testing.T) node {
	t.Helper()
	raw, err := os.ReadFile("OpenIDX.wxs")
	if err != nil {
		t.Fatal(err)
	}
	var root node
	if err := xml.Unmarshal(raw, &root); err != nil {
		t.Fatalf("OpenIDX.wxs is not well-formed XML: %v", err)
	}
	return root
}

func find(root node, local string, match func(node) bool) []node {
	var out []node
	root.walk(func(n node) {
		if n.XMLName.Local == local && (match == nil || match(n)) {
			out = append(out, n)
		}
	})
	return out
}

func byID(id string) func(node) bool { return func(n node) bool { return n.attr("Id") == id } }

// TestTheEnrolTokenNeverReachesAVerboseLog: ENROLL_TOKEN, the EnrollDevice
// property that SetProperty fills with a command line carrying it, and the
// custom action's target must all be hidden, or `msiexec /l*v` writes the
// fleet credential to %TEMP%.
func TestTheEnrolTokenNeverReachesAVerboseLog(t *testing.T) {
	root := load(t)
	for _, id := range []string{"ENROLL_TOKEN", "EnrollDevice", "PROXY_URL"} {
		props := find(root, "Property", byID(id))
		if len(props) != 1 || props[0].attr("Hidden") != "yes" {
			t.Errorf("Property %s must be declared once with Hidden=\"yes\"", id)
		}
	}
	ca := find(root, "CustomAction", byID("EnrollDevice"))
	if len(ca) != 1 || ca[0].attr("HideTarget") != "yes" || ca[0].attr("Impersonate") != "no" {
		t.Error("CustomAction EnrollDevice must be HideTarget=\"yes\" Impersonate=\"no\"")
	}
}

func TestNewInstallerPropertiesAreDeclaredAndPassed(t *testing.T) {
	root := load(t)
	set := find(root, "SetProperty", byID("EnrollDevice"))
	if len(set) != 1 {
		t.Fatal("SetProperty EnrollDevice missing")
	}
	cmd := set[0].attr("Value")
	for prop, flag := range map[string]string{
		"TUNNEL_ENABLED": "--tunnel", "SERVER_CA": "--server-ca", "PROXY_URL": "--proxy-url",
		"LOG_LEVEL": "--log-level", "KEEP_ENROLL_TOKEN": "--keep-token",
	} {
		if len(find(root, "Property", byID(prop))) != 1 {
			t.Errorf("Property %s is not declared", prop)
		}
		if !strings.Contains(cmd, flag) || !strings.Contains(cmd, "["+prop+"]") {
			t.Errorf("the enrol command does not pass %s as %s", prop, flag)
		}
	}
	if k := find(root, "Property", byID("KEEP_ENROLL_TOKEN")); len(k) == 1 && k[0].attr("Value") != "1" {
		t.Error("KEEP_ENROLL_TOKEN must default to 1")
	}
}

// TestEnrolRunsOnUpgrade: the old NOT Installed condition skipped the action
// on an upgrade, so a new SERVER_URL was never written.
func TestEnrolRunsOnUpgrade(t *testing.T) {
	root := load(t)
	c := find(root, "Custom", func(n node) bool { return n.attr("Action") == "EnrollDevice" })
	if len(c) != 1 {
		t.Fatal("EnrollDevice is not sequenced")
	}
	cond := c[0].attr("Condition")
	if strings.Contains(cond, "NOT Installed") {
		t.Errorf("EnrollDevice still skips upgrades: %q", cond)
	}
	if !strings.Contains(cond, `REMOVE~="ALL"`) {
		t.Errorf("EnrollDevice must be skipped on uninstall: %q", cond)
	}
}

// TestDetectionRegistryIsWritten: Intune's detection rule reads
// HKLM\SOFTWARE\OpenIDX\Agent Version.
func TestDetectionRegistryIsWritten(t *testing.T) {
	root := load(t)
	keys := find(root, "RegistryKey", func(n node) bool {
		return n.attr("Root") == "HKLM" && n.attr("Key") == `SOFTWARE\OpenIDX\Agent`
	})
	if len(keys) != 1 {
		t.Fatal(`no HKLM SOFTWARE\OpenIDX\Agent RegistryKey`)
	}
	names := map[string]string{}
	for _, v := range find(keys[0], "RegistryValue", nil) {
		names[v.attr("Name")] = v.attr("Value")
	}
	for _, want := range []string{"Version", "InstallDir", "ServerUrl"} {
		if _, ok := names[want]; !ok {
			t.Errorf("registry value %s is not written", want)
		}
	}
	if names["Version"] != "$(var.Version)" {
		t.Errorf("Version is %q, want $(var.Version)", names["Version"])
	}
}

// TestUninstallRemovesTheDataFolder: %ProgramData%\OpenIDX\agent holds the
// device's credentials and the sealed fleet token.
func TestUninstallRemovesTheDataFolder(t *testing.T) {
	root := load(t)
	rm := find(root, "RemoveFolderEx", nil)
	if len(rm) != 1 || rm[0].XMLName.Space != "http://wixtoolset.org/schemas/v4/wxs/util" {
		t.Fatal("expected one util:RemoveFolderEx")
	}
	if rm[0].attr("On") != "uninstall" || rm[0].attr("Property") != "AGENTDATADIR" {
		t.Errorf("RemoveFolderEx must run On=uninstall from AGENTDATADIR")
	}
	if !strings.Contains(rm[0].attr("Condition"), "NOT UPGRADINGPRODUCTCODE") {
		t.Error("RemoveFolderEx must not wipe the enrolment during a major upgrade")
	}
	search := find(root, "RegistrySearch", func(n node) bool { return n.attr("Name") == "DataDir" })
	if len(search) != 1 {
		t.Error("AGENTDATADIR must be read back from the DataDir registry value")
	}
}

func TestTunnelCleanupRunsOnUninstall(t *testing.T) {
	root := load(t)
	c := find(root, "Custom", func(n node) bool { return n.attr("Action") == "TunnelCleanup" })
	if len(c) != 1 || c[0].attr("After") != "StopServices" {
		t.Fatal("TunnelCleanup must be sequenced after StopServices")
	}
}
