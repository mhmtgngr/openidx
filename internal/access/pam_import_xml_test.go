package access

import (
	"strings"
	"testing"
)

// An RDM XML export, trimmed to what the importer reads, with documentation
// addresses (RFC 5737) in place of a real inventory.
const rdmXMLSample = "\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" + `<RDMExport>
  <Connections>
    <Connection>
      <ConnectionType>Group</ConnectionType>
      <Group>Servers\Web</Group>
      <ID>8d1c409e-02c5-4912-8246-5e4933fb3b9c</ID>
      <Image>iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0</Image>
      <Name>Web</Name>
    </Connection>
    <Connection>
      <ConnectionType>RDPConfigured</ConnectionType>
      <Group>Servers\Web</Group>
      <Name>web-01</Name>
      <Url>192.0.2.10</Url>
      <Description>front end</Description>
      <Image>QUJD</Image>
      <RDP><AudioCaptureRedirectionMode>Off</AudioCaptureRedirectionMode></RDP>
    </Connection>
    <Connection>
      <ConnectionType>SSHShell</ConnectionType>
      <Group>Servers\Web</Group>
      <Name>jump</Name>
      <Terminal><Host>192.0.2.20</Host><HostPort>2222</HostPort><PrivateKeyPassphrase>hunter2</PrivateKeyPassphrase></Terminal>
      <PasswordControlId>x</PasswordControlId>
    </Connection>
    <Connection>
      <ConnectionType>WebBrowser</ConnectionType>
      <Group>Websites</Group>
      <Name>wiki</Name>
      <WebBrowserUrl>https://wiki.example.test/</WebBrowserUrl>
    </Connection>
    <Connection>
      <ConnectionType>Credential</ConnectionType>
      <Group>Generic Credentials</Group>
      <Name>svc</Name>
      <Credentials><UserName>svc-backup</UserName></Credentials>
    </Connection>
    <Connection>
      <ConnectionType>AzureBlobStorage</ConnectionType>
      <Group>Cloud</Group>
      <Name>blobs</Name>
      <Tag>a</Tag><Tag>b</Tag>
    </Connection>
  </Connections>
  <DatabaseID>abc</DatabaseID>
  <Version>2026.1</Version>
</RDMExport>`

func TestParseRDMXMLExport(t *testing.T) {
	t.Parallel()
	conns, err := parseRDMExport([]byte(rdmXMLSample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(conns) != 6 {
		t.Fatalf("got %d connections, want 6", len(conns))
	}

	items := map[string]*rdmImportItem{}
	for _, c := range conns {
		it := mapRDMConnection(c)
		if it == nil {
			t.Fatalf("a connection did not map: %v", c)
		}
		items[it.Name] = it
	}

	t.Run("a group is a folder at its path", func(t *testing.T) {
		g := items["Web"]
		if g.EntryType != "group" || g.FolderPath != `Servers\Web` {
			t.Errorf("group = %+v", g)
		}
	})
	t.Run("rdp takes its host from Url and the default port", func(t *testing.T) {
		it := items["web-01"]
		if it.EntryType != "rdp" || it.Hostname != "192.0.2.10" || it.Port != 3389 || it.Description != "front end" {
			t.Errorf("rdp = %+v", it)
		}
	})
	t.Run("ssh takes host and port from Terminal", func(t *testing.T) {
		it := items["jump"]
		if it.EntryType != "ssh" || it.Hostname != "192.0.2.20" || it.Port != 2222 {
			t.Errorf("ssh = %+v", it)
		}
	})
	t.Run("a website keeps its address", func(t *testing.T) {
		if it := items["wiki"]; it.EntryType != "website" || it.URL != "https://wiki.example.test/" {
			t.Errorf("website = %+v", it)
		}
	})
	t.Run("a credential keeps its user name", func(t *testing.T) {
		if it := items["svc"]; it.EntryType != "credential" || it.Username != "svc-backup" {
			t.Errorf("credential = %+v", it)
		}
	})
	t.Run("a type with no native equivalent is kept as a note", func(t *testing.T) {
		it := items["blobs"]
		if it.EntryType != "secure_note" {
			t.Errorf("entry type = %q", it.EntryType)
		}
		if tags, _ := it.Preserved["Tag"].([]interface{}); len(tags) != 2 {
			t.Errorf("a repeated element was not kept as a list: %v", it.Preserved["Tag"])
		}
	})
	t.Run("the embedded icon is not stored anywhere", func(t *testing.T) {
		for name, it := range items {
			if _, ok := it.Preserved["Image"]; ok {
				t.Errorf("%s kept its Image", name)
			}
		}
	})
	t.Run("password-like keys are scrubbed from what is preserved", func(t *testing.T) {
		it := items["jump"]
		if _, ok := it.Preserved["PasswordControlId"]; ok {
			t.Error("PasswordControlId preserved")
		}
		term, _ := it.Preserved["Terminal"].(map[string]interface{})
		if _, ok := term["PrivateKeyPassphrase"]; ok {
			t.Error("a passphrase was preserved")
		}
	})
}

func TestParseRDMXMLRefusesWhatIsNotAnExport(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"not xml after a tag":   "<RDMExport><Connections><Connection><Name>a</Name>",
		"another document":      "<html><body>hi</body></html>",
		"mismatched tags":       "<RDMExport><Connections></RDMExport>",
		"nested far too deeply": "<RDMExport><Connections><Connection>" + strings.Repeat("<a>", 80) + strings.Repeat("</a>", 80) + "</Connection></Connections></RDMExport>",
	} {
		if _, err := parseRDMExport([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An export with no connections parses to nothing; the handler refuses that.
	conns, err := parseRDMExport([]byte("<RDMExport><Connections></Connections></RDMExport>"))
	if err != nil || len(conns) != 0 {
		t.Errorf("empty export: %v, %d", err, len(conns))
	}
	// An entity declaration is not expanded or fetched.
	if conns, err := parseRDMExport([]byte(`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><RDMExport><Connections><Connection><Name>&e;</Name></Connection></Connections></RDMExport>`)); err == nil {
		for _, c := range conns {
			if strings.Contains(strings.ToLower(rdmString(c, "Name")), "root:") {
				t.Fatal("an external entity was resolved")
			}
		}
	}
}
