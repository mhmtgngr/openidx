package access

import (
	"strings"
	"testing"
)

const testFP = "sha256:eb:45:51:d6:9b:99:39:35:3d:29:f3:49:1b:39:75:8b:fc:2e:c0:83:5b:69:0b:c3:60:c6:65:cc:88:24:85:1b"

// The broker parameters each certificate mode produces. guacd 1.6.0 against a
// self-signed xrdp target (see sql_v239.go): ignore-cert connects, nothing
// refuses, a pinned right fingerprint connects, a wrong one refuses, and a
// security of "any" or "rdp" connects with no certificate looked at.
func TestApplyPamSessionPolicyRDPCertificate(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]string
		pol      pamSessionPolicy
		want     map[string]string
		absent   []string
	}{
		{
			name:   "verify sends no ignore-cert and a TLS-based security",
			pol:    pamSessionPolicy{RDPCertMode: pamRDPCertVerify},
			want:   map[string]string{"security": "nla"},
			absent: []string{"ignore-cert", "cert-fingerprints", "cert-tofu"},
		},
		{
			name:     "verify keeps an entry's tls security",
			settings: map[string]string{"security": "tls"},
			pol:      pamSessionPolicy{RDPCertMode: pamRDPCertVerify},
			want:     map[string]string{"security": "tls"},
		},
		{
			name:     "verify replaces security any, which would skip the check",
			settings: map[string]string{"security": "any"},
			pol:      pamSessionPolicy{RDPCertMode: pamRDPCertVerify},
			want:     map[string]string{"security": "nla"},
		},
		{
			name:     "pin replaces security rdp, which would skip the check",
			settings: map[string]string{"security": "rdp"},
			pol:      pamSessionPolicy{RDPCertMode: pamRDPCertPin, RDPCertFingerprints: []string{testFP}},
			want:     map[string]string{"security": "nla", "cert-fingerprints": testFP},
			absent:   []string{"ignore-cert"},
		},
		{
			name:   "pin with no valid fingerprint is verify, never ignore",
			pol:    pamSessionPolicy{RDPCertMode: pamRDPCertPin, RDPCertFingerprints: []string{"sha1:aa:bb"}},
			want:   map[string]string{"security": "nla"},
			absent: []string{"ignore-cert", "cert-fingerprints"},
		},
		{
			name:     "ignore sends ignore-cert and leaves security alone",
			settings: map[string]string{"security": "any"},
			pol:      pamSessionPolicy{RDPCertMode: pamRDPCertIgnore},
			want:     map[string]string{"ignore-cert": "true", "security": "any"},
		},
		{
			name:   "an unknown mode is verify",
			pol:    pamSessionPolicy{RDPCertMode: "bogus"},
			want:   map[string]string{"security": "nla"},
			absent: []string{"ignore-cert"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := map[string]string{"ignore-cert": "true", "cert-tofu": "true"} // whatever came before
			for k, v := range tc.settings {
				p[k] = v
			}
			applyPamSessionPolicy(p, "rdp", tc.pol)
			for k, v := range tc.want {
				if p[k] != v {
					t.Errorf("%s = %q, want %q", k, p[k], v)
				}
			}
			for _, k := range tc.absent {
				if v, ok := p[k]; ok {
					t.Errorf("%s = %q, want it absent", k, v)
				}
			}
		})
	}
}

func TestApplyPamSessionPolicyChannels(t *testing.T) {
	closed := pamSessionPolicy{RDPCertMode: pamRDPCertVerify}
	p := map[string]string{}
	applyPamSessionPolicy(p, "rdp", closed)
	for k, v := range map[string]string{
		"disable-copy": "true", "disable-paste": "true", "enable-drive": "false", "enable-sftp": "false",
		"disable-download": "true", "disable-upload": "true",
	} {
		if p[k] != v {
			t.Errorf("closed rdp: %s = %q, want %q", k, p[k], v)
		}
	}

	open := pamSessionPolicy{RDPCertMode: pamRDPCertVerify, AllowCopy: true, AllowPaste: true, AllowFileTransfer: true}
	p = map[string]string{}
	applyPamSessionPolicy(p, "rdp", open)
	if p["disable-copy"] != "false" || p["disable-paste"] != "false" || p["enable-drive"] != "true" {
		t.Errorf("open rdp: %v", p)
	}
	// The drive's directory is the server's, per Guacamole user.
	if !strings.HasPrefix(p["drive-path"], "/tmp/guac-drive/") || p["create-drive-path"] != "true" {
		t.Errorf("open rdp drive-path = %q", p["drive-path"])
	}

	p = map[string]string{}
	applyPamSessionPolicy(p, "ssh", open)
	if p["enable-sftp"] != "true" {
		t.Errorf("open ssh: enable-sftp = %q", p["enable-sftp"])
	}
	if _, ok := p["security"]; ok {
		t.Error("an ssh session got an RDP security parameter")
	}
}

// No stored setting reaches the broker for a key the policy owns.
func TestPamSettingsCannotOpenPolicyKeys(t *testing.T) {
	settings := map[string]interface{}{
		"ignore-cert": "true", "cert-tofu": "true", "cert-fingerprints": "sha256:00",
		"enable-drive": "true", "drive-path": "/etc", "create-drive-path": "true",
		"enable-sftp": "true", "sftp-root-directory": "/", "disable-copy": "false",
		"typescript-path": "/var/lib", "create-typescript-path": "true",
	}
	p := buildPamGuacParams("password", "u", "", []byte("x"), settings, false, "", "")
	applyPamSessionPolicy(p, "rdp", pamSessionPolicy{RDPCertMode: pamRDPCertVerify})
	for _, k := range []string{"ignore-cert", "cert-tofu", "cert-fingerprints", "drive-path",
		"create-drive-path", "sftp-root-directory", "typescript-path", "create-typescript-path"} {
		if v, ok := p[k]; ok {
			t.Errorf("setting %s reached the broker as %q", k, v)
		}
	}
	if p["enable-drive"] != "false" || p["enable-sftp"] != "false" || p["disable-copy"] != "true" {
		t.Errorf("settings opened a channel: %v", p)
	}
}

func TestResolvePamSessionPolicy(t *testing.T) {
	str := func(s string) *string { return &s }
	b := func(v bool) *bool { return &v }
	fps := func(v ...string) *[]string { return &v }

	pol, err := resolvePamSessionPolicy(&pamEntryUpsertReq{}, "rdp", pamDefaultSessionPolicy())
	if err != nil || pol.RDPCertMode != pamRDPCertVerify || !pol.AllowCopy || !pol.AllowPaste || pol.AllowFileTransfer {
		t.Fatalf("default = %+v, %v", pol, err)
	}

	// An omitted field keeps what the entry has.
	cur := pamSessionPolicy{RDPCertMode: pamRDPCertPin, RDPCertFingerprints: []string{testFP}, AllowFileTransfer: true}
	pol, err = resolvePamSessionPolicy(&pamEntryUpsertReq{AllowCopy: b(true)}, "rdp", cur)
	if err != nil || pol.RDPCertMode != pamRDPCertPin || len(pol.RDPCertFingerprints) != 1 || !pol.AllowFileTransfer || !pol.AllowCopy {
		t.Fatalf("partial update = %+v, %v", pol, err)
	}

	// Fingerprints are normalised and deduplicated.
	pol, err = resolvePamSessionPolicy(&pamEntryUpsertReq{RDPCertMode: str("pin"),
		RDPCertFingerprints: fps(strings.ToUpper(testFP), " "+testFP+" ", "")}, "rdp", pamDefaultSessionPolicy())
	if err != nil || len(pol.RDPCertFingerprints) != 1 || pol.RDPCertFingerprints[0] != testFP {
		t.Fatalf("normalise = %+v, %v", pol, err)
	}

	for name, req := range map[string]*pamEntryUpsertReq{
		"unknown mode":     {RDPCertMode: str("trust")},
		"pin with none":    {RDPCertMode: str("pin")},
		"sha1 fingerprint": {RDPCertMode: str("pin"), RDPCertFingerprints: fps("sha1:aa:bb:cc")},
		"garbage":          {RDPCertMode: str("pin"), RDPCertFingerprints: fps("sha256:zz")},
		"too many":         {RDPCertMode: str("pin"), RDPCertFingerprints: fps(testFP, testFP, testFP, testFP, testFP, testFP, testFP, testFP, testFP)},
		"pin cleared":      {RDPCertFingerprints: fps()},
	} {
		start := pamDefaultSessionPolicy()
		if name == "pin cleared" {
			start = cur
		}
		if _, err := resolvePamSessionPolicy(req, "rdp", start); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// A non-RDP entry has no certificate mode.
	if _, err := resolvePamSessionPolicy(&pamEntryUpsertReq{RDPCertMode: str("ignore")}, "ssh", pamDefaultSessionPolicy()); err == nil {
		t.Error("ssh entry accepted rdp_cert_mode=ignore")
	}
	pol, err = resolvePamSessionPolicy(&pamEntryUpsertReq{RDPCertMode: str("verify")}, "ssh", pamDefaultSessionPolicy())
	if err != nil || pol.RDPCertMode != pamRDPCertVerify {
		t.Errorf("ssh verify = %+v, %v", pol, err)
	}
}

func TestPamSessionPolicyLoosened(t *testing.T) {
	verify := pamSessionPolicy{RDPCertMode: pamRDPCertVerify, RDPCertFingerprints: []string{}}
	pin := pamSessionPolicy{RDPCertMode: pamRDPCertPin, RDPCertFingerprints: []string{testFP}}
	ignore := pamSessionPolicy{RDPCertMode: pamRDPCertIgnore, RDPCertFingerprints: []string{}}
	other := pamSessionPolicy{RDPCertMode: pamRDPCertPin, RDPCertFingerprints: []string{strings.Replace(testFP, "eb", "ec", 1)}}
	withCopy := verify
	withCopy.AllowCopy = true
	withFiles := verify
	withFiles.AllowFileTransfer = true

	for _, tc := range []struct {
		name      string
		cur, next pamSessionPolicy
		want      bool
	}{
		{"verify to ignore", verify, ignore, true},
		{"pin to ignore", pin, ignore, true},
		{"pin to another pin", pin, other, true},
		{"open copy", verify, withCopy, true},
		{"open file transfer", verify, withFiles, true},
		{"ignore to verify", ignore, verify, false},
		{"ignore to pin", ignore, pin, false},
		{"verify to pin", verify, pin, true}, // trusts a certificate verify would refuse
		{"pin to verify", pin, verify, false},
		{"close copy", withCopy, verify, false},
		{"unchanged", pin, pin, false},
		{"drop a pinned fingerprint", pamSessionPolicy{RDPCertMode: pamRDPCertPin, RDPCertFingerprints: []string{testFP, other.RDPCertFingerprints[0]}}, pin, false},
	} {
		if got := pamSessionPolicyLoosened(tc.cur, tc.next); got != tc.want {
			t.Errorf("%s: loosened = %v, want %v", tc.name, got, tc.want)
		}
	}
}
