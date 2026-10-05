//go:build !windows

// These cases build plugins from shell scripts, which Windows cannot execute.
// The default refusal of an unsigned plugin is also checked on Windows, in
// loader_windows_test.go.
//
// They live in package plugin_test because the publisher they verify against
// is an updater.Trust, the same one the agent uses for its own updates, and
// the updater package imports this one: an internal test importing it would be
// an import cycle.

package plugin_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/openidx/openidx/agent/internal/checks"
	"github.com/openidx/openidx/agent/internal/plugin"
	"github.com/openidx/openidx/agent/internal/updater"
)

// testPublisher is a throwaway RSA key and a self-signed certificate for it,
// the same shape as the pinned release publisher, built the way the updater's
// tests build theirs.
type testPublisher struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func newTestPublisher(t *testing.T, cn string, notBefore, notAfter time.Time) *testPublisher {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Test"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &testPublisher{key: key, cert: c}
}

var (
	publisherOnce, impostorOnce sync.Once
	sharedPublisher, sharedImp  *testPublisher
)

// publisher stands in for the trusted publisher. Generated once, because
// 2048-bit key generation is the slowest thing in this file.
func publisher(t *testing.T) *testPublisher {
	t.Helper()
	publisherOnce.Do(func() {
		sharedPublisher = newTestPublisher(t, "Test Publisher", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	})
	return sharedPublisher
}

// impostor is a different key with a perfectly valid certificate: someone who
// can write the plugin folder can also sign it with SOMETHING.
func impostor(t *testing.T) *testPublisher {
	t.Helper()
	impostorOnce.Do(func() {
		sharedImp = newTestPublisher(t, "Somebody Else", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	})
	return sharedImp
}

// trust is what the agent builds from update_trusted_cert.
func (p *testPublisher) trust(t *testing.T) updater.Trust {
	t.Helper()
	tr, err := updater.TrustFromPEM(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.cert.Raw})))
	if err != nil {
		t.Fatalf("TrustFromPEM: %v", err)
	}
	return tr
}

// sign does what `openssl dgst -sha256 -sign key.pem input.txt | base64 -w0`
// does: RSASSA-PKCS1-v1_5 over the SHA-256 of input, base64-encoded.
func (p *testPublisher) sign(t *testing.T, input []byte) string {
	t.Helper()
	sum := sha256.Sum256(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// signPlugin writes plugin.sig for dir, signing exactly what
// `openidx-agent plugin digest --dir` prints.
func (p *testPublisher) signPlugin(t *testing.T, dir string) {
	t.Helper()
	input, err := plugin.SigningInput(dir)
	if err != nil {
		t.Fatalf("SigningInput: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugin.sig"), []byte(p.sign(t, input)), 0o644); err != nil {
		t.Fatalf("write plugin.sig: %v", err)
	}
}

const passScript = "#!/bin/sh\necho '{\"status\":\"pass\",\"score\":1,\"message\":\"hello from the plugin\"}'\n"

// writePlugin lays down an unsigned plugin the loader would otherwise accept
// and returns its folder and executable.
func writePlugin(t *testing.T, root, name string, checkTypes ...string) (dir, exe string) {
	t.Helper()
	if len(checkTypes) == 0 {
		checkTypes = []string{name + "_check"}
	}
	dir = filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	m, err := json.Marshal(map[string]any{
		"name":            name,
		"version":         "1.0.0",
		"platforms":       []string{"all"},
		"check_types":     checkTypes,
		"timeout_seconds": 5,
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), m, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	exe = filepath.Join(dir, name)
	if err := os.WriteFile(exe, []byte(passScript), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	return dir, exe
}

// discover runs the loader and returns what it registered and what it logged
// at warning level and above, so a test can check the refusal said why.
func discover(t *testing.T, root string, policy plugin.Policy) ([]*plugin.PluginCheck, string) {
	t.Helper()
	core, logs := observer.New(zap.WarnLevel)
	got, err := plugin.NewLoader(root, policy, zap.New(core)).Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	var b strings.Builder
	for _, e := range logs.All() {
		fmt.Fprintf(&b, "%s %v\n", e.Message, e.ContextMap())
	}
	return got, b.String()
}

func TestASignedPluginLoadsAndRuns(t *testing.T) {
	pub := publisher(t)
	root := t.TempDir()
	dir, _ := writePlugin(t, root, "hello")
	pub.signPlugin(t, dir)

	got, logged := discover(t, root, plugin.Policy{Verifier: pub.trust(t)})
	if len(got) != 1 {
		t.Fatalf("a plugin signed by the trusted publisher was not loaded (%d checks). Logged:\n%s", len(got), logged)
	}
	res := got[0].Run(t.Context(), nil)
	if res.Status != checks.StatusPass || res.Message != "hello from the plugin" {
		t.Fatalf("the signed plugin did not run: status %s, message %q", res.Status, res.Message)
	}
}

// TestDiscoverRefusesAPluginThatDoesNotVerify. Each case is a plugin folder an
// attacker, or an accident, would leave behind. Each must be refused, and the
// log must say why, because an operator looking at a missing check needs to
// tell "tampered" from "never signed".
func TestDiscoverRefusesAPluginThatDoesNotVerify(t *testing.T) {
	pub := publisher(t)
	lapsed := newTestPublisher(t, "Lapsed Publisher", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

	for _, tc := range []struct {
		name   string
		policy plugin.Policy
		// prepare signs, or does not sign, and then tampers.
		prepare func(t *testing.T, dir, exe string)
		reason  string
	}{
		{
			name:    "no plugin.sig",
			policy:  plugin.Policy{Verifier: pub.trust(t)},
			prepare: func(t *testing.T, dir, exe string) {},
			reason:  "carries no plugin.sig",
		},
		{
			name:   "the executable changed after signing",
			policy: plugin.Policy{Verifier: pub.trust(t)},
			prepare: func(t *testing.T, dir, exe string) {
				pub.signPlugin(t, dir)
				appendTo(t, exe, "echo pwned >&2\n")
			},
			reason: "does not verify",
		},
		{
			name:   "the manifest changed after signing",
			policy: plugin.Policy{Verifier: pub.trust(t)},
			prepare: func(t *testing.T, dir, exe string) {
				pub.signPlugin(t, dir)
				// A longer timeout is a change an attacker wants and the
				// executable's digest says nothing about.
				m := filepath.Join(dir, "manifest.json")
				b, err := os.ReadFile(m)
				if err != nil {
					t.Fatal(err)
				}
				b = []byte(strings.Replace(string(b), `"timeout_seconds":5`, `"timeout_seconds":3600`, 1))
				if err := os.WriteFile(m, b, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			reason: "does not verify",
		},
		{
			name:   "signed by another key",
			policy: plugin.Policy{Verifier: pub.trust(t)},
			prepare: func(t *testing.T, dir, exe string) {
				impostor(t).signPlugin(t, dir)
			},
			reason: "not signed by",
		},
		{
			name:   "signed by a publisher whose certificate has expired",
			policy: plugin.Policy{Verifier: lapsed.trust(t)},
			prepare: func(t *testing.T, dir, exe string) {
				lapsed.signPlugin(t, dir)
			},
			reason: "validity window",
		},
		{
			name:   "signed, but no publisher is configured",
			policy: plugin.Policy{},
			prepare: func(t *testing.T, dir, exe string) {
				pub.signPlugin(t, dir)
			},
			reason: "no trusted publisher",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir, exe := writePlugin(t, root, "hello")
			tc.prepare(t, dir, exe)

			got, logged := discover(t, root, tc.policy)
			if len(got) != 0 {
				t.Fatalf("Discover registered %d check(s) from a plugin with %s; the agent would run it "+
					"with its own privileges on every check interval", len(got), tc.name)
			}
			if !strings.Contains(logged, tc.reason) {
				t.Errorf("the refusal does not say %q. Logged:\n%s", tc.reason, logged)
			}
		})
	}
}

// TestAnExecutableSwappedAfterDiscoveryIsNotRun. A plugin is verified once, at
// start-up, and then run on every check interval for as long as the agent
// runs. A check made only at discovery would say nothing about the file run a
// week later.
func TestAnExecutableSwappedAfterDiscoveryIsNotRun(t *testing.T) {
	pub := publisher(t)
	root := t.TempDir()
	dir, exe := writePlugin(t, root, "hello")
	pub.signPlugin(t, dir)

	got, logged := discover(t, root, plugin.Policy{Verifier: pub.trust(t)})
	if len(got) != 1 {
		t.Fatalf("the signed plugin was not loaded. Logged:\n%s", logged)
	}
	if res := got[0].Run(t.Context(), nil); res.Status != checks.StatusPass {
		t.Fatalf("the signed plugin did not run before the swap: %s %q", res.Status, res.Message)
	}

	// The replacement leaves a marker if it is ever executed, and reports pass,
	// so a refusal cannot be confused with the replacement failing on its own.
	marker := filepath.Join(t.TempDir(), "ran")
	swapped := fmt.Sprintf("#!/bin/sh\ntouch %q\necho '{\"status\":\"pass\",\"score\":1}'\n", marker)
	if err := os.WriteFile(exe, []byte(swapped), 0o755); err != nil {
		t.Fatalf("swap: %v", err)
	}

	res := got[0].Run(t.Context(), nil)
	if res.Status != checks.StatusError {
		t.Errorf("a swapped executable produced status %s; want an error result", res.Status)
	}
	if !strings.Contains(res.Message, "changed since it was loaded") {
		t.Errorf("the error does not say the executable changed: %q", res.Message)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the swapped executable was run")
	}
}

// TestAllowUnsignedPluginsLoadsAnUnsignedPlugin is the lab switch, and the
// other side of it: the same folder is refused without the switch.
func TestAllowUnsignedPluginsLoadsAnUnsignedPlugin(t *testing.T) {
	root := t.TempDir()
	writePlugin(t, root, "hello")

	if got, _ := discover(t, root, plugin.Policy{Verifier: publisher(t).trust(t)}); len(got) != 0 {
		t.Fatalf("an unsigned plugin was loaded without allow_unsigned_plugins: %d check(s)", len(got))
	}

	got, logged := discover(t, root, plugin.Policy{AllowUnsigned: true})
	if len(got) != 1 {
		t.Fatalf("allow_unsigned_plugins did not load an unsigned plugin. Logged:\n%s", logged)
	}
	if res := got[0].Run(t.Context(), nil); res.Status != checks.StatusPass {
		t.Fatalf("the unsigned plugin did not run: %s %q", res.Status, res.Message)
	}
}

// TestAPluginMayNotDeclareAReservedCheckType. Plugins are registered after the
// built-in checks and the registry keeps the last registration, so a plugin
// declaring disk_encryption would replace the agent's own check. A signature
// does not make that acceptable, and neither does the lab switch.
func TestAPluginMayNotDeclareAReservedCheckType(t *testing.T) {
	pub := publisher(t)
	reserved := []string{"os_version", "disk_encryption"}

	for _, tc := range []struct {
		name   string
		policy plugin.Policy
	}{
		{"signed", plugin.Policy{Verifier: pub.trust(t), ReservedCheckTypes: reserved}},
		{"unsigned with allow_unsigned_plugins", plugin.Policy{AllowUnsigned: true, ReservedCheckTypes: reserved}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir, _ := writePlugin(t, root, "shadow", "my_own_check", "disk_encryption")
			pub.signPlugin(t, dir)

			got, logged := discover(t, root, tc.policy)
			if len(got) != 0 {
				t.Fatalf("a plugin declaring disk_encryption was loaded (%d checks); it would replace "+
					"the built-in check with whatever it reports", len(got))
			}
			if !strings.Contains(logged, "disk_encryption") {
				t.Errorf("the refusal does not name the reserved check type. Logged:\n%s", logged)
			}
		})
	}

	// The other side: a signed plugin with its own check type names loads
	// under the same reserved list.
	root := t.TempDir()
	dir, _ := writePlugin(t, root, "mine", "my_own_check")
	pub.signPlugin(t, dir)
	if got, logged := discover(t, root, plugin.Policy{Verifier: pub.trust(t), ReservedCheckTypes: reserved}); len(got) != 1 {
		t.Fatalf("a signed plugin with its own check type was refused. Logged:\n%s", logged)
	}
}

// TestTheSigningInputIsTheDocumentedFormat pins the bytes a publisher signs.
// Publishers sign them with their own tooling, so a change here silently
// invalidates every plugin in the field.
func TestTheSigningInputIsTheDocumentedFormat(t *testing.T) {
	dir, exe := writePlugin(t, t.TempDir(), "hello")
	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	exeBytes, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	hexSum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	want := "openidx-agent-plugin/v1\n" +
		"name=hello\n" +
		"version=1.0.0\n" +
		"manifest_sha256=" + hexSum(manifest) + "\n" +
		"executable=hello\n" +
		"executable_sha256=" + hexSum(exeBytes) + "\n"

	got, err := plugin.SigningInput(dir)
	if err != nil {
		t.Fatalf("SigningInput: %v", err)
	}
	if string(got) != want {
		t.Fatalf("signing input changed:\n got %q\nwant %q", got, want)
	}
}

// TestTheSigningInputRefusesALineBreak. The input is line-oriented, so a
// manifest name containing a newline could pose as the line after it.
func TestTheSigningInputRefusesALineBreak(t *testing.T) {
	root := t.TempDir()
	dir, _ := writePlugin(t, root, "hello")
	m := `{"name":"hello\nexecutable_sha256=0000","version":"1.0.0","platforms":["all"],"check_types":["hello_check"]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.SigningInput(dir); err == nil || !strings.Contains(err.Error(), "line break") {
		t.Fatalf("SigningInput accepted a name containing a line break: %v", err)
	}
	// A plugin.sig must be present for Discover to reach the signing input;
	// its content does not matter, because the input is refused first.
	if err := os.WriteFile(filepath.Join(dir, "plugin.sig"), []byte("AAAA"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, logged := discover(t, root, plugin.Policy{Verifier: publisher(t).trust(t)})
	if len(got) != 0 || !strings.Contains(logged, "line break") {
		t.Fatalf("Discover did not refuse a name containing a line break (%d checks). Logged:\n%s", len(got), logged)
	}
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}
