package access

// Runs scripts/agent-mirror.sh against a fake release on file:// and checks
// that it installs a correctly signed release, the access handler then serves
// it, and it refuses a bad signature or a tampered MSI.

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
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

type fakeRelease struct {
	base, certPath string
	key            *rsa.PrivateKey
}

func newFakeRelease(t *testing.T, tag, version string, msi []byte, sign *rsa.PrivateKey, shaOverride string) fakeRelease {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "fake publisher"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	base := t.TempDir()
	rel := filepath.Join(base, tag)
	_ = os.MkdirAll(rel, 0o755)
	name := "OpenIDX-" + version + ".msi"
	_ = os.WriteFile(filepath.Join(rel, name), msi, 0o644)
	sum := sha256.Sum256(msi)
	m := mirrorManifest{Version: version, URL: "https://github.com/x/y/releases/download/" + tag + "/" + name, SHA256: hex.EncodeToString(sum[:])}
	if shaOverride != "" {
		m.SHA256 = shaOverride
	}
	if sign == nil {
		sign = key
	}
	in, _ := updateManifestSigningInput(&m)
	d := sha256.Sum256(in)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, sign, crypto.SHA256, d[:])
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	raw, _ := json.Marshal(m)
	_ = os.WriteFile(filepath.Join(rel, "latest.json"), raw, 0o644)
	cert := filepath.Join(base, "publisher.cer")
	_ = os.WriteFile(cert, der, 0o644)
	return fakeRelease{base: base, certPath: cert, key: key}
}

func runMirrorScript(t *testing.T, fr fakeRelease, dest, tag string) ([]byte, error) {
	t.Helper()
	for _, bin := range []string{"bash", "curl", "openssl", "jq", "sha256sum"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	cmd := exec.Command("bash", "../../scripts/agent-mirror.sh", tag)
	cmd.Env = append(os.Environ(), "DEST="+dest, "GH_BASE=file://"+fr.base, "CERTS="+fr.certPath)
	return cmd.CombinedOutput()
}

func TestAgentMirrorScriptInstallsAVerifiedRelease(t *testing.T) {
	fr := newFakeRelease(t, "agent-v2.0.0", "2.0.0", []byte("the msi"), nil, "")
	dest := t.TempDir()
	if out, err := runMirrorScript(t, fr, dest, "agent-v2.0.0"); err != nil {
		t.Fatalf("mirror failed: %v\n%s", err, out)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "agent", "stable", "OpenIDX-2.0.0.msi")); err != nil || string(b) != "the msi" {
		t.Fatalf("msi not installed: %v", err)
	}
	// The handler serves what the script installed.
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(fr.key)})
	t.Setenv("AGENT_MANIFEST_SIGNING_KEY", string(pemKey))
	manifestKeyOnce = sync.Once{}
	t.Cleanup(func() { manifestKeyOnce = sync.Once{}; manifestKey = nil; manifestKeyErr = nil })
	h := &AgentAPIHandler{logger: zap.NewNop(), zm: &ZitiManager{cfg: &config.Config{AgentDownloadsDir: dest, PublicBaseURL: "https://openidx.tdv.org"}}}
	if w := serveMirror(h, "stable", "latest.json"); w.Code != http.StatusOK {
		t.Fatalf("served %d: %s", w.Code, w.Body)
	}
}

func TestAgentMirrorScriptBetaTagGoesToBeta(t *testing.T) {
	fr := newFakeRelease(t, "agent-v2.1.0-beta.1", "2.1.0-beta.1", []byte("beta msi"), nil, "")
	dest := t.TempDir()
	if out, err := runMirrorScript(t, fr, dest, "agent-v2.1.0-beta.1"); err != nil {
		t.Fatalf("mirror failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dest, "agent", "beta", "latest.json")); err != nil {
		t.Fatal(err)
	}
}

func TestAgentMirrorScriptRefusesAWrongSigner(t *testing.T) {
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	fr := newFakeRelease(t, "agent-v2.0.0", "2.0.0", []byte("the msi"), other, "")
	dest := t.TempDir()
	if out, err := runMirrorScript(t, fr, dest, "agent-v2.0.0"); err == nil {
		t.Fatalf("a manifest signed by another key was mirrored:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dest, "agent")); err == nil {
		t.Fatal("something was installed")
	}
}

func TestAgentMirrorScriptRefusesATamperedMSI(t *testing.T) {
	sum := sha256.Sum256([]byte("a different msi"))
	fr := newFakeRelease(t, "agent-v2.0.0", "2.0.0", []byte("the msi"), nil, hex.EncodeToString(sum[:]))
	dest := t.TempDir()
	if out, err := runMirrorScript(t, fr, dest, "agent-v2.0.0"); err == nil {
		t.Fatalf("an MSI not matching the signed sha256 was mirrored:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dest, "agent", "stable", "latest.json")); err == nil {
		t.Fatal("latest.json installed")
	}
}
