package access

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestDownloadsManifestIsSignedWithTheConfiguredKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	t.Setenv("AGENT_MANIFEST_SIGNING_KEY", pemKey)
	manifestKeyOnce = sync.Once{}
	t.Cleanup(func() { manifestKeyOnce = sync.Once{}; manifestKey = nil; manifestKeyErr = nil })

	dir := t.TempDir()
	for _, f := range []string{"openidx-agent_1.2.3_amd64.deb", "openidx-agent-1.2.3.aarch64.rpm", "OpenIDX-1.2.3.pkg", "openidx-agent-linux-amd64"} {
		_ = os.WriteFile(filepath.Join(dir, f), []byte(f), 0o644)
	}
	h := newDownloadHandler(t, dir)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/agent-manifest.json", nil)
	h.handleAgentManifest(c)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var out map[string]map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"linux", "macos", "linux-deb-amd64", "linux-rpm-arm64", "macos-pkg", "bin-linux-amd64"} {
		if _, ok := out[k]; !ok {
			t.Errorf("missing %s in %v", k, out)
		}
	}
	sig, err := base64.StdEncoding.DecodeString(w.Header().Get(manifestSignatureHeader))
	if err != nil || len(sig) == 0 {
		t.Fatalf("no signature header: %v", err)
	}
	input, _ := downloadsManifestSigningInput(out)
	sum := sha256.Sum256(input)
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature does not verify over the served body: %v", err)
	}
	out["linux"]["sha256"] = "00"
	tampered, _ := downloadsManifestSigningInput(out)
	ts := sha256.Sum256(tampered)
	if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, ts[:], sig) == nil {
		t.Fatal("tampered sha256 still verifies")
	}
}

func TestBadManifestSigningKeyRefusesToServe(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("AGENT_MANIFEST_SIGNING_KEY", "-----BEGIN NOPE-----")
	manifestKeyOnce = sync.Once{}
	t.Cleanup(func() { manifestKeyOnce = sync.Once{}; manifestKey = nil; manifestKeyErr = nil })
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/agent-manifest.json", nil)
	newDownloadHandler(t, t.TempDir()).handleAgentManifest(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", w.Code)
	}
}
