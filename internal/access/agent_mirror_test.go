package access

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// mirrorFixture sets a signing key (with a self-signed cert standing in for
// release-publisher.cer) and a downloads dir holding a mirrored stable channel.
func agentMirrorFixture(t *testing.T) (*AgentAPIHandler, *x509.Certificate, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OpenIDX test publisher"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	t.Setenv("AGENT_MANIFEST_SIGNING_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	manifestKeyOnce = sync.Once{}
	t.Cleanup(func() { manifestKeyOnce = sync.Once{}; manifestKey = nil; manifestKeyErr = nil })

	dir := t.TempDir()
	ch := filepath.Join(dir, "agent", "stable")
	_ = os.MkdirAll(ch, 0o755)
	_ = os.WriteFile(filepath.Join(ch, "OpenIDX-1.2.3.msi"), []byte("msi-bytes"), 0o644)
	up, _ := json.Marshal(mirrorManifest{Version: "1.2.3",
		URL:    "https://github.com/mhmtgngr/openidx/releases/download/agent-v1.2.3/OpenIDX-1.2.3.msi",
		SHA256: strings.Repeat("a", 64), Signature: "upstream"})
	_ = os.WriteFile(filepath.Join(ch, "latest.json"), up, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("no"), 0o644)
	h := &AgentAPIHandler{logger: zap.NewNop(), zm: &ZitiManager{cfg: &config.Config{
		AgentDownloadsDir: dir, OAuthIssuer: "https://openidx.tdv.org/oauth"}}}
	return h, cert, dir
}

func serveMirror(h *AgentAPIHandler, channel, file string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/agent/x/y", nil)
	c.Params = gin.Params{{Key: "channel", Value: channel}, {Key: "file", Value: file}}
	h.HandleAgentMirror(c)
	return w
}

func TestMirrorManifestIsResignedForTheBox(t *testing.T) {
	h, cert, _ := agentMirrorFixture(t)
	w := serveMirror(h, "stable", "latest.json")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var m mirrorManifest
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.URL != "https://openidx.tdv.org/downloads/agent/stable/OpenIDX-1.2.3.msi" {
		t.Fatalf("url not rewritten to the box: %q", m.URL)
	}
	if m.Version != "1.2.3" || m.SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("version/sha256 changed: %+v", m)
	}
	// The exact canonical form the agent's updater.signingInput builds.
	want := "openidx-agent-update-manifest/v1\nversion=1.2.3\nurl=" + m.URL + "\nsha256=" + m.SHA256 + "\n"
	digest := sha256.Sum256([]byte(want))
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify against the pinned cert: %v", err)
	}
}

func TestMirrorServesTheArtifactOnly(t *testing.T) {
	h, _, _ := agentMirrorFixture(t)
	if w := serveMirror(h, "stable", "OpenIDX-1.2.3.msi"); w.Code != http.StatusOK || w.Body.String() != "msi-bytes" {
		t.Fatalf("msi: %d %q", w.Code, w.Body)
	}
	if w := serveMirror(h, "stable", "other.msi"); w.Code != http.StatusNotFound {
		t.Fatalf("unnamed file served: %d", w.Code)
	}
}

func TestMirrorUnknownChannelIs404(t *testing.T) {
	h, _, _ := agentMirrorFixture(t)
	for _, ch := range []string{"nightly", "", "..", "beta"} { // beta exists as a channel but is not mirrored
		if w := serveMirror(h, ch, "latest.json"); w.Code != http.StatusNotFound {
			t.Fatalf("channel %q: %d", ch, w.Code)
		}
	}
}

func TestMirrorRefusesPathTraversal(t *testing.T) {
	h, _, _ := agentMirrorFixture(t)
	for _, f := range []string{"../../secret.txt", "..", "../latest.json", ".latest.json", "a/b", `..\secret.txt`} {
		if w := serveMirror(h, "stable", f); w.Code == http.StatusOK {
			t.Fatalf("%q served", f)
		}
	}
	// Through the real router too: gin cleans and rejects the path.
	r := gin.New()
	r.GET("/downloads/agent/:channel/:file", h.HandleAgentMirror)
	for _, p := range []string{"/downloads/agent/stable/..%2F..%2Fsecret.txt", "/downloads/agent/..%2F/secret.txt"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code == http.StatusOK {
			t.Fatalf("%s served", p)
		}
	}
}

func TestConfigUpdateBlockNamesTheBoxMirror(t *testing.T) {
	h, _, dir := agentMirrorFixture(t)
	b := h.updateBlockFor(context.Background(), "agent-1")
	if b.ManifestURL != "https://openidx.tdv.org/downloads/agent/stable/latest.json" {
		t.Fatalf("update block: %q", b.ManifestURL)
	}
	// Without a mirror the GitHub default stays as the fallback.
	_ = os.RemoveAll(filepath.Join(dir, "agent"))
	if b := h.updateBlockFor(context.Background(), "agent-1"); b.ManifestURL != defaultChannelManifest["stable"] {
		t.Fatalf("fallback: %q", b.ManifestURL)
	}
}

// The box's PublicBaseURL is the config default (http://localhost:3000) on a
// deployment that never set it. It must not outrank the issuer: the box
// advertised an MSI at localhost, which no endpoint can reach.
func TestMirrorOriginIgnoresALoopbackPublicBaseURL(t *testing.T) {
	h, _, _ := agentMirrorFixture(t)
	h.zm.cfg.PublicBaseURL = "http://localhost:3000"
	if got := h.boxOrigin(); got != "https://openidx.tdv.org" {
		t.Fatalf("origin = %q, want the issuer's", got)
	}
	h.zm.cfg.OAuthIssuer = "http://127.0.0.1:8006"
	if got := h.boxOrigin(); got != "" {
		t.Fatalf("origin = %q, want none when only loopback origins are configured", got)
	}
	h.zm.cfg.PublicBaseURL = "https://portal.example.org"
	if got := h.boxOrigin(); got != "https://portal.example.org" {
		t.Fatalf("origin = %q, want PublicBaseURL when the issuer is loopback", got)
	}
}

func TestConfigUpdateBlockSkipsMirrorWithoutKey(t *testing.T) {
	h, _, _ := agentMirrorFixture(t)
	t.Setenv("AGENT_MANIFEST_SIGNING_KEY", "")
	manifestKeyOnce = sync.Once{}
	if b := h.updateBlockFor(context.Background(), "agent-1"); b.ManifestURL != defaultChannelManifest["stable"] {
		t.Fatalf("an unsignable mirror must not be advertised: %q", b.ManifestURL)
	}
}
