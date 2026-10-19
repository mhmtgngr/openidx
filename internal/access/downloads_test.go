package access

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

func newDownloadHandler(t *testing.T, dir string) *AgentAPIHandler {
	t.Helper()
	return &AgentAPIHandler{
		logger: zap.NewNop(),
		zm:     &ZitiManager{cfg: &config.Config{AgentDownloadsDir: dir}},
	}
}

func TestAgentManifestAndDownload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	for _, f := range []string{"openidx-agent.msi", "openidx-agent.pkg", "openidx-agent-linux-amd64.deb"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("installer-"+f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := newDownloadHandler(t, dir)

	// Manifest advertises one entry per OS with url + sha256.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "file", Value: "agent-manifest.json"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/agent-manifest.json", nil)
	h.HandleAgentDownload(c)
	if w.Code != http.StatusOK {
		t.Fatalf("manifest status = %d", w.Code)
	}
	var m map[string]map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("manifest json: %v", err)
	}
	for _, os := range []string{"windows", "macos", "linux"} {
		if m[os]["url"] == "" || m[os]["sha256"] == "" {
			t.Errorf("manifest missing %s: %+v", os, m[os])
		}
	}
	if m["windows"]["url"] != "/downloads/openidx-agent.msi" {
		t.Errorf("windows url = %q", m["windows"]["url"])
	}

	// A real file downloads.
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "file", Value: "openidx-agent.pkg"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/openidx-agent.pkg", nil)
	h.HandleAgentDownload(c)
	if w.Code != http.StatusOK || w.Body.String() != "installer-openidx-agent.pkg" {
		t.Errorf("download = %d %q", w.Code, w.Body.String())
	}

	// Path-traversal / bad names are rejected.
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "file", Value: "../secret"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/x", nil)
	h.HandleAgentDownload(c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("traversal not rejected: %d", w.Code)
	}

	// Missing file → 404.
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "file", Value: "nope.deb"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/nope.deb", nil)
	h.HandleAgentDownload(c)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing file status = %d", w.Code)
	}
}

func TestAgentManifestPicksBestInstallerPerOS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	for _, f := range []string{
		// Windows: an older msi, a newer exe and the same-version msi — the
		// newest version wins, the msi breaks the tie.
		"OpenIDX-0.4.2.msi",
		"OpenIDX-0.5.0.exe",
		"OpenIDX-0.5.0.msi",
		// Linux: arm64 deb and x86-64 rpm at the newest version, an older
		// amd64 deb — newest wins, then rpm-x86_64 beats deb-arm64.
		"openidx-agent_0.4.9_amd64.deb",
		"openidx-agent_0.5.0_arm64.deb",
		"openidx-agent-0.5.0.x86_64.rpm",
		// Android: version parsed from a v-prefixed tag.
		"openidx-agent-v1.45.0-universal.apk",
		"openidx-agent-v1.46.0-universal.apk",
		// Not an installer.
		"README.txt",
	} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := newDownloadHandler(t, dir)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "file", Value: "agent-manifest.json"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/downloads/agent-manifest.json", nil)
	h.HandleAgentDownload(c)
	var m map[string]map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("manifest json: %v", err)
	}
	want := map[string]string{
		"windows": "OpenIDX-0.5.0.msi",
		"linux":   "openidx-agent-0.5.0.x86_64.rpm",
		"android": "openidx-agent-v1.46.0-universal.apk",
	}
	for k, v := range want {
		if m[k]["filename"] != v {
			t.Errorf("%s = %q, want %q", k, m[k]["filename"], v)
		}
	}
	if _, ok := m["macos"]; ok {
		t.Errorf("macos advertised with no macOS installer: %+v", m["macos"])
	}
}

func TestBetterInstallerLinuxPreference(t *testing.T) {
	cases := []struct{ a, b string }{
		{"openidx-agent_0.5.0_amd64.deb", "openidx-agent-0.5.0.x86_64.rpm"},
		{"openidx-agent-0.5.0.x86_64.rpm", "openidx-agent_0.5.0_arm64.deb"},
		{"openidx-agent_0.5.0_arm64.deb", "openidx-agent-0.5.0.aarch64.rpm"},
		{"openidx-agent_0.10.0_arm64.deb", "openidx-agent_0.9.0_amd64.deb"},
		{"openidx-agent_0.1.0_amd64.deb", "openidx-agent-linux-amd64.deb"},
	}
	for _, tc := range cases {
		if !betterInstaller(tc.a, tc.b) {
			t.Errorf("betterInstaller(%q, %q) = false, want true", tc.a, tc.b)
		}
		if betterInstaller(tc.b, tc.a) {
			t.Errorf("betterInstaller(%q, %q) = true, want false", tc.b, tc.a)
		}
	}
}
