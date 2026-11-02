package access

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// agentDownloadsDir is the directory holding per-OS agent installers (msi/pkg/
// deb/rpm). Configurable via AGENT_DOWNLOADS_DIR.
func (h *AgentAPIHandler) agentDownloadsDir() string {
	if c := h.cfg(); c != nil && strings.TrimSpace(c.AgentDownloadsDir) != "" {
		return c.AgentDownloadsDir
	}
	return "deployments/downloads"
}

// osForInstaller maps an installer filename extension to a wizard OS key, or "".
func osForInstaller(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".msi", ".exe":
		return "windows"
	case ".pkg", ".dmg":
		return "macos"
	case ".deb", ".rpm":
		return "linux"
	case ".apk":
		return "android"
	}
	return ""
}

// downloadNameRe rejects anything but a bare filename (no path traversal).
var downloadNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// windowsTrustScript is the name the trust-and-install script is served
// under when an operator places it beside the MSI (go-live-windows.md).
const windowsTrustScript = "trust-and-install-openidx-agent.ps1"

// HandleAgentDownload backs GET /downloads/:file (public, no auth — like the
// legacy APK route it replaces). It dispatches the manifest, the Android APK,
// and per-OS installers from the downloads dir. Using one param route avoids a
// gin static-vs-wildcard conflict at /downloads/*.
func (h *AgentAPIHandler) HandleAgentDownload(c *gin.Context) {
	name := c.Param("file")
	switch name {
	case "agent-manifest.json":
		h.handleAgentManifest(c)
		return
	case "openidx-agent.apk":
		h.HandleAPKDownload(c)
		return
	}
	if !downloadNameRe.MatchString(name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
		return
	}
	full := filepath.Join(h.agentDownloadsDir(), name)
	if fi, err := os.Stat(full); err != nil || fi.IsDir() {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.FileAttachment(full, name)
}

// installerVersionRe pulls the first dotted MAJOR.MINOR.PATCH out of an
// installer filename: OpenIDX-0.5.0.msi, openidx-agent_0.5.0_amd64.deb,
// openidx-agent-0.5.0.x86_64.rpm, openidx-agent-v1.46.0-arm64.apk.
var installerVersionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// installerVersion returns the semver triple in name, or zeros when the name
// carries none (an unversioned file then loses to any versioned one).
func installerVersion(name string) [3]int {
	var v [3]int
	m := installerVersionRe.FindStringSubmatch(name)
	if m == nil {
		return v
	}
	for i := 0; i < 3; i++ {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v
}

// installerArmRe matches the ARM architecture tags Linux packages use.
var installerArmRe = regexp.MustCompile(`(?i)(arm64|aarch64|armhf|armv7|armel)`)

// installerPreference ranks same-version installers for one OS; lower wins.
// Windows prefers the MSI (silent install, GPO-deployable) over a bare exe;
// macOS the pkg over a dmg; Linux the x86-64 deb, then the x86-64 rpm, then
// the ARM builds — most enrolling desktops are x86-64 Debian/Ubuntu.
func installerPreference(name string) int {
	ext := strings.ToLower(filepath.Ext(name))
	switch osForInstaller(name) {
	case "windows":
		if ext == ".msi" {
			return 0
		}
		return 1
	case "macos":
		if ext == ".pkg" {
			return 0
		}
		return 1
	case "linux":
		rank := 0
		if ext == ".rpm" {
			rank = 1
		}
		if installerArmRe.MatchString(name) {
			rank += 2
		}
		return rank
	}
	return 0
}

// betterInstaller reports whether a should be advertised over b for the same
// OS: the higher version wins, then the preferred format/architecture, then
// the lexically smaller name so the choice never depends on directory order.
func betterInstaller(a, b string) bool {
	va, vb := installerVersion(a), installerVersion(b)
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	if pa, pb := installerPreference(a), installerPreference(b); pa != pb {
		return pa < pb
	}
	return a < b
}

// handleAgentManifest advertises the available per-OS installers so the
// Add-a-device wizard can render a download button. Keys are wizard OS keys
// (windows/macos/linux/android); missing OSes are simply omitted. When the
// directory holds several installers for one OS (old releases left behind,
// msi and exe, deb and rpm) the best one is picked by betterInstaller.
func (h *AgentAPIHandler) handleAgentManifest(c *gin.Context) {
	out := map[string]gin.H{}
	dir := h.agentDownloadsDir()
	entries, _ := os.ReadDir(dir)
	best := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		osKey := osForInstaller(e.Name())
		if osKey == "" {
			continue
		}
		if cur, seen := best[osKey]; seen && !betterInstaller(e.Name(), cur) {
			continue
		}
		best[osKey] = e.Name()
	}
	for osKey, name := range best {
		sum, _ := sha256File(filepath.Join(dir, name))
		out[osKey] = gin.H{"url": "/downloads/" + name, "filename": name, "sha256": sum}
	}
	// Until the MSI is signed with a public certificate, a Windows machine
	// installs it through the trust script (agent/scripts/), which trusts the
	// project's signing certificate, checks the MSI against this manifest and
	// runs msiexec. The wizard shows that path when the script is served.
	if win, ok := out["windows"]; ok {
		if fi, err := os.Stat(filepath.Join(dir, windowsTrustScript)); err == nil && !fi.IsDir() {
			win["trust_script"] = "/downloads/" + windowsTrustScript
		}
	}
	// The Android APK historically lives at its own path; surface it if present
	// and not already provided by the downloads dir.
	if _, ok := out["android"]; !ok {
		if _, err := os.Stat(androidAPKPath); err == nil {
			sum, _ := sha256File(androidAPKPath)
			out["android"] = gin.H{"url": "/downloads/openidx-agent.apk", "filename": "openidx-agent.apk", "sha256": sum}
		}
	}
	c.JSON(http.StatusOK, out)
}

// sha256File returns the hex SHA-256 of a file.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hsh := sha256.New()
	if _, err := io.Copy(hsh, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hsh.Sum(nil)), nil
}
