package access

// Box update mirror. Windows agents fetch updates only from the OpenIDX box,
// never from github.com: scripts/agent-mirror.sh copies an agent-v* release's
// MSI and latest.json into <downloads>/agent/<channel>/, and this file serves
// them at /downloads/agent/<channel>/latest.json and /downloads/agent/<channel>/<msi>.
//
// The upstream manifest names a github.com URL, and that URL is covered by its
// signature. So the box rewrites url to itself and signs the manifest again
// with AGENT_MANIFEST_SIGNING_KEY, the release publisher key the agent pins
// (agent/internal/updater/release-publisher.cer). version and sha256 are
// passed through unchanged: the mirror script checked both against the
// upstream signature before installing them.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// updateManifestSigningDomain must equal signingDomain in
// agent/internal/updater/trust.go.
const updateManifestSigningDomain = "openidx-agent-update-manifest/v1"

// mirrorManifest is latest.json as the agent reads it (updater.Manifest).
type mirrorManifest struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

// updateManifestSigningInput is byte-for-byte updater.signingInput.
func updateManifestSigningInput(m *mirrorManifest) ([]byte, error) {
	var b strings.Builder
	b.WriteString(updateManifestSigningDomain + "\n")
	for _, f := range [][2]string{{"version", m.Version}, {"url", m.URL}, {"sha256", m.SHA256}} {
		if strings.ContainsAny(f[1], "\n\r") {
			return nil, fmt.Errorf("manifest field %q contains a line break", f[0])
		}
		fmt.Fprintf(&b, "%s=%s\n", f[0], f[1])
	}
	return []byte(b.String()), nil
}

func signUpdateManifest(key *rsa.PrivateKey, m *mirrorManifest) error {
	input, err := updateManifestSigningInput(m)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return err
	}
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

func validMirrorChannel(ch string) bool {
	_, ok := canonicalMirrorChannel(ch)
	return ok
}

// canonicalMirrorChannel maps a requested channel to the package constant, so
// nothing a request supplies reaches a file path or a log line.
func canonicalMirrorChannel(ch string) (string, bool) {
	switch ch {
	case updateChannelStable:
		return updateChannelStable, true
	case updateChannelBeta:
		return updateChannelBeta, true
	}
	return "", false
}

func (h *AgentAPIHandler) mirrorDir(channel string) string {
	return filepath.Join(h.agentDownloadsDir(), "agent", channel)
}

// boxOrigin is the public origin agents reach the box at: the OAuth issuer's
// origin (agents already reach it to enrol and sign in), else PublicBaseURL.
// A loopback origin is skipped: PublicBaseURL defaults to
// http://localhost:3000, which outranked the issuer and sent every agent to
// an MSI at "localhost". "" when nothing usable is configured.
func (h *AgentAPIHandler) boxOrigin() string {
	c := h.cfg()
	if c == nil {
		return ""
	}
	for _, raw := range []string{c.OAuthIssuer, c.PublicBaseURL} {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		if isLoopbackHost(u.Hostname()) {
			continue
		}
		return u.Scheme + "://" + u.Host
	}
	return ""
}

// readMirrorManifest loads the mirrored upstream latest.json for channel, and
// requires the artifact it names to be in the mirror.
func (h *AgentAPIHandler) readMirrorManifest(channel string) (*mirrorManifest, string, error) {
	dir := h.mirrorDir(channel)
	raw, err := os.ReadFile(filepath.Join(dir, "latest.json"))
	if err != nil {
		return nil, "", err
	}
	var m mirrorManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, "", fmt.Errorf("mirrored latest.json: %w", err)
	}
	u, err := url.Parse(m.URL)
	if err != nil {
		return nil, "", fmt.Errorf("mirrored latest.json url: %w", err)
	}
	name := pathBase(u.Path)
	if !downloadNameRe.MatchString(name) || name == "latest.json" {
		return nil, "", fmt.Errorf("mirrored latest.json names an unusable artifact %q", name)
	}
	if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.IsDir() {
		return nil, "", fmt.Errorf("mirrored artifact %s is missing", name)
	}
	return &m, name, nil
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// mirrorManifestURL is the box URL of channel's manifest when the box holds a
// usable mirror of it and can sign it, else "".
func (h *AgentAPIHandler) mirrorManifestURL(channel string) string {
	origin := h.boxOrigin()
	if origin == "" || !validMirrorChannel(channel) {
		return ""
	}
	if key, err := manifestSigningKey(); err != nil || key == nil {
		return ""
	}
	if _, _, err := h.readMirrorManifest(channel); err != nil {
		return ""
	}
	return origin + "/downloads/agent/" + channel + "/latest.json"
}

// HandleAgentMirror backs GET /downloads/agent/:channel/:file (public, like
// /downloads/:file).
func (h *AgentAPIHandler) HandleAgentMirror(c *gin.Context) {
	channel, ok := canonicalMirrorChannel(c.Param("channel"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown channel"})
		return
	}
	name := c.Param("file")
	if !downloadNameRe.MatchString(name) || strings.HasPrefix(name, ".") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
		return
	}
	m, artifact, err := h.readMirrorManifest(channel)
	if err != nil {
		if !os.IsNotExist(err) {
			h.logger.Warn("agent update mirror unusable", zap.String("channel", channel), zap.Error(err))
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not mirrored"})
		return
	}
	if name != "latest.json" {
		if name != artifact {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		// artifact came from the mirror's own latest.json and was checked
		// against downloadNameRe; serve that, not the request's string.
		c.FileAttachment(filepath.Join(h.mirrorDir(channel), artifact), artifact)
		return
	}
	origin := h.boxOrigin()
	key, kerr := manifestSigningKey()
	if origin == "" || kerr != nil || key == nil {
		h.logger.Error("agent update mirror cannot sign: needs AGENT_MANIFEST_SIGNING_KEY and a public URL",
			zap.Bool("origin_set", origin != ""), zap.Error(kerr))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "update mirror signing not configured"})
		return
	}
	m.URL = origin + "/downloads/agent/" + channel + "/" + artifact
	if err := signUpdateManifest(key, m); err != nil {
		h.logger.Error("agent update mirror signing failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "manifest signing failed"})
		return
	}
	c.Header("Cache-Control", "no-cache")
	c.JSON(http.StatusOK, m)
}
