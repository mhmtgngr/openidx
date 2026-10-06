//go:build !windows

package agent

import (
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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/checks"
	"github.com/openidx/openidx/agent/internal/plugin"
)

// These cases drive LoadPlugins from agent.json, so they check the wiring the
// plugin package's own tests cannot: that the publisher plugins are verified
// against is the one update_trusted_cert names, that allow_unsigned_plugins is
// read from the config, and that the built-in checks are the reserved names.

// testSigner is a throwaway publisher: an RSA key and a self-signed
// certificate, the shape of the pinned release publisher.
type testSigner struct {
	key     *rsa.PrivateKey
	certPEM string
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Test Plugin Publisher"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return &testSigner{key: key, certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// sign writes plugin.sig for the plugin in dir over exactly what
// `openidx-agent plugin digest --dir` prints.
func (s *testSigner) sign(t *testing.T, dir string) {
	t.Helper()
	input, err := plugin.SigningInput(dir)
	require.NoError(t, err)
	sum := sha256.Sum256(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plugin.sig"), []byte(base64.StdEncoding.EncodeToString(sig)), 0o644))
}

// writePluginWithChecks is writeHelloPlugin with the check types chosen.
func writePluginWithChecks(t *testing.T, root, name string, checkTypes ...string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	m, err := json.Marshal(map[string]any{
		"name": name, "version": "1.0.0", "platforms": []string{"all"},
		"check_types": checkTypes, "timeout_seconds": 5,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), m, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755))
	return dir
}

// loadPluginsWith builds an agent from cfg, registers the built-in checks and
// then the plugins, in the order the service and `serve` use.
func loadPluginsWith(t *testing.T, cfg *AgentConfig) *Agent {
	t.Helper()
	cfg.ServerURL, cfg.AgentID, cfg.AuthToken = "https://openidx.test", "a1", "tok"
	dir := t.TempDir()
	saveTestConfig(t, dir, cfg)
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.RegisterBuiltinChecks()
	a.LoadPlugins()
	return a
}

func TestLoadPluginsVerifiesAgainstThePublisherInUpdateTrustedCert(t *testing.T) {
	signer := newTestSigner(t)
	plugins := t.TempDir()
	writeHelloPlugin(t, plugins)
	signer.sign(t, filepath.Join(plugins, "hello"))

	a := loadPluginsWith(t, &AgentConfig{PluginDir: plugins, UpdateTrustedCertPEM: signer.certPEM})
	_, ok := a.registry.Get("hello_check")
	require.True(t, ok, "a plugin signed by the publisher update_trusted_cert names is registered")

	// The same signed folder under the default publisher, the pinned OpenIDX
	// release key, which did not sign it.
	b := loadPluginsWith(t, &AgentConfig{PluginDir: plugins})
	_, ok = b.registry.Get("hello_check")
	require.False(t, ok, "a plugin signed by a key other than the configured publisher is refused")
}

func TestAllowUnsignedPluginsInAgentJSON(t *testing.T) {
	plugins := t.TempDir()
	writeHelloPlugin(t, plugins)

	a := loadPluginsWith(t, &AgentConfig{PluginDir: plugins})
	_, ok := a.registry.Get("hello_check")
	require.False(t, ok, "an unsigned plugin is refused by default")

	b := loadPluginsWith(t, &AgentConfig{PluginDir: plugins, AllowUnsignedPlugins: true})
	_, ok = b.registry.Get("hello_check")
	require.True(t, ok, "allow_unsigned_plugins loads an unsigned plugin")
}

// TestAPluginCannotReplaceABuiltinCheck. Plugins are registered after the
// built-in checks and the registry keeps the last registration, so before this
// a plugin declaring disk_encryption replaced the agent's own check with
// whatever the plugin reported. Signed or not, it is refused whole.
func TestAPluginCannotReplaceABuiltinCheck(t *testing.T) {
	signer := newTestSigner(t)
	for _, tc := range []struct {
		name string
		cfg  func(plugins string) *AgentConfig
	}{
		{"signed by the configured publisher", func(p string) *AgentConfig {
			return &AgentConfig{PluginDir: p, UpdateTrustedCertPEM: signer.certPEM}
		}},
		{"unsigned under allow_unsigned_plugins", func(p string) *AgentConfig {
			return &AgentConfig{PluginDir: p, AllowUnsignedPlugins: true}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plugins := t.TempDir()
			signer.sign(t, writePluginWithChecks(t, plugins, "shadow", "shadow_check", "disk_encryption"))

			a := loadPluginsWith(t, tc.cfg(plugins))
			got, ok := a.registry.Get("disk_encryption")
			require.True(t, ok)
			require.IsType(t, &checks.DiskEncryptionCheck{}, got,
				"disk_encryption is no longer the built-in check; a plugin replaced it")
			_, ok = a.registry.Get("shadow_check")
			require.False(t, ok, "the plugin's other check types were registered; it must be refused whole")
		})
	}
}
