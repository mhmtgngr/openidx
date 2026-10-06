//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// writeHelloPlugin lays down a plugin the loader accepts: a directory with a
// manifest and a matching executable, under a root only the owner can write.
func writeHelloPlugin(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, "hello")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(
		`{"name":"hello","version":"1.0.0","platforms":["all"],"check_types":["hello_check"],"timeout_seconds":5}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hello"), []byte("#!/bin/sh\nexit 0\n"), 0o755))
}

// TestConfigTrustedReadsTheModeBits: a config only its owner can write is
// trusted; one the group or everyone can write is not.
func TestConfigTrustedReadsTheModeBits(t *testing.T) {
	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: "https://openidx.test", AgentID: "a1", AuthToken: "tok"})
	require.NoError(t, ConfigTrusted(dir), "Save writes 0600, which is trusted")

	require.NoError(t, os.Chmod(ConfigPath(dir), 0o666))
	err := ConfigTrusted(dir)
	require.Error(t, err, "a world-writable agent.json is not to be obeyed")
	require.Contains(t, err.Error(), "writable")

	require.NoError(t, os.Chmod(ConfigPath(dir), 0o644))
	require.NoError(t, ConfigTrusted(dir), "readable by others is fine; the tray reads it")
}

// TestPluginsAreNotLoadedFromAnUntrustedConfig: the same plugin directory is
// loaded from a 0600 agent.json and ignored from a 0666 one. Both configs set
// allow_unsigned_plugins, which shows that the switch is not obeyed from an
// untrusted file either.
func TestPluginsAreNotLoadedFromAnUntrustedConfig(t *testing.T) {
	plugins := t.TempDir()
	writeHelloPlugin(t, plugins)

	trusted := t.TempDir()
	saveTestConfig(t, trusted, &AgentConfig{ServerURL: "https://openidx.test", AgentID: "a1", AuthToken: "tok", PluginDir: plugins, AllowUnsignedPlugins: true})
	a, err := NewAgent(zap.NewNop(), trusted)
	require.NoError(t, err)
	a.LoadPlugins()
	_, ok := a.registry.Get("hello_check")
	require.True(t, ok, "a plugin named by a trusted config is registered")

	untrusted := t.TempDir()
	saveTestConfig(t, untrusted, &AgentConfig{ServerURL: "https://openidx.test", AgentID: "a1", AuthToken: "tok", PluginDir: plugins, AllowUnsignedPlugins: true})
	require.NoError(t, os.Chmod(ConfigPath(untrusted), 0o666))
	b, err := NewAgent(zap.NewNop(), untrusted)
	require.NoError(t, err)
	b.LoadPlugins()
	_, ok = b.registry.Get("hello_check")
	require.False(t, ok, "a plugin directory named by a world-writable config is ignored")
}
