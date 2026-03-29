package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testLogger(t *testing.T) *zap.Logger {
	t.Helper()
	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	return logger
}

func TestLoader_Discover_ValidPlugin(t *testing.T) {
	pluginDir := t.TempDir()
	subDir := filepath.Join(pluginDir, "my-plugin")
	require.NoError(t, os.MkdirAll(subDir, 0755))

	manifest := `{"name":"my-plugin","version":"1.0.0","description":"Test plugin","platforms":["linux","darwin"],"check_types":["hello","world"],"timeout_seconds":10}`
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "manifest.json"), []byte(manifest), 0644))

	script := "#!/bin/bash\necho '{\"status\":\"pass\",\"score\":1.0}'\n"
	execPath := filepath.Join(subDir, "my-plugin.sh")
	require.NoError(t, os.WriteFile(execPath, []byte(script), 0755))

	loader := NewLoader(pluginDir, testLogger(t))
	plugins, err := loader.Discover()
	require.NoError(t, err)
	// Two check types → two PluginChecks
	assert.Len(t, plugins, 2)

	names := make(map[string]bool)
	for _, p := range plugins {
		names[p.Name()] = true
	}
	assert.True(t, names["hello"])
	assert.True(t, names["world"])
}

func TestLoader_Discover_EmptyDir(t *testing.T) {
	pluginDir := t.TempDir()
	loader := NewLoader(pluginDir, testLogger(t))
	plugins, err := loader.Discover()
	require.NoError(t, err)
	assert.Nil(t, plugins)
}

func TestLoader_Discover_MissingDir(t *testing.T) {
	loader := NewLoader("/nonexistent/path/that/does/not/exist", testLogger(t))
	plugins, err := loader.Discover()
	require.NoError(t, err)
	assert.Nil(t, plugins)
}

func TestLoader_Discover_SkipsInvalidManifest(t *testing.T) {
	pluginDir := t.TempDir()
	subDir := filepath.Join(pluginDir, "bad-plugin")
	require.NoError(t, os.MkdirAll(subDir, 0755))

	// Write an invalid manifest
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "manifest.json"), []byte("{invalid json"), 0644))

	loader := NewLoader(pluginDir, testLogger(t))
	plugins, err := loader.Discover()
	require.NoError(t, err)
	assert.Nil(t, plugins)
}

func TestLoader_Discover_SkipsNoExecutable(t *testing.T) {
	pluginDir := t.TempDir()
	subDir := filepath.Join(pluginDir, "no-exec-plugin")
	require.NoError(t, os.MkdirAll(subDir, 0755))

	manifest := `{"name":"no-exec-plugin","version":"1.0.0","platforms":["linux","darwin"],"check_types":["test"],"timeout_seconds":5}`
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "manifest.json"), []byte(manifest), 0644))
	// No executable file written

	loader := NewLoader(pluginDir, testLogger(t))
	plugins, err := loader.Discover()
	require.NoError(t, err)
	assert.Nil(t, plugins)
}

func TestLoader_Discover_SkipsNonDirEntries(t *testing.T) {
	pluginDir := t.TempDir()
	// Write a plain file (not a directory) at the top level
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "not-a-dir"), []byte("hello"), 0644))

	loader := NewLoader(pluginDir, testLogger(t))
	plugins, err := loader.Discover()
	require.NoError(t, err)
	assert.Nil(t, plugins)
}
