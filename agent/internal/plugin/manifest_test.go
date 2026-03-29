package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadManifest_Valid(t *testing.T) {
	dir := t.TempDir()
	data := `{"name":"test-plugin","version":"1.0.0","description":"Test","platforms":["linux"],"check_types":["test_check"],"timeout_seconds":15}`
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(data), 0644)

	m, err := LoadManifest(dir)
	require.NoError(t, err)
	assert.Equal(t, "test-plugin", m.Name)
	assert.Equal(t, "1.0.0", m.Version)
	assert.Equal(t, []string{"linux"}, m.Platforms)
	assert.Equal(t, []string{"test_check"}, m.CheckTypes)
	assert.Equal(t, 15, m.TimeoutSeconds)
}

func TestLoadManifest_MissingFile(t *testing.T) {
	_, err := LoadManifest(t.TempDir())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read manifest")
}

func TestLoadManifest_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{invalid"), 0644)
	_, err := LoadManifest(dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse manifest")
}

func TestLoadManifest_MissingName(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"check_types":["x"]}`), 0644)
	_, err := LoadManifest(dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestLoadManifest_DefaultTimeout(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"name":"p","check_types":["x"]}`), 0644)
	m, err := LoadManifest(dir)
	require.NoError(t, err)
	assert.Equal(t, 30, m.TimeoutSeconds)
}
