package agent

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentConfig_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()

	original := &AgentConfig{
		ServerURL:  "https://openidx.example.com",
		AgentID:    "agent-abc-123",
		DeviceID:   "device-xyz-456",
		EnrolledAt: "2026-03-29T00:00:00Z",
		AuthToken:  "super-secret-token",
	}

	err := original.Save(dir)
	require.NoError(t, err)

	// Verify the file was written with restrictive permissions.
	info, err := os.Stat(dir + "/agent.json")
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	loaded, err := LoadConfig(dir)
	require.NoError(t, err)

	assert.Equal(t, original.ServerURL, loaded.ServerURL)
	assert.Equal(t, original.AgentID, loaded.AgentID)
	assert.Equal(t, original.DeviceID, loaded.DeviceID)
	assert.Equal(t, original.EnrolledAt, loaded.EnrolledAt)
	assert.Equal(t, original.AuthToken, loaded.AuthToken)
}

func TestLoadConfig_NotFound(t *testing.T) {
	dir := t.TempDir()

	_, err := LoadConfig(dir)
	assert.Error(t, err)
}

func TestServerConfig_Defaults(t *testing.T) {
	cfg := DefaultServerConfig()

	assert.Equal(t, "1h", cfg.ReportInterval)
	require.Len(t, cfg.Checks, 3)

	checksByType := make(map[string]CheckConfig, len(cfg.Checks))
	for _, c := range cfg.Checks {
		checksByType[c.Type] = c
	}

	osCheck, ok := checksByType["os_version"]
	require.True(t, ok, "expected os_version check")
	assert.Equal(t, "high", osCheck.Severity)
	assert.Equal(t, "1h", osCheck.Interval)

	diskCheck, ok := checksByType["disk_encryption"]
	require.True(t, ok, "expected disk_encryption check")
	assert.Equal(t, "critical", diskCheck.Severity)
	assert.Equal(t, "6h", diskCheck.Interval)

	procCheck, ok := checksByType["process_running"]
	require.True(t, ok, "expected process_running check")
	assert.Equal(t, "medium", procCheck.Severity)
	assert.Equal(t, "15m", procCheck.Interval)
}
