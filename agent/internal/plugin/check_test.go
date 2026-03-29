package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/openidx/openidx/agent/internal/checks"
	"github.com/stretchr/testify/assert"
)

func TestPluginCheck_ImplementsCheck(t *testing.T) {
	var _ checks.Check = (*PluginCheck)(nil)
}

func TestPluginCheck_Name(t *testing.T) {
	pc := NewPluginCheck(&Manifest{Name: "test"}, "/bin/true", "my_check")
	assert.Equal(t, "my_check", pc.Name())
}

func TestPluginCheck_Run_Success(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "plugin.sh")
	os.WriteFile(script, []byte("#!/bin/bash\necho '{\"status\":\"pass\",\"score\":0.95,\"message\":\"all good\"}'"), 0755)

	pc := NewPluginCheck(&Manifest{Name: "test", TimeoutSeconds: 5}, script, "test_check")
	result := pc.Run(context.Background(), nil)

	assert.Equal(t, checks.StatusPass, result.Status)
	assert.Equal(t, 0.95, result.Score)
	assert.Equal(t, "all good", result.Message)
}

func TestPluginCheck_Run_PluginError(t *testing.T) {
	pc := NewPluginCheck(&Manifest{Name: "test", TimeoutSeconds: 1}, "/nonexistent/plugin", "test_check")
	result := pc.Run(context.Background(), nil)

	assert.Equal(t, checks.StatusError, result.Status)
	assert.Contains(t, result.Message, "plugin error")
}

func TestMapStatus(t *testing.T) {
	assert.Equal(t, checks.StatusPass, mapStatus("pass"))
	assert.Equal(t, checks.StatusFail, mapStatus("fail"))
	assert.Equal(t, checks.StatusWarn, mapStatus("warn"))
	assert.Equal(t, checks.StatusError, mapStatus("error"))
	assert.Equal(t, checks.StatusError, mapStatus("unknown"))
}
