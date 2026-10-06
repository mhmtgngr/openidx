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
	pc := NewPluginCheck(&Manifest{Name: "test"}, "/bin/true", "", "my_check")
	assert.Equal(t, "my_check", pc.Name())
}

func TestPluginCheck_Run_Success(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "plugin.sh")
	body := []byte("#!/bin/bash\necho '{\"status\":\"pass\",\"score\":0.95,\"message\":\"all good\"}'")
	os.WriteFile(script, body, 0755)

	pc := NewPluginCheck(&Manifest{Name: "test", TimeoutSeconds: 5}, script, sha256Hex(body), "test_check")
	result := pc.Run(context.Background(), nil)

	assert.Equal(t, checks.StatusPass, result.Status)
	assert.Equal(t, 0.95, result.Score)
	assert.Equal(t, "all good", result.Message)
}

// TestPluginCheck_Run_RefusesAnExecutableItWasNotGiven is the other side of
// Run_Success: the same script is not run when the digest recorded at load
// time is missing or belongs to other bytes.
func TestPluginCheck_Run_RefusesAnExecutableItWasNotGiven(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "plugin.sh")
	marker := filepath.Join(dir, "ran")
	body := []byte("#!/bin/sh\ntouch " + marker + "\necho '{\"status\":\"pass\",\"score\":1}'\n")
	if err := os.WriteFile(script, body, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, digest, want string }{
		{"no digest recorded", "", "no digest was recorded"},
		{"another file's digest", sha256Hex([]byte("something else")), "changed since it was loaded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := NewPluginCheck(&Manifest{Name: "test", TimeoutSeconds: 5}, script, tc.digest, "test_check")
			result := pc.Run(context.Background(), nil)
			assert.Equal(t, checks.StatusError, result.Status)
			assert.Contains(t, result.Message, tc.want)
			_, err := os.Stat(marker)
			assert.True(t, os.IsNotExist(err), "the executable was run")
		})
	}
}

func TestPluginCheck_Run_PluginError(t *testing.T) {
	pc := NewPluginCheck(&Manifest{Name: "test", TimeoutSeconds: 1}, "/nonexistent/plugin", sha256Hex(nil), "test_check")
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
