package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTempScript writes a bash script to a temp dir, makes it executable,
// and returns its path.
func writeTempScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "plugin.sh")
	err := os.WriteFile(path, []byte("#!/bin/bash\n"+body+"\n"), 0755)
	require.NoError(t, err)
	return path
}

func TestExecute_Success(t *testing.T) {
	script := writeTempScript(t, `cat <<'EOF'
{"status":"pass","score":1.0,"message":"ok"}
EOF`)

	req := &Request{Action: "check", Type: "test_check"}
	resp, err := Execute(context.Background(), script, req, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "pass", resp.Status)
	assert.Equal(t, 1.0, resp.Score)
	assert.Equal(t, "ok", resp.Message)
}

func TestExecute_Timeout(t *testing.T) {
	script := writeTempScript(t, `sleep 60`)

	req := &Request{Action: "check"}
	_, err := Execute(context.Background(), script, req, 100*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
}

func TestExecute_InvalidJSON(t *testing.T) {
	script := writeTempScript(t, `echo "not json"`)

	req := &Request{Action: "check"}
	_, err := Execute(context.Background(), script, req, 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse plugin response")
}
