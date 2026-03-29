package enrollment

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestEnroll_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/access/agent/enroll", r.URL.Path)
		json.NewEncoder(w).Encode(map[string]string{
			"agent_id":   "agent-test-001",
			"device_id":  "device-test-001",
			"auth_token": "tok-123",
		})
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	dir := t.TempDir()

	result, err := Enroll(logger, server.URL, "enrollment-token", dir)
	require.NoError(t, err)
	assert.Equal(t, "agent-test-001", result.AgentConfig.AgentID)
	assert.Equal(t, "device-test-001", result.AgentConfig.DeviceID)
	assert.Equal(t, "tok-123", result.AgentConfig.AuthToken)
	assert.Equal(t, server.URL, result.AgentConfig.ServerURL)
}

func TestEnroll_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	_, err := Enroll(logger, server.URL, "bad-token", t.TempDir())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server enrollment failed")
}
