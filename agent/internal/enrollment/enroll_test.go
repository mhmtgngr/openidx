package enrollment

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	// No Ziti JWT in response — JWT file should not be created.
	assert.Empty(t, result.ZitiIdentity)
	_, statErr := os.Stat(filepath.Join(dir, "ziti-enrollment.jwt"))
	assert.True(t, os.IsNotExist(statErr), "ziti-enrollment.jwt should not exist when server omits ziti_jwt")
}

func TestEnroll_WithZitiJWT(t *testing.T) {
	const fakeJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.payload"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/access/agent/enroll", r.URL.Path)
		json.NewEncoder(w).Encode(map[string]string{
			"agent_id":   "agent-ziti-001",
			"device_id":  "device-ziti-001",
			"auth_token": "tok-ziti",
			"ziti_jwt":   fakeJWT,
		})
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	dir := t.TempDir()

	result, err := Enroll(logger, server.URL, "enrollment-token", dir)
	require.NoError(t, err)
	assert.Equal(t, "agent-ziti-001", result.AgentConfig.AgentID)

	// JWT file must be written with the exact token contents.
	jwtPath := filepath.Join(dir, "ziti-enrollment.jwt")
	data, readErr := os.ReadFile(jwtPath)
	require.NoError(t, readErr, "ziti-enrollment.jwt should be created")
	assert.Equal(t, fakeJWT, string(data))

	// ZitiIdentityFile path should be set in config and result.
	expectedIdentityPath := filepath.Join(dir, "ziti-identity.json")
	assert.Equal(t, expectedIdentityPath, result.AgentConfig.ZitiIdentityFile)
	assert.Equal(t, expectedIdentityPath, result.ZitiIdentity)

	// Config on disk should also reflect the ZitiIdentityFile path.
	assert.Equal(t, expectedIdentityPath, result.AgentConfig.ZitiIdentityFile)
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
