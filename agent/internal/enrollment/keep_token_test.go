package enrollment

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/secretfile"
)

func TestKeepTokenSealsTheFleetToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"agent_id": "a1", "device_id": "d1", "auth_token": "at"})
	}))
	defer srv.Close()
	dir := t.TempDir()
	on := true
	_, err := EnrollWithOptions(zap.NewNop(), Options{
		ServerURL: srv.URL, Token: "fleet-secret-token", ConfigDir: dir,
		KeepToken: true, Tunnel: &on, LogLevel: "debug",
	})
	require.NoError(t, err)

	raw, err := os.ReadFile(SealedTokenPath(dir))
	require.NoError(t, err)
	if runtime.GOOS == "windows" {
		assert.True(t, secretfile.IsProtected(raw), "the sealed token must be DPAPI-protected")
		assert.NotContains(t, string(raw), "fleet-secret-token")
	} else {
		st, err := os.Stat(SealedTokenPath(dir))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}
	got, err := LoadSealedToken(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "fleet-secret-token", got.Token)
	assert.Equal(t, srv.URL, got.ServerURL)

	cfg, err := agent.LoadConfig(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg.Tunnel)
	assert.True(t, cfg.Tunnel.Enabled)
	assert.Equal(t, "debug", cfg.LogLevel)
}

func TestWithoutKeepTokenNothingIsSealed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"agent_id": "a1", "device_id": "d1", "auth_token": "at"})
	}))
	defer srv.Close()
	dir := t.TempDir()
	_, err := EnrollWithOptions(zap.NewNop(), Options{ServerURL: srv.URL, Token: "tok", ConfigDir: dir})
	require.NoError(t, err)
	got, err := LoadSealedToken(dir)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestKeepTokenSurvivesAFailedEnrolment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	dir := t.TempDir()
	_, err := EnrollWithOptions(zap.NewNop(), Options{ServerURL: srv.URL, Token: "tok", ConfigDir: dir, KeepToken: true})
	require.Error(t, err)
	got, err := LoadSealedToken(dir)
	require.NoError(t, err)
	require.NotNil(t, got, "a failed enrolment must leave the token for the service to retry")
}

func TestRevokedEnrolmentDeletesTheSealedToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"agent_revoked"}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	_, err := EnrollWithOptions(zap.NewNop(), Options{ServerURL: srv.URL, Token: "tok", ConfigDir: dir, KeepToken: true})
	require.Error(t, err)
	_, statErr := os.Stat(SealedTokenPath(dir))
	assert.True(t, os.IsNotExist(statErr), "403 agent_revoked must delete the sealed token")
}

func TestSealTokenRefusesAnEmptyToken(t *testing.T) {
	err := SealToken(t.TempDir(), SealedToken{ServerURL: "https://x"})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "token"))
}
