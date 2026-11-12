package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestAuthInvalidReenrolsFromSealedToken: the server stops accepting the
// device's credential. After authFailThreshold refusals the service enrols
// again with its sealed fleet token, saves the new credential, and reports.
func TestAuthInvalidReenrolsFromSealedToken(t *testing.T) {
	var good atomic.Value
	good.Store("the-servers-token")
	var reports, enrols atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/agent/enroll") {
			if r.Header.Get("Authorization") != "Bearer fleet-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["device_fingerprint"] == "" {
				t.Error("the re-enrolment carries no fingerprint")
			}
			enrols.Add(1)
			good.Store("fresh-token")
			_, _ = w.Write([]byte(`{"agent_id":"a1","device_id":"d1","auth_token":"fresh-token","status":"active"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+good.Load().(string) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/agent/config"):
			_, _ = w.Write([]byte(`{"checks":[{"type":"always","severity":"high"}],"report_interval":"1h"}`))
		case strings.HasSuffix(r.URL.Path, "/agent/report"):
			reports.Add(1)
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "stale"})
	require.NoError(t, SaveSealedToken(dir, "fleet-token"))
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.DisableRemoteSupport = true
	a.registry.Register("always", &mockPassCheck{name: "always"})

	for i := 1; i < authFailThreshold; i++ {
		_ = a.RunOnce(context.Background())
		require.Equal(t, int32(0), enrols.Load(), "refusal %d is not yet a state", i)
	}
	require.NoError(t, a.RunOnce(context.Background()))
	require.Equal(t, int32(1), enrols.Load(), "the sealed token re-enrols the device once")
	require.False(t, a.AuthInvalid())
	require.Equal(t, int32(1), reports.Load(), "the device reports with its new credential")

	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.Equal(t, "fresh-token", cfg.AuthToken, "the new credential is saved")
	require.Equal(t, "fleet-token", LoadSealedToken(dir), "the sealed token stays for next time")
}

// TestRevokedDeviceForgetsItsSealedToken: a 403 from /agent/config is a
// revoke, and the device deletes its sealed token so nothing brings it back
// on its own.
func TestRevokedDeviceForgetsItsSealedToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "t"})
	require.NoError(t, SaveSealedToken(dir, "fleet-token"))
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.DisableRemoteSupport = true
	_ = a.RunOnce(context.Background())
	require.True(t, a.Revoked())
	require.Equal(t, "", LoadSealedToken(dir), "a revoked device holds no token to re-enrol with")
}

// TestNoSealedTokenStaysAuthInvalid: without a sealed token the device asks
// its person to enrol it again, as before.
func TestNoSealedTokenStaysAuthInvalid(t *testing.T) {
	var good atomic.Value
	good.Store("x")
	var reports atomic.Int32
	srv := authServer(t, &good, &reports)
	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "stale"})
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.DisableRemoteSupport = true
	for i := 0; i < authFailThreshold; i++ {
		_ = a.RunOnce(context.Background())
	}
	require.True(t, a.AuthInvalid())
}
