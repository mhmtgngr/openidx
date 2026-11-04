package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// authServer answers /agent/config and /agent/report, accepting only the
// bearer token in *good; anything else is answered 401, as requireEnrolledAgent
// does for a credential that no longer matches the row.
func authServer(t *testing.T, good *atomic.Value, reports *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+good.Load().(string) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid agent credentials"}`))
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/agent/config"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"checks":[{"type":"always","severity":"high"}],"report_interval":"1h"}`))
		case strings.HasSuffix(r.URL.Path, "/agent/report"):
			reports.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestARefusedCredentialBecomesAStateAfterSeveralSyncs: one 401 is not yet a
// state (it may pass); authFailThreshold in a row are, after which the cycle
// stops posting reports that would be refused. It is not a revoke.
func TestARefusedCredentialBecomesAStateAfterSeveralSyncs(t *testing.T) {
	var good atomic.Value
	good.Store("the-servers-token")
	var reports atomic.Int32
	srv := authServer(t, &good, &reports)

	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "stale"})
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.registry.Register("always", &mockPassCheck{name: "always"})

	for i := 1; i < authFailThreshold; i++ {
		_ = a.RunOnce(context.Background())
		require.False(t, a.AuthInvalid(), "refusal %d of %d is not yet a state", i, authFailThreshold)
	}
	_ = a.RunOnce(context.Background())
	require.True(t, a.AuthInvalid(), "%d refusals in a row mark the credential invalid", authFailThreshold)
	require.False(t, a.Revoked(), "a refused credential is not a revoke")

	require.NoError(t, a.RunOnce(context.Background()), "an invalid credential is a state, not an error to retry")
	require.Equal(t, int32(0), reports.Load(), "nothing the server would refuse is posted")
}

// TestAServiceTakesUpAReEnrolmentWithoutARestart: the device is enrolled
// again while the service runs (a code enrolment writes a new token to
// agent.json and does not restart a running service). The next refused sync
// reads the file, switches to the new credential, and the device reports.
func TestAServiceTakesUpAReEnrolmentWithoutARestart(t *testing.T) {
	var good atomic.Value
	good.Store("the-servers-token")
	var reports atomic.Int32
	srv := authServer(t, &good, &reports)

	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "stale"})
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.DisableRemoteSupport = true // as the Windows service runs it
	a.registry.Register("always", &mockPassCheck{name: "always"})

	for i := 0; i < authFailThreshold; i++ {
		_ = a.RunOnce(context.Background())
	}
	require.True(t, a.AuthInvalid())

	// The person enrolls the device again from My Devices.
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "the-servers-token"})

	require.NoError(t, a.RunOnce(context.Background()))
	require.False(t, a.AuthInvalid(), "the new credential is accepted and clears the state")
	require.Equal(t, int32(1), reports.Load(), "and the device reports again, without a restart")
}

// TestOnlyTheServiceSwapsItsCredential: a process that may hold a
// remote-support stream on its client (the tray, a foreground run) never
// swaps it underneath that stream; it stays refused until restarted.
func TestOnlyTheServiceSwapsItsCredential(t *testing.T) {
	var good atomic.Value
	good.Store("the-servers-token")
	var reports atomic.Int32
	srv := authServer(t, &good, &reports)

	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "stale"})
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.registry.Register("always", &mockPassCheck{name: "always"})

	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "the-servers-token"})
	_ = a.RunOnce(context.Background())
	require.Equal(t, int32(0), reports.Load(), "a non-service process keeps the credential it started with")
}

// TestARefusalCountResetsOnSuccess: refusals separated by a success never add
// up to the threshold.
func TestARefusalCountResetsOnSuccess(t *testing.T) {
	var good atomic.Value
	good.Store("tok")
	var reports atomic.Int32
	srv := authServer(t, &good, &reports)

	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "tok"})
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.registry.Register("always", &mockPassCheck{name: "always"})

	for i := 0; i < authFailThreshold*2; i++ {
		if i%2 == 0 {
			good.Store("something-else")
		} else {
			good.Store("tok")
		}
		_ = a.RunOnce(context.Background())
		require.False(t, a.AuthInvalid(), "cycle %d: refusals were never consecutive", i)
	}
}
