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

// TestARevokedDeviceStopsReportingUntilTheServerTakesItBack: a 403 on the
// config sync marks the device revoked, after which the cycle runs no checks
// and posts nothing; a later 200 clears it and the cycle reports again.
func TestARevokedDeviceStopsReportingUntilTheServerTakesItBack(t *testing.T) {
	var refuse atomic.Bool
	var reports atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/agent/config"):
			if refuse.Load() {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"agent revoked"}`))
				return
			}
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

	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "tok"})
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.registry.Register("always", &mockPassCheck{name: "always"})

	refuse.Store(true)
	require.NoError(t, a.RunOnce(context.Background()), "a revoked cycle is not an error to retry")
	require.True(t, a.Revoked(), "the 403 must mark the device revoked")
	require.Equal(t, int32(0), reports.Load(), "a revoked device must not post a report")

	require.NoError(t, a.RunOnce(context.Background()))
	require.Equal(t, int32(0), reports.Load(), "still revoked, still nothing posted")

	refuse.Store(false)
	require.NoError(t, a.RunOnce(context.Background()))
	require.False(t, a.Revoked(), "a successful sync clears the state")
	require.Equal(t, int32(1), reports.Load(), "once the server accepts the device, the cycle reports again")
}

// TestAnUnreachableServerIsNotARevocation: an ordinary failure to sync keeps
// the cycle going with the cached config, as it always did.
func TestAnUnreachableServerIsNotARevocation(t *testing.T) {
	var reports atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/agent/config"):
			w.WriteHeader(http.StatusBadGateway)
		case strings.HasSuffix(r.URL.Path, "/agent/report"):
			reports.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "tok"})
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.registry.Register("os_version", &mockPassCheck{name: "os_version"})

	require.NoError(t, a.RunOnce(context.Background()))
	require.False(t, a.Revoked())
	require.Equal(t, int32(1), reports.Load(), "a 502 on the config is not a revocation; the cached config still reports")
}
