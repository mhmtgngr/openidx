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

// newCountingServer answers /agent/config with cfg and counts the posture
// reports it receives.
func newCountingServer(t *testing.T, cfg string) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var configs, reports atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/agent/config"):
			configs.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(cfg))
		case strings.HasSuffix(r.URL.Path, "/agent/report"):
			reports.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &configs, &reports
}

// TestARemoteSupportOnlyAgentPollsButNeverReports: the tray's loop must fetch
// the config (that is how a pending session reaches it) and post no posture
// report, which is the service's job.
func TestARemoteSupportOnlyAgentPollsButNeverReports(t *testing.T) {
	srv, configs, reports := newCountingServer(t,
		`{"checks":[{"type":"always","severity":"high"}],"report_interval":"1h"}`)
	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "tok"})

	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.registry.Register("always", &mockPassCheck{name: "always"})
	a.RemoteSupportOnly = true

	require.NoError(t, a.RunOnce(context.Background()))

	require.Equal(t, int32(1), configs.Load(), "the config must be polled, or a pending session is never seen")
	require.Equal(t, int32(0), reports.Load(), "a remote-support-only agent must not post a posture report")
}

// TestTheFullCycleStillReports is the other side: the same server and config,
// without RemoteSupportOnly, produce one report.
func TestTheFullCycleStillReports(t *testing.T) {
	srv, configs, reports := newCountingServer(t,
		`{"checks":[{"type":"always","severity":"high"}],"report_interval":"1h"}`)
	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: srv.URL, AgentID: "a1", DeviceID: "d1", AuthToken: "tok"})

	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	a.registry.Register("always", &mockPassCheck{name: "always"})

	require.NoError(t, a.RunOnce(context.Background()))

	require.Equal(t, int32(1), configs.Load())
	require.Equal(t, int32(1), reports.Load(), "the service's cycle reports posture")
}
