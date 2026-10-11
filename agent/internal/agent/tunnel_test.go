package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// tunnelServer answers /agent/config with configBody and /agent/report with
// reportBody, and keeps the last report it was sent.
type tunnelServer struct {
	mu                     sync.Mutex
	configBody, reportBody string
	lastReport             []byte
}

func (s *tunnelServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v1/access/agent/config":
		_, _ = io.WriteString(w, s.configBody)
	case "/api/v1/access/agent/report":
		s.lastReport, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, s.reportBody)
	default:
		http.NotFound(w, r)
	}
}

func newTunnelAgent(t *testing.T, srv *tunnelServer, tc *TunnelConfig) *Agent {
	t.Helper()
	hs := httptest.NewServer(http.HandlerFunc(srv.handler))
	t.Cleanup(hs.Close)
	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{
		ServerURL: hs.URL, AgentID: "agent-tun", DeviceID: "device-tun", AuthToken: "tok", Tunnel: tc,
	})
	a, err := NewAgent(zap.NewNop(), dir)
	require.NoError(t, err)
	// The supervisor exists but is not Run: these tests are about what the
	// agent tells it and what it reports, not about a tunneler process.
	a.tun.Store(a.newTunnelSupervisor())
	a.applyTunnelEnablement()
	return a
}

func TestReportCarriesTunnelStatus(t *testing.T) {
	srv := &tunnelServer{configBody: `{"checks":[],"report_interval":"1h"}`, reportBody: `{"status":"ok"}`}
	a := newTunnelAgent(t, srv, nil)
	require.NoError(t, a.RunOnce(context.Background()))

	var payload map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(srv.lastReport, &payload))
	require.Contains(t, payload, "tunnel_status")
	assert.JSONEq(t, `{"state":"off","version":"","last_seen":null,"services":[]}`, string(payload["tunnel_status"]))
}

func TestReportOmitsTunnelStatusWithoutASupervisor(t *testing.T) {
	srv := &tunnelServer{configBody: `{"checks":[]}`, reportBody: `{}`}
	a := newTunnelAgent(t, srv, nil)
	a.tun.Store(nil)
	require.NoError(t, a.RunOnce(context.Background()))
	var payload map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(srv.lastReport, &payload))
	assert.NotContains(t, payload, "tunnel_status")
}

func TestTunnelIsOffByDefaultAndOnWhenAgentJSONEnablesIt(t *testing.T) {
	srv := &tunnelServer{configBody: `{"checks":[]}`, reportBody: `{}`}
	assert.False(t, newTunnelAgent(t, srv, nil).tun.Load().Enabled())
	assert.True(t, newTunnelAgent(t, srv, &TunnelConfig{Enabled: true}).tun.Load().Enabled())
}

func TestOrgAlwaysOnFromTheReportResponseTurnsTheTunnelOn(t *testing.T) {
	srv := &tunnelServer{configBody: `{"checks":[]}`,
		reportBody: `{"status":"ok","org_network_policy":{"always_on":true}}`}
	a := newTunnelAgent(t, srv, nil)
	require.False(t, a.tun.Load().Enabled())
	require.NoError(t, a.RunOnce(context.Background()))
	assert.True(t, a.tun.Load().Enabled(), "always_on in the report response must turn the tunnel on")
}

func TestOrgAlwaysOnFromConfigAndItsWithdrawal(t *testing.T) {
	srv := &tunnelServer{configBody: `{"checks":[],"org_network_policy":{"always_on":true}}`, reportBody: `{}`}
	a := newTunnelAgent(t, srv, nil)
	require.NoError(t, a.SyncConfig(context.Background()))
	assert.True(t, a.tun.Load().Enabled())

	// A policy that does not mention always_on keeps the last answer: a
	// server that leaves the field out has not turned the tunnel off.
	srv.mu.Lock()
	srv.configBody = `{"checks":[],"org_network_policy":{}}`
	srv.mu.Unlock()
	require.NoError(t, a.SyncConfig(context.Background()))
	assert.True(t, a.tun.Load().Enabled())

	srv.mu.Lock()
	srv.configBody = `{"checks":[],"org_network_policy":{"always_on":false}}`
	srv.mu.Unlock()
	require.NoError(t, a.SyncConfig(context.Background()))
	assert.False(t, a.tun.Load().Enabled(), "always_on false with the device's own setting off is off")

	b := newTunnelAgent(t, srv, &TunnelConfig{Enabled: true})
	require.NoError(t, b.SyncConfig(context.Background()))
	assert.True(t, b.tun.Load().Enabled(), "the organization's policy does not turn off a device the owner enabled")
}

func TestTheTrayAgentSupervisesNoTunnel(t *testing.T) {
	srv := &tunnelServer{configBody: `{"checks":[]}`, reportBody: `{}`}
	a := newTunnelAgent(t, srv, &TunnelConfig{Enabled: true})
	a.tun.Store(nil)
	a.RemoteSupportOnly = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = a.Run(ctx)
	assert.Nil(t, a.TunnelStatus(), "a RemoteSupportOnly agent must not start a tunneler")
}
