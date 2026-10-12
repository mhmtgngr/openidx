package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/tunnel"
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

// fakeBlock records what the agent asks of the direct-access block.
type fakeBlock struct {
	mu      sync.Mutex
	scripts []string
	fail    error
}

func (f *fakeBlock) run(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.scripts = append(f.scripts, s)
	return nil
}

func (f *fakeBlock) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.scripts)
}

func (f *fakeBlock) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scripts) == 0 {
		return ""
	}
	return f.scripts[len(f.scripts)-1]
}

func reportedTunnel(t *testing.T, srv *tunnelServer) map[string]json.RawMessage {
	t.Helper()
	srv.mu.Lock()
	defer srv.mu.Unlock()
	var payload map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(srv.lastReport, &payload))
	var ts map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(payload["tunnel_status"], &ts))
	return ts
}

func TestAVersionedPolicyIsReportedAppliedWithItsGaps(t *testing.T) {
	srv := &tunnelServer{
		configBody: `{"checks":[],"org_network_policy":{"always_on":true,"split_tunnel":false,` +
			`"block_direct_corporate_cidrs":true,"corporate_cidrs":["10.0.0.0/8"],"version":"0123456789abcdef"}}`,
		reportBody: `{}`}
	a := newTunnelAgent(t, srv, nil)
	unsupported := errors.New("no firewall hook here")
	a.directBlock.Store(tunnel.NewDirectBlockFunc(func(string) error { t.Error("loaded a block where unsupported"); return nil },
		func() error { return unsupported }))
	require.NoError(t, a.RunOnce(context.Background()))

	ts := reportedTunnel(t, srv)
	assert.JSONEq(t, `"split"`, string(ts["mode"]), "the bundled tunneler always runs split")
	assert.JSONEq(t, `"0123456789abcdef"`, string(ts["policy_version"]), "gaps do not hold the version back")
	assert.JSONEq(t, `["full_tunnel","block_direct"]`, string(ts["policy_gaps"]))
	assert.True(t, a.tun.Load().Enabled())
}

func TestTheBlockIsLoadedAndRemovedAsThePolicySays(t *testing.T) {
	srv := &tunnelServer{
		configBody: `{"checks":[],"org_network_policy":{"block_direct_corporate_cidrs":true,` +
			`"corporate_cidrs":["10.0.0.0/8","192.168.1.0/24"],"version":"aaaaaaaaaaaaaaaa"}}`,
		reportBody: `{}`}
	a := newTunnelAgent(t, srv, nil)
	fb := &fakeBlock{}
	a.directBlock.Store(tunnel.NewDirectBlockFunc(fb.run, func() error { return nil }))
	require.NoError(t, a.RunOnce(context.Background()))
	assert.Contains(t, fb.last(), "elements = { 10.0.0.0/8, 192.168.1.0/24 }")
	ts := reportedTunnel(t, srv)
	assert.JSONEq(t, `"aaaaaaaaaaaaaaaa"`, string(ts["policy_version"]))
	assert.NotContains(t, ts, "policy_gaps")

	// The same version again loads nothing.
	n := fb.count()
	require.NoError(t, a.SyncConfig(context.Background()))
	assert.Equal(t, n, fb.count())

	// The policy turns the block off: the table is removed.
	srv.mu.Lock()
	srv.configBody = `{"checks":[],"org_network_policy":{"block_direct_corporate_cidrs":false,"version":"bbbbbbbbbbbbbbbb"}}`
	srv.mu.Unlock()
	require.NoError(t, a.SyncConfig(context.Background()))
	assert.NotContains(t, fb.last(), "chain output")
	assert.Contains(t, fb.last(), "delete table inet openidx_direct")
}

func TestAFailedBlockHoldsTheVersionBackAndSaysWhy(t *testing.T) {
	srv := &tunnelServer{
		configBody: `{"checks":[],"org_network_policy":{"block_direct_corporate_cidrs":true,` +
			`"corporate_cidrs":["10.0.0.0/8"],"version":"cccccccccccccccc"}}`,
		reportBody: `{}`}
	a := newTunnelAgent(t, srv, nil)
	fb := &fakeBlock{fail: errors.New("netlink: Operation not permitted")}
	a.directBlock.Store(tunnel.NewDirectBlockFunc(fb.run, func() error { return nil }))
	require.NoError(t, a.RunOnce(context.Background()))
	ts := reportedTunnel(t, srv)
	assert.NotContains(t, ts, "policy_version", "a policy that failed to apply is not reported applied")
	assert.Contains(t, string(ts["last_error"]), "Operation not permitted")

	// The next delivery of the same version tries again.
	fb.mu.Lock()
	fb.fail = nil
	fb.mu.Unlock()
	require.NoError(t, a.RunOnce(context.Background()))
	ts = reportedTunnel(t, srv)
	assert.JSONEq(t, `"cccccccccccccccc"`, string(ts["policy_version"]))
	assert.NotContains(t, ts, "last_error")
}

func TestAPolicyFromAnOlderServerAddsNothingToTheReport(t *testing.T) {
	srv := &tunnelServer{configBody: `{"checks":[],"org_network_policy":{"always_on":false}}`, reportBody: `{}`}
	a := newTunnelAgent(t, srv, nil)
	require.NoError(t, a.RunOnce(context.Background()))
	ts := reportedTunnel(t, srv)
	for _, k := range []string{"mode", "policy_version", "policy_gaps", "last_error"} {
		assert.NotContains(t, ts, k)
	}
}
