package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/tunnel"
)

// withNames gives the test agent the manager startTunnel would have started,
// without a tunneler or a resolver behind it.
func withNames(a *Agent) *tunnel.Names {
	n := tunnel.NewNames(zap.NewNop(), "")
	a.names.Store(n)
	return n
}

const pinsPolicy = `{"checks":[],"org_network_policy":{"always_on":true,"version":"v1","name_resolution":"agent","name_pins_version":"d1",
 "name_pins":[{"name":"wiki.corp.example","ip":"100.127.0.10","service":"openidx-net-wiki"},{"name":"hr.corp.example","ip":"100.127.0.11","service":"openidx-net-hr"}]}}`

func TestNameResolutionPolicyReachesTheManager(t *testing.T) {
	srv := &tunnelServer{configBody: pinsPolicy, reportBody: `{}`}
	a := newTunnelAgent(t, srv, nil)
	n := withNames(a)
	require.NoError(t, a.SyncConfig(context.Background()))
	st := n.Status()
	assert.True(t, st.Wanted)
	assert.Equal(t, 2, st.Requested)

	// The pins are per device: they change under the SAME policy version, and
	// the manager must hear it.
	srv.mu.Lock()
	srv.configBody = `{"checks":[],"org_network_policy":{"always_on":true,"version":"v1","name_resolution":"agent","name_pins_version":"d2",
	 "name_pins":[{"name":"wiki.corp.example","ip":"100.127.0.10","service":"openidx-net-wiki"}]}}`
	srv.mu.Unlock()
	require.NoError(t, a.SyncConfig(context.Background()))
	assert.Equal(t, 1, n.Status().Requested, "a change of pins under an unchanged policy version was not applied")

	// The setting going back to tunnel (the fields are absent) turns it off.
	srv.mu.Lock()
	srv.configBody = `{"checks":[],"org_network_policy":{"always_on":true,"version":"v2"}}`
	srv.mu.Unlock()
	require.NoError(t, a.SyncConfig(context.Background()))
	st = n.Status()
	assert.False(t, st.Wanted)
	assert.Equal(t, 0, st.Requested)
}

func TestAPolicyThatArrivedBeforeTheManagerIsAppliedWhenItStarts(t *testing.T) {
	srv := &tunnelServer{configBody: pinsPolicy, reportBody: `{}`}
	a := newTunnelAgent(t, srv, nil)
	require.NoError(t, a.SyncConfig(context.Background())) // no manager yet: nothing to tell
	require.Nil(t, a.names.Load())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.startNames(ctx, a.tun.Load())
	n := a.names.Load()
	require.NotNil(t, n)
	assert.True(t, n.Status().Wanted, "the policy delivered earlier was lost")
	assert.Equal(t, 2, n.Status().Requested)
}

func TestTheServerTheAgentTalksToIsNeverAnswered(t *testing.T) {
	assert.Equal(t, []string{"openidx.corp.example"}, protectedHosts("https://openidx.corp.example"))
	assert.Equal(t, []string{"openidx.corp.example"}, protectedHosts(" https://openidx.corp.example:8443/base "))
	assert.Equal(t, []string{"10.0.0.5"}, protectedHosts("http://10.0.0.5:8080"))
	assert.Nil(t, protectedHosts(""))
	assert.Nil(t, protectedHosts("not a url"))
}

func TestUndeliveredNameResolutionIsAbsentFromTheStatus(t *testing.T) {
	srv := &tunnelServer{configBody: `{"checks":[],"org_network_policy":{"always_on":true,"version":"v1"}}`, reportBody: `{}`}
	a := newTunnelAgent(t, srv, nil)
	withNames(a)
	require.NoError(t, a.SyncConfig(context.Background()))
	st := a.TunnelStatus()
	require.NotNil(t, st)
	raw, err := json.Marshal(st)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "name_resolution", "a policy gap that was never asked for")
}
