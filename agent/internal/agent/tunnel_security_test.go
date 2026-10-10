package agent

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var privilegedTunnelSettings = &TunnelConfig{
	Enabled:      true,
	BinaryPath:   "/tmp/planted/ziti-edge-tunnel",
	Mode:         "child",
	ProbeAddress: "127.0.0.1:1",
}

func TestTrustedAgentJSONTunnelSettingsAreObeyed(t *testing.T) {
	srv := &tunnelServer{configBody: `{"checks":[]}`, reportBody: `{}`}
	a := newTunnelAgent(t, srv, privilegedTunnelSettings)
	cfg, local := a.tunnelSettings()
	assert.True(t, local)
	assert.Equal(t, privilegedTunnelSettings.BinaryPath, cfg.BinaryPath)
	assert.Equal(t, privilegedTunnelSettings.ProbeAddress, cfg.ProbeAddress)
	assert.True(t, a.tun.Load().Enabled())
}

func TestUntrustedAgentJSONTunnelSettingsAreAllIgnored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not decide trust on Windows; the DACL check has its own tests")
	}
	cases := map[string]func(a *Agent){
		"agent.json writable by others": func(a *Agent) {
			require.NoError(t, os.Chmod(ConfigPath(a.configDir), 0o666))
		},
		"config directory writable by others": func(a *Agent) {
			require.NoError(t, os.Chmod(a.configDir, 0o777))
		},
	}
	for name, makeUntrusted := range cases {
		t.Run(name, func(t *testing.T) {
			srv := &tunnelServer{configBody: `{"checks":[]}`, reportBody: `{}`}
			a := newTunnelAgent(t, srv, privilegedTunnelSettings)
			makeUntrusted(a)
			cfg, local := a.tunnelSettings()
			assert.False(t, local, "enabled from an untrusted agent.json must not start a privileged tunneler")
			assert.Empty(t, cfg.BinaryPath, "binary_path from an untrusted agent.json chose what root runs")
			assert.Empty(t, string(cfg.Mode))
			assert.Empty(t, cfg.ProbeAddress)

			a.tun.Store(a.newTunnelSupervisor())
			a.applyTunnelEnablement()
			assert.False(t, a.tun.Load().Enabled())
		})
	}
}

// The server's answers can turn the tunnel on and off and nothing else: no
// field of /agent/config or of the report response reaches the binary, the
// mode, the probe or the arguments.
func TestServerValuesNeverSelectABinaryOrArguments(t *testing.T) {
	hostile := `{"checks":[],
		"tunnel":{"enabled":true,"binary_path":"/tmp/evil","mode":"child","probe_address":"10.0.0.1:1"},
		"org_network_policy":{"always_on":true,"binary_path":"/tmp/evil","args":["--evil"],"mode":"child"}}`
	srv := &tunnelServer{configBody: hostile, reportBody: hostile}
	a := newTunnelAgent(t, srv, nil)
	require.NoError(t, a.RunOnce(context.Background()))

	assert.True(t, a.tun.Load().Enabled(), "always_on still turns the tunnel on")
	assert.Nil(t, a.config.Tunnel, "the server's answer must not become local tunnel settings")
	cfg, local := a.tunnelSettings()
	assert.False(t, local)
	assert.Empty(t, cfg.BinaryPath)
	assert.Empty(t, string(cfg.Mode))
	assert.Empty(t, cfg.ProbeAddress)
}
