package access

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCorporatePrefixesAreCanonical(t *testing.T) {
	got := corporatePrefixes(
		[]string{"10.0.0.9/16", "10.0.0.0/8", "192.168.1.0/24", "fd00::1/64", "garbage", "10.0.0.0/24"},
		[]string{"192.168.1.20", "172.16.0.5", "fs1.corp.example", "::ffff:172.16.0.6", "2001:db8::7"},
	)
	// 10.0.0.0/16 and 10.0.0.0/24 are inside 10.0.0.0/8; 192.168.1.20 is
	// inside 192.168.1.0/24; a name is not an address; a v4-mapped host is v4.
	want := []string{"10.0.0.0/8", "172.16.0.5/32", "172.16.0.6/32", "192.168.1.0/24", "2001:db8::7/128", "fd00::/64"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("corporatePrefixes = %v, want %v", got, want)
	}
	if got := corporatePrefixes(nil, nil); len(got) != 0 {
		t.Errorf("no ranges gave %v", got)
	}
}

func TestPolicyVersionMovesWithWhatADeviceActsOn(t *testing.T) {
	base := agentNetworkPolicy{SplitTunnel: true, CorporateCIDRs: []string{}}
	v := policyVersion(base)
	if !isPolicyVersion(v) {
		t.Fatalf("version %q is not 16 hex characters", v)
	}
	if policyVersion(base) != v {
		t.Error("the same policy gave two versions")
	}
	for name, p := range map[string]agentNetworkPolicy{
		"always on": {AlwaysOn: true, SplitTunnel: true},
		"full":      {SplitTunnel: false},
		"block":     {SplitTunnel: true, BlockDirectCorporateCIDRs: true},
		"ranges":    {SplitTunnel: true, BlockDirectCorporateCIDRs: true, CorporateCIDRs: []string{"10.0.0.0/8"}},
	} {
		if policyVersion(p) == v {
			t.Errorf("%s: the version did not move", name)
		}
	}
}

// TestTheGoAgentsTunnelStatusIsRead pins the report the Go agent actually
// sends (agent/internal/tunnel/status.go): services as names, its own state
// words, and the policy fields. A list of names used to fail the whole report.
func TestTheGoAgentsTunnelStatusIsRead(t *testing.T) {
	body := `{"agent_id":"a1","results":[],"tunnel_status":{"state":"connected","version":"v1.18.7",
		"last_seen":"2026-10-10T12:00:00Z","services":["erp-web","rdp-finance"],"mode":"split",
		"policy_version":"0123456789ABCDEF","policy_gaps":["block_direct","bogus","block_direct"],
		"last_error":"` + strings.Repeat("x", 600) + `"}}`
	var r agentReport
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("the Go agent's report does not decode: %v", err)
	}
	ts := r.TunnelStatus
	ts.normalize()
	if ts.State != "up" || len(ts.Services) != 2 || ts.Services[0].Name != "erp-web" {
		t.Errorf("state/services read as %q %+v", ts.State, ts.Services)
	}
	if ts.Mode != "split" || ts.PolicyVersion != "0123456789abcdef" {
		t.Errorf("mode/version read as %q %q", ts.Mode, ts.PolicyVersion)
	}
	if !reflect.DeepEqual(ts.PolicyGaps, []string{"block_direct"}) {
		t.Errorf("gaps read as %v", ts.PolicyGaps)
	}
	if len(ts.LastError) != maxTunnelErrorLen {
		t.Errorf("last_error kept %d bytes", len(ts.LastError))
	}

	// Objects still decode, and the agent's other states map.
	var obj agentTunnelStatus
	if err := json.Unmarshal([]byte(`{"state":"degraded","services":[{"name":"s","dial_failures":3}]}`), &obj); err != nil {
		t.Fatal(err)
	}
	if n := obj.normalize(); n != 3 || obj.State != "down" {
		t.Errorf("degraded with 3 failures read as %q, %d", obj.State, n)
	}
	for in, want := range map[string]string{"off": "off", "not_installed": "not_installed", "weird": "unknown"} {
		s := agentTunnelStatus{State: in, Mode: "tunnel-all", PolicyVersion: "not-a-version"}
		s.normalize()
		if s.State != want || s.Mode != "" || s.PolicyVersion != "" {
			t.Errorf("%s read as %q mode %q version %q", in, s.State, s.Mode, s.PolicyVersion)
		}
	}
}

func TestTunnelPolicyState(t *testing.T) {
	v, other := "0123456789abcdef", "fedcba9876543210"
	for _, c := range []struct {
		reported  *string
		hasStatus bool
		current   string
		want      string
	}{
		{&v, true, v, "applied"},
		{&other, true, v, "pending"},
		{nil, true, v, "pending"},
		{&v, false, v, ""},
		{&v, true, "", ""},
	} {
		if got := tunnelPolicyState(c.reported, c.hasStatus, c.current); got != c.want {
			t.Errorf("tunnelPolicyState(%v, %v, %q) = %q, want %q", c.reported, c.hasStatus, c.current, got, c.want)
		}
	}
}
