//go:build windows

package tunnel

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestLiveNamesOnThisMachine drives the real thing: the real NRPT script, the
// real loopback listener and the system resolver an application would use. It
// needs an elevated prompt and changes this machine's name resolution for a few
// seconds, so it runs only when OPENIDX_LIVE_NAMES=1, and it removes what it
// added whatever happens. Run it with a VPN that enforces its own DNS connected
// to see the case this exists for.
func TestLiveNamesOnThisMachine(t *testing.T) {
	if os.Getenv("OPENIDX_LIVE_NAMES") != "1" {
		t.Skip("set OPENIDX_LIVE_NAMES=1 on a test machine (elevated) to run this")
	}
	const name = "pin-live.openidx.example"
	n := NewNames(zap.NewNop(), "")
	t.Cleanup(func() {
		n.workMu.Lock()
		n.stop(false)
		n.workMu.Unlock()
		_ = n.rules.Clear(nil)
	})
	n.SetWanted(true, []NamePin{{Name: name, IP: "100.127.0.10"}})
	n.reconcile(context.Background(), true, nil)
	st := n.Status()
	t.Logf("status: %+v", st)
	if st.State != NamesActive || st.Pins != 1 {
		t.Fatalf("not active: %+v", st)
	}

	// An application's lookup: the system resolver, which consults the NRPT.
	addrs, err := n.resolve(context.Background(), name)
	if err != nil || len(addrs) != 1 || addrs[0] != "100.127.0.10" {
		t.Fatalf("system resolver: %v, %v", addrs, err)
	}
	// A name that is not pinned does not come from the agent.
	before := n.resp.Answered()
	_, _ = n.resolve(context.Background(), "not-pinned.openidx.example")
	if n.resp.Answered() != before {
		t.Error("the agent answered a name it does not pin")
	}
	out, _ := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'Added by openidx-agent' } | ForEach-Object { ($_.Namespace -join ',') + ' -> ' + ($_.NameServers -join ',') }").CombinedOutput()
	t.Logf("agent rules:\n%s", out)
	if !strings.Contains(string(out), name+" -> 127.64.0.2") {
		t.Errorf("the rule is not in the table: %s", out)
	}

	// Taking it away leaves nothing behind.
	n.SetWanted(false, nil)
	n.reconcile(context.Background(), true, nil)
	out, _ = exec.Command("powershell", "-NoProfile", "-Command",
		"@(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'Added by openidx-agent' }).Count").CombinedOutput()
	if strings.TrimSpace(string(out)) != "0" {
		t.Errorf("rules left behind: %s", out)
	}
}
