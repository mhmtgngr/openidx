package collect

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"runtime"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/doctor"
	"github.com/openidx/openidx/agent/internal/ipc"
	"github.com/openidx/openidx/agent/internal/tunnel"
)

type okProbes struct{}

func (okProbes) Resolve(context.Context, string) ([]string, error) {
	return []string{"198.51.100.7"}, nil
}
func (okProbes) DialTCP(context.Context, string) error { return nil }
func (okProbes) DNSQuery(context.Context, string, string) (doctor.DNSAnswer, error) {
	return doctor.DNSAnswer{}, context.DeadlineExceeded
}
func (okProbes) TLSHandshake(context.Context, string, string) error { return nil }
func (okProbes) HTTPGet(context.Context, string) (doctor.HTTPResult, error) {
	return doctor.HTTPResult{Status: 401, Date: time.Now()}, nil
}
func (okProbes) Proxy(string) *url.URL { return nil }
func (okProbes) Now() time.Time        { return time.Now() }

type stubActions struct{ onRestart func() }

func (stubActions) FlushDNS(context.Context) error { return nil }
func (s stubActions) RestartService(context.Context) error {
	if s.onRestart != nil {
		s.onRestart()
	}
	return nil
}

func enrolledConfig(string) (*agent.AgentConfig, error) {
	return &agent.AgentConfig{
		ServerURL: "https://idx.example.test", AgentID: "agent-1",
		Tunnel: &agent.TunnelConfig{Enabled: true},
	}, nil
}

func unreadable(string) (*agent.AgentConfig, error) {
	return nil, fmt.Errorf("reading agent config: %w", fs.ErrPermission)
}

func pipe(state *tunnel.State) func() (*ipc.Status, error) {
	return func() (*ipc.Status, error) {
		return &ipc.Status{
			Enrolled: true, AgentID: "agent-1", ServerURL: "https://idx.example.test",
			Tunnel: &tunnel.Status{State: *state},
		}, nil
	}
}

func noPipe() (*ipc.Status, error) { return nil, errors.New("no pipe") }

func testDeps(state *tunnel.State) Deps {
	return Deps{LoadConfig: enrolledConfig, QueryIPC: pipe(state), Probes: okProbes{}, Actions: stubActions{}}
}

func TestInputsFromConfigAndPipe(t *testing.T) {
	state := tunnel.StateConnected
	in := Inputs(testDeps(&state), "", "0.6.0")
	if !in.Enrolled || in.AgentID != "agent-1" || !in.TunnelExpected || in.ConfigErr != nil || in.AgentVersion != "0.6.0" {
		t.Errorf("inputs = %+v", in)
	}
	if in.ServiceRunning == nil || !*in.ServiceRunning || in.Tunnel == nil {
		t.Errorf("status pipe not used: %+v", in)
	}
}

// An ordinary user cannot read agent.json: the service's pipe fills in.
func TestInputsFallBackToPipeWhenConfigUnreadable(t *testing.T) {
	state := tunnel.StateConnected
	d := testDeps(&state)
	d.LoadConfig = unreadable
	in := Inputs(d, "", "")
	if !in.Enrolled || in.ServerURL == "" || in.ConfigErr != nil || !in.TunnelExpected {
		t.Errorf("inputs = %+v", in)
	}
}

func TestConfigUnreadableWithoutPipe(t *testing.T) {
	d := Deps{LoadConfig: unreadable, QueryIPC: noPipe, Probes: okProbes{}, Actions: stubActions{}}
	b := Run(context.Background(), d, "", "", false)
	if f := b.Failing(); len(f) == 0 || f[0].Code != doctor.CodeConfigUnreadable {
		t.Errorf("failing = %+v", f)
	}
}

func TestServiceStateWithoutPipe(t *testing.T) {
	in := Inputs(Deps{LoadConfig: enrolledConfig, QueryIPC: noPipe}, "", "")
	if runtime.GOOS == "windows" {
		if in.ServiceRunning == nil || *in.ServiceRunning {
			t.Error("a silent pipe on Windows means the service is down")
		}
	} else if in.ServiceRunning != nil {
		t.Error("without a pipe the service state is unknown, not down")
	}
}

func TestRunPlansWithoutFixAndRechecksWithIt(t *testing.T) {
	state := tunnel.StateDegraded
	d := testDeps(&state)
	restarts := 0
	d.Actions = stubActions{onRestart: func() { restarts++; state = tunnel.StateConnected }}

	b := Run(context.Background(), d, "", "", false)
	if b.Healthy() || restarts != 0 || len(b.Repairs) != 1 || b.Repairs[0].Outcome != doctor.OutcomePlanned {
		t.Fatalf("without fix: healthy=%v restarts=%d repairs=%+v", b.Healthy(), restarts, b.Repairs)
	}
	b = Run(context.Background(), d, "", "", true)
	if !b.Healthy() || restarts != 1 || len(b.Repairs) != 1 || b.Repairs[0].Outcome != doctor.OutcomeApplied {
		t.Fatalf("with fix: healthy=%v restarts=%d repairs=%+v", b.Healthy(), restarts, b.Repairs)
	}
}

// On a phone the engine is inside the app: no service to be down, no tunneler
// to be off, nothing to repair.
func TestOnAPhoneTheServiceAndTunnelHaveNothingToSayAndNothingIsRepaired(t *testing.T) {
	old := OnPhone
	OnPhone = func() bool { return true }
	t.Cleanup(func() { OnPhone = old })

	// The shape that, anywhere else, is a failing service and a switched-off
	// tunnel: enrolled, no status pipe, tunnel not configured.
	repairs := 0
	d := Deps{LoadConfig: func(string) (*agent.AgentConfig, error) {
		return &agent.AgentConfig{AgentID: "phone-1", ServerURL: "https://idx.example.test"}, nil
	}, QueryIPC: noPipe, Probes: okProbes{}, Actions: stubActions{onRestart: func() { repairs++ }}}

	if in := Inputs(d, "", ""); !in.Mobile {
		t.Fatalf("a phone's inputs say it is not one: %+v", in)
	}
	for _, fix := range []bool{false, true} {
		b := Run(context.Background(), d, "", "", fix)
		if !b.Healthy() {
			t.Errorf("fix=%v: a healthy phone was judged unhealthy: %+v", fix, b.Failing())
		}
		if len(b.Repairs) != 0 || repairs != 0 {
			t.Errorf("fix=%v: a phone was offered or given a repair: %+v (restarts %d)", fix, b.Repairs, repairs)
		}
		for _, c := range b.Checks {
			if (c.ID == doctor.CheckService || c.ID == doctor.CheckTunnel) && c.Status != doctor.StatusSkipped {
				t.Errorf("fix=%v: %s was %s on a phone", fix, c.ID, c.Status)
			}
		}
	}
}
