package agent

import (
	"context"
	"time"

	"github.com/openidx/openidx/agent/internal/doctor"
)

// diagnoseBudget bounds the doctor run behind a "diagnose" fleet command.
const diagnoseBudget = 40 * time.Second

// doctorProbes is the seam the tests replace.
var doctorProbes = doctor.NewProbes

// diagnose answers a "diagnose" fleet command: it runs the device doctor from
// inside the agent, which knows what a separate process cannot (the tunnel's
// live state on every platform), and returns the bundle as the command's
// result. It repairs nothing; the server asked a question.
func (a *Agent) diagnose() commandOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), diagnoseBudget)
	defer cancel()
	b := doctor.Run(ctx, a.doctorInputs(), doctorProbes(), doctor.Options{})
	return commandOutcome{status: "done", result: map[string]any{"bundle": b}}
}

// doctorInputs is what the running agent knows about itself.
func (a *Agent) doctorInputs() doctor.Inputs {
	running := true
	in := doctor.Inputs{
		AgentVersion:   a.Version,
		ServiceRunning: &running,
		Tunnel:         a.TunnelStatus(),
	}
	in.NamesByAgent = a.NamesByAgent()
	if cfg := a.config; cfg != nil {
		in.AgentID = cfg.AgentID
		in.ServerURL = cfg.ServerURL
		in.ProxyURL = cfg.ProxyURL
		in.Enrolled = cfg.AgentID != ""
		in.IdentityFile = cfg.ZitiIdentityFile
		in.TunnelExpected = cfg.Tunnel != nil && cfg.Tunnel.Enabled
	}
	return in
}
