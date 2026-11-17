package doctor

import (
	"context"
	"errors"
)

// Errors an Actions implementation uses to say why it did nothing.
var (
	ErrNeedsElevation = errors.New("needs elevation")
	ErrUnsupported    = errors.New("not supported on this platform")
)

// WindowsServiceName is the agent's Windows service. It repeats
// winservice.ServiceName because that package imports the agent, which
// imports this one; a test in cmd/openidx-agent holds the two together.
const WindowsServiceName = "OpenIDXAgent"

// Actions are the local repairs. Both are safe to repeat and change nothing
// about what the device may reach.
type Actions interface {
	FlushDNS(ctx context.Context) error
	RestartService(ctx context.Context) error
}

// NewActions returns this platform's repairs.
func NewActions() Actions { return osActions{} }

// PlanRepairs names the repairs the bundle's failures call for, DNS first.
func PlanRepairs(b Bundle) []Repair {
	var dns, svc bool
	for _, c := range b.Failing() {
		switch c.Code {
		case CodeDNSFail, CodeDNSTimeout:
			dns = true
		case CodeServiceNotRunning, CodeTunnelDown:
			svc = true
		}
	}
	out := []Repair{}
	if dns {
		out = append(out, Repair{ID: RepairFlushDNS, Outcome: OutcomePlanned})
	}
	if svc {
		out = append(out, Repair{ID: RepairRestartService, Outcome: OutcomePlanned})
	}
	return out
}

// ApplyRepairs runs the planned repairs and returns what became of each. One
// failing does not stop the next.
func ApplyRepairs(ctx context.Context, b Bundle, a Actions) []Repair {
	plan := PlanRepairs(b)
	for i := range plan {
		var err error
		switch plan[i].ID {
		case RepairFlushDNS:
			err = a.FlushDNS(ctx)
		case RepairRestartService:
			err = a.RestartService(ctx)
		}
		switch {
		case err == nil:
			plan[i].Outcome = OutcomeApplied
		case errors.Is(err, ErrNeedsElevation):
			plan[i].Outcome = OutcomeNeedsElevation
		default:
			plan[i].Outcome, plan[i].Detail = OutcomeFailed, clip(err.Error())
		}
	}
	return plan
}
