package abac

import (
	"context"
	"strings"

	"github.com/openidx/openidx/internal/common/database"
)

// Mode is the tri-state ABAC_ENFORCE gate, the same shape as
// PAM_SESSION_RISK_GATE and POSTURE_DEVICE_TRUST_GATE:
//
//	off     (default) — policies are not consulted at all.
//	observe           — evaluate and record what WOULD be denied; permit.
//	enforce           — evaluate and deny.
//
// Off is the default because turning enforcement on for policies that have
// never enforced anything can lock people out of applications they use today.
// Observe exists so an operator can see, from the audit trail, exactly whom
// enforcing would have stopped BEFORE flipping it -- the same staged rollout
// the assignment gate uses.
type Mode string

const (
	ModeOff     Mode = "off"
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
)

// ParseMode reads a configured value. Anything unrecognised is off: a typo in
// a deployment variable must fail toward today's behaviour, never silently
// into enforcement.
func ParseMode(v string) Mode {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "observe":
		return ModeObserve
	case "enforce":
		return ModeEnforce
	default:
		return ModeOff
	}
}

// Decide turns a policy result into what the enforcement point should do.
//
// allow says whether the request proceeds. wouldDeny says whether the policies
// refused it, which is true on BOTH branches when they did -- enforcement must
// never be quieter than report mode, or an operator who flips the flag loses
// the very records that told them it was safe. That rule is the assignment
// gate's (internal/oauth/service.go, recordAssignmentDecision) and this
// follows it.
func Decide(res Result, mode Mode) (allow, wouldDeny bool) {
	if mode == ModeOff {
		return true, false
	}
	if res.Allowed {
		return true, false
	}
	return mode != ModeEnforce, true
}

// Gate evaluates and decides in one call: the shape an enforcement point wants.
// With mode off it does no query at all, so ABAC costs nothing until an
// operator turns it on.
func Gate(ctx context.Context, db *database.PostgresDB, orgID string, mode Mode, req EvaluationRequest) (allow, wouldDeny bool, res Result) {
	if mode == ModeOff {
		return true, false, Result{Allowed: true, Reason: "abac disabled"}
	}
	res = Evaluate(ctx, db, orgID, req)
	allow, wouldDeny = Decide(res, mode)
	return allow, wouldDeny, res
}
