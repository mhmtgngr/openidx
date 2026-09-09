// Package stepup owns one question: "did the person making this request prove
// a second factor recently enough?" — and, unlike the step-up machinery it is
// built on, something in the product now asks it.
//
// /oauth/stepup-challenge, /oauth/stepup-verify and /oauth/stepup-status have
// shipped for a long time. They create a challenge, verify an MFA factor
// against it and mint a short-lived RS256 JWT carrying step_up: true. No
// handler, no middleware and no gate in the product has ever read that token,
// so answering a step-up challenge changed nothing about what the caller could
// then do. It is the same defect class as the ABAC editor that enforced
// nothing and the ISPM rules that scored nothing: a control that displays
// without enforcing.
//
// The freshness fact lives on the session, not in a bearer
// ------------------------------------------------------------------
// The obvious wiring — have the client carry the step_up JWT to the protected
// endpoint — was not taken. The gate lives in two services that would each
// need to validate a second token issued by a third, every client would need
// to learn to hold and present it, and the resulting proof would be something
// the caller hands us. Instead /oauth/stepup-verify stamps
// sessions.mfa_verified_at (v186) and the gate reads that column: server-side
// state, one row, no new client contract, and the same answer whichever
// service asks. The step_up JWT keeps its existing meaning for any caller that
// wants a portable receipt; nothing here depends on it.
//
// Refreshing an access token deliberately does NOT refresh this. The refresh
// grant carries session_id forward (that is what makes a revoked session's
// markers bite), so a token refreshed at hour ten still points at a session
// whose factor is ten hours old. That is the property the gate needs: a long
// -lived native client cannot refresh its way out of proving who is holding
// the laptop.
//
// orgID and sessionID are explicit parameters rather than read from orgctx or
// a gin context, for the reason internal/abac and internal/appaccess take
// them: this package is consumed by services with different context plumbing,
// and an explicit scope is testable.
package stepup

import (
	"context"
	"strings"
	"time"

	"github.com/openidx/openidx/internal/common/database"
)

// Mode is the tri-state STEPUP_GATE, the same shape as ABAC_ENFORCE,
// PAM_SESSION_RISK_GATE and POSTURE_DEVICE_TRUST_GATE:
//
//	off     (default) — freshness is not consulted; no query is made.
//	observe           — evaluate and record who WOULD be asked; permit.
//	enforce           — evaluate and refuse, asking for a step-up.
//
// Off is the default for the reason the others are: turning on a control that
// has never enforced anything can lock out the person holding the only admin
// account. Observe exists so an operator can read, from the audit trail,
// exactly who would have been interrupted before anyone is.
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

// DefaultMaxAge is the window applied when the gate is on and the operator has
// configured no other. It is not zero, and that is deliberate: `security.
// reauth_interval` has shipped documented as "0 = disabled", so an operator
// who turns STEPUP_GATE on while that setting sits at its default would get a
// gate that gates nothing — a control that displays without enforcing, which
// is the thing this whole change exists to stop. Turning the gate on is the
// statement that freshness is wanted; the window only tunes how fresh.
const DefaultMaxAge = 15 * time.Minute

// Reason values carried on a decision and into its audit record.
const (
	// ReasonFresh — the session proved a factor inside the window.
	ReasonFresh = "fresh"
	// ReasonStale — it proved one, but too long ago.
	ReasonStale = "stale"
	// ReasonNeverVerified — the session has no recorded second factor at all.
	// Distinct from stale because it is a different operator conversation: an
	// org whose login policy does not require MFA will see these and nothing
	// else, and the answer there is the login policy, not the window.
	ReasonNeverVerified = "never_verified"
	// ReasonNoSession — a human caller whose token carries no sid, so
	// freshness cannot be established either way.
	ReasonNoSession = "no_session"
	// ReasonLookupFailed — the session row could not be read.
	ReasonLookupFailed = "lookup_failed"
	// ReasonMachineCaller — an API key, service account or client-credentials
	// token. Never gated; see Decision.
	ReasonMachineCaller = "machine_caller"
)

// Decision is the full answer, kept as data so the enforcement points log and
// audit the same fields and a caller can be told what to do about it.
type Decision struct {
	// Required reports that the caller must prove a factor before this action.
	// It is true on BOTH the observe and enforce branches when the session is
	// stale — enforcement is never quieter than report mode, the rule the
	// assignment gate set and every gate since has followed.
	Required bool
	// Allowed is what the enforcement point should actually do.
	Allowed bool
	Reason  string
	// LastVerified is the session's recorded factor time; zero when none.
	LastVerified time.Time
	// Age is how long ago that was; zero when LastVerified is zero.
	Age time.Duration
	// MaxAge is the window the decision was made against.
	MaxAge time.Duration
}

// Caller is what an enforcement point knows about who is asking. It is a
// struct rather than four arguments because the machine-caller carve-out below
// is the part most likely to be got wrong by a future call site, and naming
// the fields makes an omission visible.
type Caller struct {
	UserID    string
	OrgID     string
	SessionID string
	// AuthMethod is the auth middleware's "auth_method" — "api_key" for a
	// minted key or service-account PAT.
	AuthMethod string
	// ServiceAccountID is set by the same middleware for a service account.
	ServiceAccountID string
}

// IsMachine reports whether this caller is an unattended identity: an API key,
// a service account, or a client-credentials token (which carries no subject
// at all, since GenerateJWT is called with an empty user id for that grant).
//
// Machine identities are never gated. Step-up is a control over a person: it
// asks someone to touch a key or read a code off a phone, and there is nobody
// to ask. An unattended integration that hit this gate would not prompt — it
// would simply start failing, at 03:00, with a 403 nobody can clear. Machine
// access is bounded by the scopes it was provisioned with and by the
// assignment gate, which are controls that can actually apply to it.
//
// A human caller with no session is NOT a machine caller and is not covered by
// this carve-out; see Gate.
func (c Caller) IsMachine() bool {
	return c.UserID == "" ||
		strings.EqualFold(c.AuthMethod, "api_key") ||
		c.ServiceAccountID != ""
}

// Freshness reads when this session last proved a second factor. ok is false
// when the session has no recorded factor; err is non-nil only when the row
// could not be read at all, which the caller must not confuse with "stale".
func Freshness(ctx context.Context, db *database.PostgresDB, orgID, sessionID string) (t time.Time, ok bool, err error) {
	if db == nil || db.Pool == nil || sessionID == "" || orgID == "" {
		return time.Time{}, false, nil
	}
	var verified *time.Time
	if err := db.Pool.QueryRow(ctx,
		`SELECT mfa_verified_at FROM sessions WHERE id = $1 AND org_id = $2`,
		sessionID, orgID).Scan(&verified); err != nil {
		return time.Time{}, false, err
	}
	if verified == nil {
		return time.Time{}, false, nil
	}
	return *verified, true, nil
}

// Gate is the whole decision: the shape an enforcement point wants.
//
// With mode off it makes no query at all, so the gate costs nothing until an
// operator turns it on.
//
// Fail-closed under enforcement. A session row that cannot be read is refused
// when the mode is enforce, and permitted-with-a-record when it is observe.
// The assignment gate was changed for exactly this reason in P5: the one flag
// an operator flips to lock something down must not come open when the
// database is unreachable, which is precisely when an attacker would like it
// to. Observe mode is a report, so a failed read there is a gap in the report,
// not a decision.
func Gate(ctx context.Context, db *database.PostgresDB, mode Mode, maxAge time.Duration, caller Caller) Decision {
	if mode == ModeOff {
		return Decision{Allowed: true, Reason: ReasonFresh, MaxAge: maxAge}
	}
	if caller.IsMachine() {
		return Decision{Allowed: true, Reason: ReasonMachineCaller, MaxAge: maxAge}
	}
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}

	// A person whose token carries no sid. Freshness cannot be established
	// either way, so this follows the same fail-closed rule as a failed read:
	// under enforce it is refused, under observe it is recorded. It is a
	// distinct reason because the fix is different — a token minted without a
	// session is a bug in whatever minted it, not a user who needs to tap a
	// phone, and an operator watching in observe mode needs to see that
	// before they enforce.
	if caller.SessionID == "" {
		return Decision{
			Required: true,
			Allowed:  mode != ModeEnforce,
			Reason:   ReasonNoSession,
			MaxAge:   maxAge,
		}
	}

	verified, ok, err := Freshness(ctx, db, caller.OrgID, caller.SessionID)
	if err != nil {
		return Decision{
			Required: true,
			Allowed:  mode != ModeEnforce,
			Reason:   ReasonLookupFailed,
			MaxAge:   maxAge,
		}
	}
	if !ok {
		return Decision{
			Required: true,
			Allowed:  mode != ModeEnforce,
			Reason:   ReasonNeverVerified,
			MaxAge:   maxAge,
		}
	}

	age := time.Since(verified)
	if age <= maxAge {
		return Decision{
			Allowed:      true,
			Reason:       ReasonFresh,
			LastVerified: verified,
			Age:          age,
			MaxAge:       maxAge,
		}
	}
	return Decision{
		Required:     true,
		Allowed:      mode != ModeEnforce,
		Reason:       ReasonStale,
		LastVerified: verified,
		Age:          age,
		MaxAge:       maxAge,
	}
}

// Stamp records that this session has just proved a second factor. Called from
// the login path (when the flow verified one) and from /oauth/stepup-verify on
// success — the latter being what finally gives step-up an effect.
//
// Best-effort by contract: it returns the error for the caller to log, and no
// caller may fail a successful authentication because the stamp did not land.
// The consequence of a lost stamp is that the user is asked again, which is
// the safe direction.
func Stamp(ctx context.Context, db *database.PostgresDB, orgID, sessionID string) error {
	if db == nil || db.Pool == nil || sessionID == "" || orgID == "" {
		return nil
	}
	_, err := db.Pool.Exec(ctx,
		`UPDATE sessions SET mfa_verified_at = NOW() WHERE id = $1 AND org_id = $2`,
		sessionID, orgID)
	return err
}
