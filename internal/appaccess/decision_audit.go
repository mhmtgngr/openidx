package appaccess

// The assignment gate's decision record.
//
// `ACCESS_ASSIGNMENT_ENFORCE=false` is the default and means report-only: both
// enforcement points (the reverse proxy's overlay in internal/access, and
// /oauth/authorize in internal/oauth) evaluate the gate, deny nothing, and
// record the gap. Those records are the ENTIRE evidence base for deciding
// whether to flip the flag, and the flip is the one irreversible step of the
// rollout — so a record that is dropped, or written in a shape only one of the
// two enforcement points emits, defeats the staging plan.
//
// The two enforcement points live in different packages with different context
// plumbing, and a reviewer previously caught them emitting different outcome
// strings and putting the user id in different places. The shape therefore
// lives here, next to Allowed() — the one function both of them ask the
// underlying question with — so "one query finds both" is true by
// construction rather than by two hand-maintained literals agreeing.
//
// Both points write to `unified_audit_events`, NOT `audit_events`: the unified
// stream is what the console's audit page and the Assignment Report read, and
// it carries the `oauth` source that audit_events does not.
//
// This paragraph used to end "unified_audit_events has no org_id column and so
// is not subject to the org-scoped RLS policy the audit_events writes fall foul
// of. Do not add org scoping to these records — the table cannot express it."
// The premise was a bug wearing a design's clothes: audit_events was refusing
// those writes because their context was detached, not because the record was
// wrong, and a table that cannot say whose row it holds shows every tenant's
// enforcement decisions to every tenant. Since v142 the table carries org_id
// under the FORCE belt and both writers stamp it.
const (
	// EventTypeWouldDeny is the report-mode record: the caller was NOT
	// assigned, the flag was off, and the request was allowed anyway. These
	// are the rows an operator counts before flipping the flag.
	EventTypeWouldDeny = "access.assignment.would_deny"

	// EventTypeDenied is the enforcement record: the caller was not assigned,
	// the flag was on, and the request was actually refused. Enforcement must
	// never be quieter than report mode, so this is recorded on the same path
	// through the same builder; it is a distinct event_type only so an
	// operator filtering for real denials is not swamped by the report-mode
	// rows, matching how the two points already distinguish real denials in
	// their legacy audit streams.
	EventTypeDenied = "access.assignment.denied"

	// ReasonNotAssigned is the only reason either gate produces today. It is a
	// constant so the details key has a stable, greppable value.
	ReasonNotAssigned = "not_assigned"

	// SourceProxy is the unified_audit_events.source for the reverse-proxy
	// enforcement point. It matches the source the access service's other
	// healthy unified writes already use, so these rows land in the same
	// stream operators already query.
	SourceProxy = "access-service"

	// SourceOIDC is the unified_audit_events.source for the /oauth/authorize
	// enforcement point. Before this, no oauth rows reached the table at all.
	SourceOIDC = "oauth"

	// EnforcementPointProxy / EnforcementPointOIDC are the details values that
	// say WHICH gate produced a record, so a single query over both sources
	// can still tell them apart.
	EnforcementPointProxy = "proxy"
	EnforcementPointOIDC  = "oidc"
)

// DecisionEventType maps one gate decision to its unified event_type.
// enforced reports whether ACCESS_ASSIGNMENT_ENFORCE was on and the request
// was therefore actually refused, rather than merely recorded.
func DecisionEventType(enforced bool) string {
	if enforced {
		return EventTypeDenied
	}
	return EventTypeWouldDeny
}

// DecisionDetailKeys is the canonical set of details keys EVERY assignment
// decision record carries, whichever enforcement point wrote it. A query
// filtering or grouping on any of these finds both sides. Enforcement points
// may add their own keys on top (the proxy adds the route name; the OIDC gate
// adds the client id) — extra keys never remove the guarantee, missing ones
// would.
var DecisionDetailKeys = []string{
	"enforcement_point",
	"user_id",
	"application_id",
	"reason",
	"enforced",
}

// DecisionDetails builds the details payload for one assignment-gate decision.
//
// user_id is carried in details even though the proxy also has a dedicated
// user_id column and the OIDC side does not always populate one: a reviewer
// found the user reachable in the actor field on one side and buried in
// details on the other, so it is now in BOTH places on both sides and a query
// on details->>'user_id' works uniformly.
//
// extra is merged last but may not overwrite a canonical key — the shape is
// the point.
func DecisionDetails(enforcementPoint, userID, applicationID string, enforced bool, extra map[string]interface{}) map[string]interface{} {
	d := map[string]interface{}{
		"enforcement_point": enforcementPoint,
		"user_id":           userID,
		"application_id":    applicationID,
		"reason":            ReasonNotAssigned,
		"enforced":          enforced,
	}
	for k, v := range extra {
		if _, canonical := d[k]; canonical {
			continue
		}
		d[k] = v
	}
	return d
}

// --- ABAC decisions -------------------------------------------------------
//
// The ABAC gate (internal/abac, ABAC_ENFORCE) writes through the same table
// and the same canonical details keys as the assignment gate, so one query
// over unified_audit_events finds every reason a request was refused or would
// have been. Only the event_type and the reason differ, which is what lets an
// operator separate "not assigned to the app" from "a policy said no".
const (
	// EventTypeABACWouldDeny is the observe-mode record: the tenant's policies
	// denied, ABAC_ENFORCE was not "enforce", and the request proceeded. These
	// are the rows an operator counts before moving to enforce.
	EventTypeABACWouldDeny = "access.abac.would_deny"

	// EventTypeABACDenied is the enforcement record.
	EventTypeABACDenied = "access.abac.denied"

	// ReasonABACDenied is the reason value both ABAC records carry.
	ReasonABACDenied = "abac_policy_denied"
)

// ABACDecisionEventType maps one ABAC decision to its unified event_type.
func ABACDecisionEventType(enforced bool) string {
	if enforced {
		return EventTypeABACDenied
	}
	return EventTypeABACWouldDeny
}

// ABACDecisionDetails builds the details payload for one ABAC decision. It
// carries every key in DecisionDetailKeys, with reason = ReasonABACDenied, plus
// the policy that decided it — without policy_id an operator reading a denial
// cannot tell which of their policies produced it, which is the first question
// they will ask.
func ABACDecisionDetails(enforcementPoint, userID, applicationID, policyID, policyReason string, enforced bool, extra map[string]interface{}) map[string]interface{} {
	d := map[string]interface{}{
		"enforcement_point": enforcementPoint,
		"user_id":           userID,
		"application_id":    applicationID,
		"reason":            ReasonABACDenied,
		"enforced":          enforced,
		"policy_id":         policyID,
		"policy_reason":     policyReason,
	}
	for k, v := range extra {
		if _, canonical := d[k]; canonical {
			continue
		}
		d[k] = v
	}
	return d
}
