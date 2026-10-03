package governance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/externalid"
)

// The three approval-policy fields that decided nothing.
//
// approval_policies has stored max_wait_hours since the first schema, every
// ApprovalStep has carried Order and MinApprovals, and the console has shown
// all three. Until this file none of them was read where a decision is made:
// every approver row had to approve whatever a step's min_approvals said, the
// rows of every step were live at once whatever their order, and a request
// nobody answered stayed pending for ever. This file is where they are read.
//
//   - A step needs min_approvals approvals (one when unset) from the rows the
//     policy expanded it into. A step that cannot reach that number is refused
//     when the request is filed, not left to sit.
//   - Steps run in order. Only the rows of the lowest unsatisfied step may
//     decide; an approver of a later step is told to wait, and the queue does
//     not show them the request yet. When a step is satisfied its remaining
//     rows are skipped, so nobody is asked for an approval that no longer
//     counts.
//   - A request no policy step answers within max_wait_hours expires, with a
//     row in the audit trail; the deadline is recorded on the request when it
//     is filed so a policy edited afterwards does not move it.
//
// The per-row minimum and the deadline are recorded on the rows (migration
// v212), not looked up from the policy at decision time: a request keeps the
// terms it was filed under.

// chainError says why a policy's chain cannot be built for this request. It is
// a fact about the policy and the directory, not about the caller, and the
// requester is told the reason rather than a generic failure.
type chainError struct{ reason string }

func (e *chainError) Error() string { return e.reason }

// effectiveOrder is the step's position: its order when set, the legacy
// step_order when that is set instead, else its place in the list.
func (st ApprovalStep) effectiveOrder(index int) int {
	if st.Order > 0 {
		return st.Order
	}
	if st.StepOrder > 0 {
		return st.StepOrder
	}
	return index + 1
}

// effectiveMinApprovals is how many approvals the step needs; one when unset.
func (st ApprovalStep) effectiveMinApprovals() int {
	if st.MinApprovals > 0 {
		return st.MinApprovals
	}
	return 1
}

// resolveStepApprovers names the users a step expands to, in the org, with the
// requester excluded (four eyes) and each user once.
func (s *Service) resolveStepApprovers(ctx context.Context, orgID string, step ApprovalStep, requesterID string) ([]string, error) {
	var ids []string
	add := func(id string) {
		if id == "" || id == requesterID {
			return
		}
		for _, have := range ids {
			if have == id {
				return
			}
		}
		ids = append(ids, id)
	}
	switch step.Type {
	case ApprovalStepTypeSpecificUser:
		add(step.ApproverID)
	case ApprovalStepTypeRole:
		if step.RoleID == "" {
			return nil, &chainError{"an approval step of type role names no role"}
		}
		rows, err := s.db.Pool.Query(ctx,
			`SELECT DISTINCT user_id FROM user_roles WHERE role_id = $1 AND org_id = $2
			   AND (expires_at IS NULL OR expires_at > NOW())`, step.RoleID, orgID)
		if err != nil {
			return nil, fmt.Errorf("list the holders of the approver role: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, fmt.Errorf("scan an approver role holder: %w", err)
			}
			add(id)
		}
	case ApprovalStepTypeGroup:
		if step.GroupID == "" {
			return nil, &chainError{"an approval step of type group names no group"}
		}
		rows, err := s.db.Pool.Query(ctx,
			`SELECT DISTINCT user_id FROM group_memberships WHERE group_id = $1 AND org_id = $2
			   AND (expires_at IS NULL OR expires_at > NOW())`, step.GroupID, orgID)
		if err != nil {
			return nil, fmt.Errorf("list the members of the approver group: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, fmt.Errorf("scan an approver group member: %w", err)
			}
			add(id)
		}
	case ApprovalStepTypeManager:
		var managerID *string
		if err := s.db.Pool.QueryRow(ctx,
			`SELECT manager_id FROM users WHERE id = $1 AND org_id = $2`, requesterID, orgID).Scan(&managerID); err != nil {
			return nil, fmt.Errorf("look up the requester's manager: %w", err)
		}
		if managerID == nil {
			return nil, &chainError{"the approval policy routes this request to the requester's manager, and the requester has none"}
		}
		add(*managerID)
	default:
		return nil, &chainError{fmt.Sprintf("the approval policy has a step of unknown type %q", step.Type)}
	}
	return s.withoutExternalApprovers(ctx, orgID, ids)
}

// withoutExternalApprovers drops external (vendor) users from a step's
// approvers, keeping the order: an external user never approves (invariant
// I2). A role an external user cannot hold rules most of them out already;
// this covers the rest, a group step on an external_allowed group, a manager
// step, and a specific user. The database refuses an external approver row as
// well (migration v214), so a step that resolved one would otherwise fail the
// whole request instead of losing that approver. A step left with too few is
// refused by the caller's min_approvals check, like any other short step.
func (s *Service) withoutExternalApprovers(ctx context.Context, orgID string, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return ids, nil
	}
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id::text FROM users WHERE id = ANY($1::uuid[]) AND org_id = $2 AND user_type = 'external'`, ids, orgID)
	if err != nil {
		return nil, fmt.Errorf("check the approvers' user type: %w", err)
	}
	defer rows.Close()
	external := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan an external approver: %w", err)
		}
		external[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("check the approvers' user type: %w", err)
	}
	if len(external) == 0 {
		return ids, nil
	}
	kept := ids[:0:0]
	for _, id := range ids {
		if !external[id] {
			kept = append(kept, id)
		}
	}
	return kept, nil
}

// stepProgress is one step's state, from its rows.
type stepProgress struct {
	Order    int
	Needed   int
	Approved int
	Pending  int
}

// satisfied reports whether the step has the approvals it needs.
func (p stepProgress) satisfied() bool { return p.Approved >= p.Needed }

// approvalProgress reads a request's steps from its rows: the step each row
// belongs to, how many approvals that step needs and how many it has. active
// is the lowest unsatisfied step, 0 when every step is satisfied (done true)
// and when the request has no rows at all (done false: nobody can approve a
// request that has no approvers).
func (s *Service) approvalProgress(ctx context.Context, requestID, orgID string) (steps []stepProgress, active int, done bool, err error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT step_order, MAX(step_min_approvals),
		        COUNT(*) FILTER (WHERE decision = 'approved'),
		        COUNT(*) FILTER (WHERE decision = 'pending')
		   FROM access_request_approvals
		  WHERE request_id = $1 AND org_id = $2
		  GROUP BY step_order
		  ORDER BY step_order`, requestID, orgID)
	if err != nil {
		return nil, 0, false, fmt.Errorf("read the request's approval steps: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p stepProgress
		if err := rows.Scan(&p.Order, &p.Needed, &p.Approved, &p.Pending); err != nil {
			return nil, 0, false, fmt.Errorf("scan an approval step: %w", err)
		}
		steps = append(steps, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, fmt.Errorf("read the request's approval steps: %w", err)
	}
	if len(steps) == 0 {
		return steps, 0, false, nil
	}
	for _, p := range steps {
		if !p.satisfied() {
			return steps, p.Order, false, nil
		}
	}
	return steps, 0, true, nil
}

// callerStep is the step of the caller's pending row on the request, or 0
// when they have none.
func (s *Service) callerStep(ctx context.Context, requestID, approverID, orgID string) (int, error) {
	var step int
	err := s.db.Pool.QueryRow(ctx,
		`SELECT step_order FROM access_request_approvals
		  WHERE request_id = $1 AND approver_id = $2 AND decision = 'pending' AND org_id = $3
		  ORDER BY step_order LIMIT 1`, requestID, approverID, orgID).Scan(&step)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("find the caller's approval row: %w", err)
	}
	return step, nil
}

// skipRemainingInStep marks the still-pending rows of a satisfied step as
// skipped, so an approver whose decision no longer counts is not asked for
// it. Returns how many rows it closed.
func (s *Service) skipRemainingInStep(ctx context.Context, requestID string, step int, orgID string) (int64, error) {
	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE access_request_approvals SET decision = 'skipped', decided_at = NOW()
		  WHERE request_id = $1 AND step_order = $2 AND decision = 'pending' AND org_id = $3`,
		requestID, step, orgID)
	if err != nil {
		return 0, fmt.Errorf("skip the remaining approvers of step %d: %w", step, err)
	}
	return tag.RowsAffected(), nil
}

// expireUnansweredRequests ends every pending request whose answer_by has
// passed: the request becomes expired, its pending rows are closed, and an
// audit row says the policy's wait ran out. Idempotent, install-wide (the
// deadline is the request's own, whatever its organization), and run from the
// JIT expiry sweep.
func (s *Service) expireUnansweredRequests(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide sweep over every tenant's pending requests; each row's own org_id scopes the writes below
		`UPDATE access_requests SET status = 'expired', updated_at = NOW()
		  WHERE status = 'pending' AND answer_by IS NOT NULL AND answer_by < NOW()
		  RETURNING id, org_id, requester_id, resource_type, resource_id, resource_name, answer_by`)
	if err != nil {
		s.logger.Warn("approval timeout sweep: could not expire unanswered requests", zap.Error(err))
		return
	}
	type expired struct {
		id, org, requester, rtype, rid, rname string
		answerBy                              time.Time
	}
	var done []expired
	for rows.Next() {
		var e expired
		if err := rows.Scan(&e.id, &e.org, &e.requester, &e.rtype, &e.rid, &e.rname, &e.answerBy); err != nil {
			s.logger.Warn("approval timeout sweep: scan failed", zap.Error(err))
			continue
		}
		done = append(done, e)
	}
	rows.Close()
	for _, e := range done {
		if _, err := s.db.Pool.Exec(ctx,
			`UPDATE access_request_approvals SET decision = 'expired', decided_at = NOW()
			  WHERE request_id = $1 AND org_id = $2 AND decision = 'pending'`, e.id, e.org); err != nil {
			s.logger.Warn("approval timeout sweep: could not close the approval rows",
				logsafe.String("request_id", e.id), zap.Error(err))
		}
		details := fmt.Sprintf(`{"request_id":%q,"resource_name":%q,"answer_by":%q,"reason":"no decision before the policy's max_wait_hours"}`,
			e.id, logsafe.Clean(e.rname), e.answerBy.UTC().Format(time.RFC3339))
		if _, err := s.db.Pool.Exec(ctx,
			`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
			 VALUES (gen_random_uuid(), 'access', 'provisioning', 'access_request.expired_unanswered', 'success', $1, '0.0.0.0', $2, $3, $4, NOW(), $5)`,
			e.requester, e.rid, e.rtype, details, e.org); err != nil {
			s.logger.Warn("approval timeout sweep: audit write failed",
				logsafe.String("request_id", e.id), zap.Error(err))
		}
		s.logger.Info("approval timeout sweep: an unanswered access request expired",
			logsafe.String("request_id", e.id), logsafe.String("requester_id", e.requester))
		s.requestEnded(ctx, e.org, e.id, "unanswered")
	}
}

// requesterSponsor reports whether the requester is an external (vendor) user
// and, if so, their sponsor. An external user with no sponsor cannot have a
// request approved: the account is suspended, expired or disabled once its
// sponsor goes, and the request is refused with that said.
func (s *Service) requesterSponsor(ctx context.Context, orgID, requesterID string) (string, bool, error) {
	if requesterID == "" {
		return "", false, nil
	}
	// The type first, as I4's check reads it, and the account only for an
	// external user.
	external, err := externalid.IsExternal(ctx, s.db.Pool, orgID, requesterID)
	if err != nil {
		return "", false, fmt.Errorf("read whether the requester is an external user: %w", err)
	}
	if !external {
		return "", false, nil
	}
	acct, err := externalid.Load(ctx, s.db.Pool, orgID, requesterID)
	if err != nil {
		return "", true, fmt.Errorf("read the external requester's sponsor: %w", err)
	}
	if acct.SponsorUserID == "" {
		return "", true, &chainError{"an external user's request is approved by their sponsor first, and this account has no sponsor"}
	}
	return acct.SponsorUserID, true, nil
}

// withoutApprover returns ids without id.
func withoutApprover(ids []string, id string) []string {
	out := make([]string, 0, len(ids))
	for _, v := range ids {
		if v != id {
			out = append(out, v)
		}
	}
	return out
}

// approverBasis is why an approver is on an approval row (migration v226):
// the step that named them, and the role or group a role or group step named.
// The approver is held to it when they decide.
type approverBasis struct {
	kind string // basisUser, basisRole, basisGroup, basisManager, basisSponsor, basisDefault
	id   string // the role or group, for basisRole and basisGroup
}

const (
	basisUser    = "user"    // a specific_user step names them: nothing to re-check
	basisRole    = "role"    // they held the step's role when the request was filed
	basisGroup   = "group"   // they were in the step's group
	basisManager = "manager" // they were the requester's manager
	basisSponsor = "sponsor" // they were the external requester's sponsor
	basisDefault = "default" // no policy covers the request: the default approver
)

// basis is the approverBasis of the rows a step expands to.
func (st ApprovalStep) basis() approverBasis {
	switch st.Type {
	case ApprovalStepTypeRole:
		return approverBasis{kind: basisRole, id: st.RoleID}
	case ApprovalStepTypeGroup:
		return approverBasis{kind: basisGroup, id: st.GroupID}
	case ApprovalStepTypeManager:
		return approverBasis{kind: basisManager}
	default:
		return approverBasis{kind: basisUser}
	}
}

// approverEligibleSQL is true when the approver of approval row a, on request
// ar, still stands where their row's basis put them: a role or a group step's
// approver still holds the role or the membership, live (its window open); a
// manager step's approver is still the requester's manager; a sponsor is
// still the external requester's sponsor. A row naming a user, the default
// approver's row, and a row written before v226 (no basis) are not
// re-checked. The approver's queue and the decision read the same predicate,
// so the queue offers nothing the decision refuses.
const approverEligibleSQL = `(CASE a.approver_basis
	WHEN 'role' THEN EXISTS (SELECT 1 FROM user_roles ur
	                          WHERE ur.user_id = a.approver_id AND ur.role_id = a.approver_basis_id AND ur.org_id = a.org_id
	                            AND (ur.expires_at IS NULL OR ur.expires_at > NOW()))
	WHEN 'group' THEN EXISTS (SELECT 1 FROM group_memberships gm
	                           WHERE gm.user_id = a.approver_id AND gm.group_id = a.approver_basis_id AND gm.org_id = a.org_id
	                             AND (gm.expires_at IS NULL OR gm.expires_at > NOW()))
	WHEN 'manager' THEN EXISTS (SELECT 1 FROM users rq
	                             WHERE rq.id = ar.requester_id AND rq.org_id = ar.org_id AND rq.manager_id = a.approver_id)
	WHEN 'sponsor' THEN EXISTS (SELECT 1 FROM users rq
	                             WHERE rq.id = ar.requester_id AND rq.org_id = ar.org_id AND rq.sponsor_user_id = a.approver_id)
	ELSE TRUE END)`

// approverStillEligible reports whether any of the caller's pending rows at
// step still stands on its basis (approverEligibleSQL). The chain is built when
// the request is filed, from the roles, groups, manager and sponsor of that
// day; an approver who has since lost what put them on it no longer decides.
//
// Any, not one: two steps of a policy can share a step order, so one approver
// can hold two rows there on two bases (the requester's manager who also holds
// the step's role). The queue shows the request while either stands, and the
// decision has to agree with it; a single row read with LIMIT 1 was whichever
// one the database returned first.
func (s *Service) approverStillEligible(ctx context.Context, requestID, approverID string, step int, orgID string) (bool, error) {
	var ok bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(bool_or(`+approverEligibleSQL+`), false)
		  FROM access_request_approvals a
		  JOIN access_requests ar ON ar.id = a.request_id AND ar.org_id = a.org_id
		 WHERE a.request_id = $1 AND a.approver_id = $2 AND a.step_order = $3
		   AND a.decision = 'pending' AND a.org_id = $4`, requestID, approverID, step, orgID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("re-check the approver's basis: %w", err)
	}
	return ok, nil
}
