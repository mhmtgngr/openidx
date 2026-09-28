package governance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
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
			`SELECT DISTINCT user_id FROM user_roles WHERE role_id = $1 AND org_id = $2`, step.RoleID, orgID)
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
			`SELECT DISTINCT user_id FROM group_memberships WHERE group_id = $1 AND org_id = $2`, step.GroupID, orgID)
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
	return ids, nil
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
	}
}
