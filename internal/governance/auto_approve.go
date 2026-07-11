package governance

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Auto-approval of access requests (V-007).
//
// Approval policies have carried a typed auto_approve_conditions field —
// validated at save time and echoed by the API — since the V-007 fix, but
// nothing ever evaluated it: requests always went through the manual approval
// chain, and admins who configured auto-approval were silently ignored.
//
// tryAutoApprove evaluates the conditions at request creation, fail-closed in
// every direction:
//
//   - a nil or empty conditions object never auto-approves (absence of
//     conditions means manual approval, not approve-everyone);
//   - every SET condition must be supported AND hold;
//   - MaxRiskScore and MaxRequestCount are stored but NOT auto-evaluated —
//     there is no canonical per-user risk score (risk_score exists only per
//     login_history/proxy_sessions row) and no defined counting window. If
//     either is set the policy never auto-approves, and a warning says so,
//     rather than inventing semantics for an approval bypass;
//   - any query error means no auto-approval.
//
// On success the request takes the exact same path as the final manual
// approval decision: status -> approved, then fulfillRequest — so the SoD
// gate on role grants and the fail-loud unknown-resource handling apply to
// auto-approved requests identically.

// tryAutoApprove returns true when the request was auto-approved (and
// fulfillment attempted). The caller skips creating approval rows.
func (s *Service) tryAutoApprove(ctx context.Context, requestID string, cond *AutoApproveConditions) bool {
	if cond == nil {
		return false
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return false
	}

	var request AccessRequest
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT id, requester_id, resource_type, COALESCE(resource_id, ''), COALESCE(resource_name, ''), expires_at
		 FROM access_requests WHERE id = $1 AND org_id = $2`,
		requestID, org.ID,
	).Scan(&request.ID, &request.RequesterID, &request.ResourceType, &request.ResourceID,
		&request.ResourceName, &request.ExpiresAt); err != nil {
		s.logger.Warn("auto-approve: request lookup failed", zap.String("request_id", requestID), zap.Error(err))
		return false
	}

	if !s.autoApproveConditionsMet(ctx, org.ID, request.RequesterID, cond) {
		return false
	}

	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE access_requests SET status = 'approved', updated_at = $1 WHERE id = $2 AND org_id = $3`,
		time.Now(), requestID, org.ID); err != nil {
		s.logger.Error("auto-approve: failed to mark request approved", zap.Error(err))
		return false
	}
	request.Status = "approved"

	// Same semantics as the manual decision path: a fulfillment error is
	// logged, the request stays approved.
	if err := s.fulfillRequest(ctx, &request); err != nil {
		s.logger.Error("auto-approve: failed to fulfill request",
			zap.String("request_id", requestID), zap.Error(err))
	}

	// Best-effort audit: an approval bypass firing must be traceable.
	details, _ := json.Marshal(map[string]any{
		"request_id": requestID, "resource_type": request.ResourceType, "resource_id": request.ResourceID,
	})
	if _, err := s.db.Pool.Exec(ctx,
		`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
		 VALUES (gen_random_uuid(), 'access', 'governance', 'access_request.auto_approved', 'success', $1, '0.0.0.0', $2, 'access_request', $3, NOW(), $4)`,
		request.RequesterID, requestID, string(details), org.ID); err != nil {
		s.logger.Warn("auto-approve: failed to write audit event",
			zap.String("request_id", requestID), zap.Error(err))
	}
	return true
}

// autoApproveConditionsMet evaluates only — no side effects. True only when
// at least one supported condition is set and every set condition holds.
func (s *Service) autoApproveConditionsMet(ctx context.Context, orgID, requesterID string, cond *AutoApproveConditions) bool {
	if cond.MaxRiskScore != nil {
		s.logger.Warn("auto_approve_conditions.max_risk_score is not auto-evaluated (no canonical per-user risk score); policy will not auto-approve")
		return false
	}
	if cond.MaxRequestCount != nil {
		s.logger.Warn("auto_approve_conditions.max_request_count is not auto-evaluated (no defined counting window); policy will not auto-approve")
		return false
	}

	anySet := false

	if len(cond.AllowedRoles) > 0 {
		anySet = true
		var n int
		if err := s.db.Pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM user_roles ur
			JOIN roles r ON ur.role_id = r.id AND r.org_id = ur.org_id
			WHERE ur.user_id = $1 AND ur.org_id = $2
			  AND (r.name = ANY($3) OR r.id::text = ANY($3))`,
			requesterID, orgID, cond.AllowedRoles).Scan(&n); err != nil || n == 0 {
			return false
		}
	}

	if len(cond.AllowedGroups) > 0 {
		anySet = true
		var n int
		if err := s.db.Pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM group_memberships gm
			JOIN groups g ON gm.group_id = g.id AND g.org_id = gm.org_id
			WHERE gm.user_id = $1 AND gm.org_id = $2
			  AND (g.name = ANY($3) OR g.id::text = ANY($3))`,
			requesterID, orgID, cond.AllowedGroups).Scan(&n); err != nil || n == 0 {
			return false
		}
	}

	if cond.RequireMFA != nil && *cond.RequireMFA {
		anySet = true
		var n int
		if err := s.db.Pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM (
				SELECT user_id FROM mfa_totp WHERE user_id = $1 AND org_id = $2 AND enabled = true
				UNION
				SELECT user_id FROM mfa_webauthn WHERE user_id = $1 AND org_id = $2
			) t`,
			requesterID, orgID).Scan(&n); err != nil || n == 0 {
			return false
		}
	}

	return anySet
}
