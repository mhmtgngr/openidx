package oauth

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/appaccess"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// recordAssignmentDecision durably records one /oauth/authorize assignment-gate
// decision into unified_audit_events.
//
// Why not logAuditEvent (saml.go): that writes audit_events, which is org-scoped
// and whose RLS policy rejects these writes — on the live box audit_events has
// taken one row since June while unified_audit_events takes writes today, and
// it carries no `oauth` source at all. In report mode
// (ACCESS_ASSIGNMENT_ENFORCE=false, the default) these records are the ONLY
// evidence an operator has for whether flipping the flag is safe, and the flip
// is irreversible — so they have to land in the table that accepts them.
//
// unified_audit_events has no org_id column, so this is a plain insert and RLS
// is not in play; do not add org scoping the table cannot express. route_id is
// left NULL: this enforcement point exists precisely for applications with no
// published route.
//
// This is a side-effect recorder only. It never influences the gate's verdict,
// never returns an error to the caller, and every failure is logged at WARN —
// a silently dropped decision record is the defect this exists to fix.
func (s *Service) recordAssignmentDecision(ctx context.Context, userID, clientID, appID, actorIP string, enforced bool) {
	eventType := appaccess.DecisionEventType(enforced)
	details := appaccess.DecisionDetails(appaccess.EnforcementPointOIDC, userID, appID, enforced,
		map[string]interface{}{"client_id": clientID})

	if s.db == nil || s.db.Pool == nil {
		s.logger.Warn("assignment decision not recorded: no database handle",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", userID),
			logsafe.String("client_id", clientID),
			logsafe.String("application_id", appID),
			zap.Bool("enforced", enforced))
		return
	}

	detailsJSON, err := json.Marshal(details)
	if err != nil {
		s.logger.Warn("assignment decision not recorded: details would not marshal",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", userID),
			logsafe.String("application_id", appID),
			zap.Error(err))
		return
	}

	var userIDPtr *string
	if userID != "" {
		userIDPtr = &userID
	}

	//orgscope:ignore unified_audit_events has no org_id column by design (that is why it accepts these writes at all); the record is scoped by user_id + application_id instead
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO unified_audit_events (id, source, event_type, route_id, user_id, actor_ip, details, created_at)
		VALUES ($1, $2, $3, NULL, $4, $5, $6, NOW())
	`, uuid.New().String(), appaccess.SourceOIDC, eventType, userIDPtr, actorIP, detailsJSON); err != nil {
		s.logger.Warn("assignment decision not recorded: unified audit write failed",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", userID),
			logsafe.String("client_id", clientID),
			logsafe.String("application_id", appID),
			zap.Bool("enforced", enforced),
			zap.Error(err))
	}
}

// recordABACDecision durably records one /oauth/authorize ABAC decision, on the
// same path and with the same guarantees as recordAssignmentDecision: it lands
// in unified_audit_events, it is written on BOTH the observe and enforce
// branches so enforcement is never quieter than report mode, it never
// influences the verdict, and every failure is logged rather than swallowed.
func (s *Service) recordABACDecision(ctx context.Context, userID, clientID, appID, actorIP, policyID, policyReason string, enforced bool) {
	eventType := appaccess.ABACDecisionEventType(enforced)
	details := appaccess.ABACDecisionDetails(appaccess.EnforcementPointOIDC, userID, appID, policyID, policyReason, enforced,
		map[string]interface{}{"client_id": clientID})

	if s.db == nil || s.db.Pool == nil {
		s.logger.Warn("abac decision not recorded: no database handle",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", userID),
			logsafe.String("client_id", clientID))
		return
	}

	detailsJSON, err := json.Marshal(details)
	if err != nil {
		s.logger.Warn("abac decision not recorded: details would not marshal",
			logsafe.String("event_type", eventType), zap.Error(err))
		return
	}

	var userIDPtr *string
	if userID != "" {
		userIDPtr = &userID
	}

	//orgscope:ignore unified_audit_events has no org_id column by design (that is why it accepts these writes at all); the record is scoped by user_id + application_id instead
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO unified_audit_events (id, source, event_type, route_id, user_id, actor_ip, details, created_at)
		VALUES ($1, $2, $3, NULL, $4, $5, $6, NOW())
	`, uuid.New().String(), appaccess.SourceOIDC, eventType, userIDPtr, actorIP, detailsJSON); err != nil {
		s.logger.Warn("abac decision not recorded: unified audit write failed",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", userID),
			logsafe.String("client_id", clientID),
			zap.Bool("enforced", enforced),
			zap.Error(err))
	}
}
