package oauth

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/appaccess"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// recordAssignmentDecision durably records one /oauth/authorize assignment-gate
// decision into unified_audit_events.
//
// Why unified_audit_events and not audit_events (saml.go's logAuditEvent): the
// unified stream is what the console's audit page and the Assignment Report
// read, and it carries an `oauth` source that audit_events does not. In report
// mode (ACCESS_ASSIGNMENT_ENFORCE=false, the default) these records are the
// ONLY evidence an operator has for whether flipping the flag is safe, and the
// flip is irreversible.
//
// This comment used to say something else — that audit_events "rejects these
// writes" and that unified_audit_events "has no org_id column by design (that
// is why it accepts these writes at all)". Both halves were wrong in the same
// way. audit_events was rejecting writes because its writers handed the pool a
// detached context.Background(), leaving app.org_id empty so RLS refused them;
// that was a bug, not a property of the table. And a missing tenant column is
// not a design: it meant every tenant's admin could read every tenant's
// enforcement decisions off the audit page. v142 gives the table org_id and the
// FORCE belt, so this insert names the tenant like every other.
//
// route_id is left NULL: this enforcement point exists precisely for
// applications with no published route.
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

	orgID, resolved := orgctx.AuditOrgID(ctx)
	if !resolved {
		s.logger.Warn("assignment decision has no org context; filed under the primary organization",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", userID),
			logsafe.String("client_id", clientID))
	}

	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO unified_audit_events (id, org_id, source, event_type, route_id, user_id, actor_ip, details, created_at)
		VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, NOW())
	`, uuid.New().String(), orgID, appaccess.SourceOIDC, eventType, userIDPtr, actorIP, detailsJSON); err != nil {
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

	orgID, resolved := orgctx.AuditOrgID(ctx)
	if !resolved {
		s.logger.Warn("abac decision has no org context; filed under the primary organization",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", userID),
			logsafe.String("client_id", clientID))
	}

	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO unified_audit_events (id, org_id, source, event_type, route_id, user_id, actor_ip, details, created_at)
		VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, NOW())
	`, uuid.New().String(), orgID, appaccess.SourceOIDC, eventType, userIDPtr, actorIP, detailsJSON); err != nil {
		s.logger.Warn("abac decision not recorded: unified audit write failed",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", userID),
			logsafe.String("client_id", clientID),
			zap.Bool("enforced", enforced),
			zap.Error(err))
	}
}
