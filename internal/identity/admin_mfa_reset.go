// Package identity - an administrator resets a user's second factors.
//
// The per-factor removals in admin_signin_methods.go answer "this one phone is
// gone". The help-desk call is usually broader: the user has a new phone, the
// old authenticator app went with the old one, and they need to start over.
// Removing every factor one row at a time from the user page was the only way,
// and it left the account half-reset whenever the administrator missed one.
//
// POST /users/:id/mfa/reset removes the named factors -- or all of them -- in
// one transaction, scoped to the caller's organization, and audits it once
// with what was removed. The user then signs in with their password and is
// enrolled again under the grace period or the MFA policy that applies.
package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/middleware"
)

// mfaResetStatements maps every factor a reset can remove to the statement
// that removes all of the user's credentials of that kind. Each is scoped by
// user and org. The single-row factors are the per-factor admin removals'
// own statements, so the two paths cannot drift apart; security keys and
// push devices, which the per-factor path removes one id at a time, go all
// at once here. Spent backup codes stay, as they do there: they prove nothing.
var mfaResetStatements = map[string]string{
	"totp":         adminRemovableMethods["totp"],
	"email":        adminRemovableMethods["email"],
	"sms":          adminRemovableMethods["sms"],
	"backup_codes": adminRemovableMethods["backup_codes"],
	"webauthn":     `DELETE FROM mfa_webauthn WHERE user_id = $1 AND org_id = $2`,
	"push":         `DELETE FROM mfa_push_devices WHERE user_id = $1 AND org_id = $2`,
	"phone":        `DELETE FROM mfa_phone_call WHERE user_id = $1 AND org_id = $2`,
}

// mfaResetFactors lists the keys of mfaResetStatements in a stable order.
func mfaResetFactors() []string {
	out := make([]string, 0, len(mfaResetStatements))
	for f := range mfaResetStatements {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// errUnknownMFAFactor is returned for a factor name a reset does not know.
var errUnknownMFAFactor = errors.New("unknown MFA factor")

// normalizeMFAResetFactors lower-cases, de-duplicates and validates the
// requested factors. An empty request means every factor.
func normalizeMFAResetFactors(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return mfaResetFactors(), nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(requested))
	for _, f := range requested {
		f = strings.ToLower(strings.TrimSpace(f))
		if _, ok := mfaResetStatements[f]; !ok {
			return nil, fmt.Errorf("%w: %q", errUnknownMFAFactor, f)
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ResetMFA removes the given factors (already normalized) of userID in orgID,
// all or nothing, and reports how many credentials of each kind went.
func (s *Service) ResetMFA(ctx context.Context, orgID, userID string, factors []string) (map[string]int64, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	removed := make(map[string]int64, len(factors))
	for _, f := range factors {
		stmt, ok := mfaResetStatements[f]
		if !ok {
			return nil, fmt.Errorf("%w: %q", errUnknownMFAFactor, f)
		}
		tag, err := tx.Exec(ctx, stmt, userID, orgID)
		if err != nil {
			return nil, fmt.Errorf("reset %s: %w", f, err)
		}
		removed[f] = tag.RowsAffected()
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return removed, nil
}

// adminStepUp is the MFA-freshness gate (STEPUP_GATE, middleware.RequireFreshMFA)
// that admin-api mounts on every admin write, here on the identity writes that
// strip a user's second factors. The identity service does not otherwise
// mount it, and an MFA reset is exactly the change a stolen admin token is
// used for. With the gate off it does no work; reads and machine credentials
// are never gated. Decisions go to this service's audit trail.
func (s *Service) adminStepUp() gin.HandlerFunc {
	cfg := middleware.StepUpConfig{Source: "identity"}
	if s.cfg != nil {
		cfg.Gate, cfg.MaxAge = s.cfg.StepUpGate, s.cfg.StepUpMaxAge
	}
	return middleware.RequireFreshMFA(s.db, cfg, s.recordStepUpDecision, s.logger)
}

// recordStepUpDecision has the shape of middleware.StepUpRecorder and files
// the gate's decision as an identity audit event.
func (s *Service) recordStepUpDecision(ctx context.Context, source, eventType, _, userID, _ string, details map[string]interface{}) error {
	outcome := "success"
	if enforced, _ := details["enforced"].(bool); enforced {
		outcome = "failure"
	}
	s.logAuditEvent(ctx, source, "security", eventType, outcome, userID, userID, "user", details)
	return nil
}

// mfaResetRequest is the body of POST /users/:id/mfa/reset.
type mfaResetRequest struct {
	Factors []string `json:"factors"`
}

// handleAdminResetMFA serves POST /users/:id/mfa/reset.
func (s *Service) handleAdminResetMFA(c *gin.Context) {
	org, userID, ok := s.adminTargetInOrg(c)
	if !ok {
		return
	}
	// An administrator's own factors change through their profile, which asks
	// them for their password or a current code. This path asks for neither,
	// so it must not be a way around that.
	if actor := c.GetString("user_id"); actor != "" && actor == userID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "reset your own MFA from your profile, not through the admin reset",
		})
		return
	}

	var req mfaResetRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
	}
	factors, err := normalizeMFAResetFactors(req.Factors)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unknown MFA factor; one of " + strings.Join(mfaResetFactors(), ", "),
		})
		return
	}

	removed, err := s.ResetMFA(c.Request.Context(), org.ID, userID, factors)
	if err != nil {
		s.logger.Error("could not reset a user's MFA",
			logsafe.String("user_id", userID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reset MFA"})
		return
	}
	var total int64
	for _, n := range removed {
		total += n
	}
	s.auditAdminSignInChange(c, "mfa.admin_reset", userID, map[string]interface{}{
		"factors": factors, "removed": removed, "total_removed": total,
	})
	c.JSON(http.StatusOK, gin.H{"factors": factors, "removed": removed, "total_removed": total})
}
