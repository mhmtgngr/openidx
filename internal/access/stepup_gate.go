package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/stepup"
)

// The MFA-freshness gate, at the two places the client access design names:
// launching a privileged session (or revealing the credential behind one), and
// any write made with admin authority.
//
// WHAT WAS MISSING. The product could ask a user to re-prove a factor
// mid-session -- /oauth/stepup-challenge, -verify and -status have shipped for
// a long time -- and nothing ever asked. The endpoints minted a step_up JWT no
// handler read, so a user who completed a challenge found the action they were
// stepping up FOR exactly as permitted, or refused, as before. Meanwhile the
// two actions that most want a fresh factor were gated only on who you are:
// once a laptop had signed in at 09:00, opening an RDP session to a domain
// controller at 19:00 asked nothing of the person holding it, and neither did
// deleting a user.
//
// WHAT THE GATE IS NOT. It is not a second authentication. It reads a
// timestamp the login and step-up paths write (sessions.mfa_verified_at, v186)
// and compares it to a window. Everything about proving the factor stays where
// it was; this only decides whether the proof is recent enough for THIS
// action, and answers a refusal with the endpoint that can fix it.
//
// The safe-method carve-out is deliberate and is checked before anything else:
// reading a page never triggers a re-authentication prompt. Only a write does,
// which is what the design says and what keeps a console usable.

// safeMethod reports whether this request only reads. GET/HEAD/OPTIONS are the
// methods a browser may issue on its own (a prefetch, a preflight), so they can
// never be the thing an operator meant to gate.
func safeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// stepUpCaller reads what the auth middleware established about who is asking.
func stepUpCaller(c *gin.Context) stepup.Caller {
	return stepup.Caller{
		UserID:           c.GetString("user_id"),
		OrgID:            c.GetString("org_id"),
		SessionID:        c.GetString("session_id"),
		AuthMethod:       c.GetString("auth_method"),
		ServiceAccountID: c.GetString("service_account_id"),
	}
}

// stepUpMode is the configured gate, or off when there is no config.
func (s *Service) stepUpMode() stepup.Mode {
	if s.config == nil {
		return stepup.ModeOff
	}
	return stepup.ParseMode(s.config.StepUpGate)
}

// requireFreshMFA is route middleware for the PAM launch and reveal endpoints.
// action names what is being attempted, and reaches the audit record and the
// refusal body so the user is told which thing needs the factor.
func (s *Service) requireFreshMFA(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.freshMFAAllows(c, appaccess.EnforcementPointPAMLaunch, action) {
			c.Next()
		}
	}
}

// adminWriteNeedsFreshMFA is the admin-authority half, called from
// requireAdminRole once the caller has been established as an admin.
//
// It hangs off the role gate rather than a list of admin endpoints on purpose.
// A list of "sensitive" admin routes is precisely the artefact that lets the
// next endpoint escape: someone adds a handler, mounts it beside its
// neighbours, and it inherits every gate except the one nobody remembered.
// Deriving it from the authority the request already carries means a route
// that requires admin gets this the day it is written.
//
// It is deliberately broader than a hand-picked list: an admin marking a
// notification read is gated too, because they hold admin authority while they
// do it. That is the conservative direction, and it is stated here rather than
// discovered by an operator.
func (s *Service) adminWriteNeedsFreshMFA(c *gin.Context) bool {
	return !s.freshMFAAllows(c, appaccess.EnforcementPointAdminWrite, c.Request.Method+" "+c.FullPath())
}

// freshMFAAllows evaluates the gate and, when it refuses, writes the 403 and
// aborts. It returns whether the request may proceed.
func (s *Service) freshMFAAllows(c *gin.Context, enforcementPoint, action string) bool {
	mode := s.stepUpMode()
	if mode == stepup.ModeOff {
		return true
	}
	if safeMethod(c.Request.Method) {
		return true
	}

	ctx := c.Request.Context()
	caller := stepUpCaller(c)
	// orgctx is the authoritative tenant for this request; the gin key is a
	// fallback for the paths that set it before the resolver runs.
	if org, err := orgctx.From(ctx); err == nil {
		caller.OrgID = org.ID
	}

	maxAge := stepup.MaxAge(ctx, s.db, s.config.StepUpMaxAge)
	decision := stepup.Gate(ctx, s.db, mode, maxAge, caller)
	if !decision.Required {
		return true
	}

	s.recordStepUpDecision(c, enforcementPoint, action, caller, decision)

	if decision.Allowed {
		return true
	}
	c.AbortWithStatusJSON(http.StatusForbidden, stepUpRefusal(action, decision))
	return false
}

// stepUpRefusal is the body a refused caller gets. It names the endpoint that
// clears the refusal, because a 403 that only says "no" leaves a user with a
// legitimate need and no route to it -- and because the console needs a
// machine-readable signal to open the step-up dialog rather than a toast.
func stepUpRefusal(action string, d stepup.Decision) gin.H {
	return gin.H{
		"error":             "step_up_required",
		"error_description": "this action requires a recently verified second factor",
		"reason":            d.Reason,
		"action":            action,
		"max_age_seconds":   int(d.MaxAge.Seconds()),
		"challenge_url":     "/oauth/stepup-challenge",
	}
}

// recordStepUpDecision writes the decision to unified_audit_events through the
// same path as the assignment and ABAC gates, on BOTH the observe and enforce
// branches. Enforcement is never quieter than report mode: an operator who
// flips the flag must not lose the records that told them it was safe.
func (s *Service) recordStepUpDecision(c *gin.Context, enforcementPoint, action string, caller stepup.Caller, d stepup.Decision) {
	enforced := !d.Allowed
	eventType := appaccess.StepUpDecisionEventType(enforced)
	details := appaccess.StepUpDecisionDetails(
		enforcementPoint, caller.UserID, action, d.Reason,
		int(d.Age.Seconds()), int(d.MaxAge.Seconds()), enforced, nil)

	if s.auditService == nil {
		s.logger.Warn("step-up decision not recorded: unified audit service unavailable",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", caller.UserID),
			logsafe.String("action", action),
			zap.Bool("enforced", enforced))
		return
	}
	if err := s.auditService.RecordEvent(c.Request.Context(), appaccess.SourceProxy, eventType,
		"", caller.UserID, c.ClientIP(), details); err != nil {
		s.logger.Warn("step-up decision not recorded: unified audit write failed",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", caller.UserID),
			logsafe.String("action", action),
			zap.Bool("enforced", enforced),
			zap.Error(err))
	}
}
