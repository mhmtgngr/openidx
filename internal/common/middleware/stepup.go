package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/stepup"
)

// RequireFreshMFA is the admin-API half of the STEPUP_GATE freshness gate: a
// write made with admin authority needs a recently verified second factor.
//
// The access service applies the same rule inside its own requireAdminRole.
// Here the surface is the whole /api/v1 admin group, so the gate is mounted
// once on the group and decides per request from two facts the request already
// carries -- the HTTP method, and whether the caller holds an admin role.
// Reads are never gated; neither are machine identities, which have nobody to
// prompt.
//
// It is deliberately not a list of sensitive admin endpoints. A list is the
// artefact that lets the next endpoint escape: a handler is added, mounted
// beside its neighbours, and inherits every gate except the one nobody
// remembered to extend. Deriving the decision from the authority the request
// already carries means a route written tomorrow is covered the day it lands.
//
// Mount it AFTER the auth, permission and tenant middleware: it needs roles,
// the session id from the sid claim, and the resolved org.

// StepUpRecorder writes one decision to the unified audit stream. It has the
// shape of access.UnifiedAuditService.RecordEvent so a service can pass that
// method directly; it is a function rather than an interface so this package
// need not import the access service, which imports this one.
type StepUpRecorder func(ctx context.Context, source, eventType, routeID, userID, actorIP string, details map[string]interface{}) error

// StepUpConfig is what the gate needs from configuration.
type StepUpConfig struct {
	// Gate is STEPUP_GATE: off | observe | enforce.
	Gate string
	// MaxAge is STEPUP_MAX_AGE, the deployment default window. The console's
	// security.reauth_interval overrides it when an operator sets one.
	MaxAge time.Duration
	// Source is the unified_audit_events.source to record under.
	Source string
}

// RequireFreshMFA builds the middleware. With the gate off it does no work and
// makes no query, so it is safe to mount unconditionally.
func RequireFreshMFA(db *database.PostgresDB, cfg StepUpConfig, rec StepUpRecorder, logger *zap.Logger) gin.HandlerFunc {
	mode := stepup.ParseMode(cfg.Gate)
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(c *gin.Context) {
		if mode == stepup.ModeOff {
			c.Next()
			return
		}
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		if !callerHoldsAdminRole(c) {
			c.Next()
			return
		}

		ctx := c.Request.Context()
		caller := stepup.Caller{
			UserID:           c.GetString("user_id"),
			OrgID:            c.GetString("org_id"),
			SessionID:        c.GetString("session_id"),
			AuthMethod:       c.GetString("auth_method"),
			ServiceAccountID: c.GetString("service_account_id"),
		}
		if org, err := orgctx.From(ctx); err == nil {
			caller.OrgID = org.ID
		}

		maxAge := stepup.MaxAge(ctx, db, cfg.MaxAge)
		decision := stepup.Gate(ctx, db, mode, maxAge, caller)
		if !decision.Required {
			c.Next()
			return
		}

		action := c.Request.Method + " " + c.FullPath()
		recordStepUp(ctx, rec, cfg.Source, caller, action, decision, c.ClientIP(), logger)

		if decision.Allowed {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":             "step_up_required",
			"error_description": "this action requires a recently verified second factor",
			"reason":            decision.Reason,
			"action":            action,
			"max_age_seconds":   int(decision.MaxAge.Seconds()),
			"challenge_url":     "/oauth/stepup-challenge",
		})
	}
}

// callerHoldsAdminRole reports whether this request carries admin authority.
// The same two role names the admin surface's own gates use.
func callerHoldsAdminRole(c *gin.Context) bool {
	rolesRaw, ok := c.Get("roles")
	if !ok {
		return false
	}
	roles, ok := rolesRaw.([]string)
	if !ok {
		return false
	}
	for _, r := range roles {
		if r == "admin" || r == "super_admin" {
			return true
		}
	}
	return false
}

// recordStepUp writes the decision on BOTH the observe and enforce branches:
// enforcement must never be quieter than report mode, or an operator who flips
// the flag loses the records that told them it was safe.
func recordStepUp(ctx context.Context, rec StepUpRecorder, source string, caller stepup.Caller, action string, d stepup.Decision, clientIP string, logger *zap.Logger) {
	enforced := !d.Allowed
	eventType := appaccess.StepUpDecisionEventType(enforced)
	if rec == nil {
		logger.Warn("step-up decision not recorded: no audit recorder wired",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", caller.UserID),
			logsafe.String("action", action),
			zap.Bool("enforced", enforced))
		return
	}
	details := appaccess.StepUpDecisionDetails(
		appaccess.EnforcementPointAdminWrite, caller.UserID, action, d.Reason,
		int(d.Age.Seconds()), int(d.MaxAge.Seconds()), enforced, nil)
	if err := rec(ctx, source, eventType, "", caller.UserID, clientIP, details); err != nil {
		logger.Warn("step-up decision not recorded: unified audit write failed",
			logsafe.String("event_type", eventType),
			logsafe.String("user_id", caller.UserID),
			logsafe.String("action", action),
			zap.Bool("enforced", enforced),
			zap.Error(err))
	}
}
