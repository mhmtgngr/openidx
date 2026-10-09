package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The enforcement posture is the one page an administrator reads before
// switching a control from observe to enforce: which controls are open, what
// each leaves undone, and how many times in the last week it would have
// refused something. The counts come from the would_deny audit events the
// observe modes record, so "flip it" is a decision made on numbers rather
// than on hope. Production startup refuses open controls outside a declared
// window (config/enforcement.go); this is where the window's days left show.

// wouldDenyWindow is how far back the would_deny counts look.
const wouldDenyWindow = 7 * 24 * time.Hour

// EnforcementGate is one control with its weekly would-deny count.
type EnforcementGate struct {
	config.GateStatus
	WouldDeny7d int64 `json:"would_deny_7d"`
}

// EnforcementPosture is the answer to GET /admin/security-posture.
type EnforcementPosture struct {
	Environment     string            `json:"environment"`
	FullyEnforcing  bool              `json:"fully_enforcing"`
	ObserveUntil    string            `json:"observe_until,omitempty"`
	ObserveDaysLeft int               `json:"observe_days_left,omitempty"`
	WindowStatus    string            `json:"window_status,omitempty"`
	Gates           []EnforcementGate `json:"gates"`
	// EnvLines are the exact settings that would make this install fully
	// enforcing, ready to paste into the service environment.
	EnvLines []string `json:"env_lines"`
}

func (s *Service) handleSecurityPosture(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	now := time.Now()

	posture := EnforcementPosture{
		Environment:    s.config.Environment,
		FullyEnforcing: true,
		WindowStatus:   s.config.EnforcementWindowStatus(now),
	}
	if until, set, err := s.config.ObserveWindow(now); set && err == nil {
		posture.ObserveUntil = until.Format("2006-01-02")
		if now.Before(until) {
			posture.ObserveDaysLeft = int(until.Sub(now).Hours() / 24)
		}
	}
	for _, g := range s.config.ProductionGateStatuses() {
		gate := EnforcementGate{GateStatus: g}
		if !g.Enforcing {
			posture.FullyEnforcing = false
			posture.EnvLines = append(posture.EnvLines, g.Name+"="+enforceValueFor(g))
		}
		if g.ObserveAction != "" {
			gate.WouldDeny7d = s.countWouldDeny(ctx, g.ObserveAction, now.Add(-wouldDenyWindow))
		}
		posture.Gates = append(posture.Gates, gate)
	}
	c.JSON(http.StatusOK, posture)
}

// enforceValueFor is the value that closes a control: on/off controls take
// "true", tri-state ones take "enforce".
func enforceValueFor(g config.GateStatus) string {
	switch g.Name {
	case "ACCESS_ASSIGNMENT_ENFORCE", "ACCESS_API_REQUIRE_AUTH", "ADMIN_API_REQUIRE_AUTH":
		return "true"
	}
	return "enforce"
}

// countWouldDeny counts one observe action in the caller's organization since
// a point in time. A count that cannot be read is reported as 0 and logged;
// the page is still useful without it.
func (s *Service) countWouldDeny(ctx context.Context, action string, since time.Time) int64 {
	org, err := orgctx.From(ctx)
	if err != nil {
		return 0
	}
	var n int64
	err = s.db.Pool.QueryRow(ctx, `
		SELECT count(*) FROM unified_audit_events
		WHERE org_id = $1 AND event_type = $2 AND created_at >= $3`,
		org.ID, action, since).Scan(&n)
	if err != nil {
		s.logger.Warn("security posture: could not count would-deny events",
			zap.String("action", action), zap.Error(err))
		return 0
	}
	return n
}
