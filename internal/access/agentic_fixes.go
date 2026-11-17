package access

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/diagnose"
)

// autoFix is a fix the platform may carry out on a device by itself: the
// fleet command that does it and the lowest mode that lets it. Only fixes
// that are reversible and change nothing about what the device may reach are
// listed. reenroll is deliberately absent: the fleet gates it behind a fresh
// second factor and autonomy does not get around that.
var autoFixes = map[string]struct {
	kind    string
	minMode agenticMode
}{
	diagnose.FixRestartTunnel: {"restart", modeTier0},
	diagnose.FixCollectLogs:   {"collect_logs", modeTier0},
	diagnose.FixUpdateAgent:   {"update_now", modeTier1},
}

const (
	// maxAutoFixesPerDay is how often one fix is applied to one device in 24
	// hours. A fix that did not work twice will not work a third time; the
	// ledger shows it as suppressed and a person takes over.
	maxAutoFixesPerDay = 2
	// autoFixLife is how long a queued fix may wait for the device.
	autoFixLife = 15 * time.Minute
	// ledgerQuiet stops a device that reports on every retry from filling the
	// ledger with the same line.
	ledgerQuiet = time.Hour
)

// decideFix says what to do with a fix: "applied" (queue it), "observed"
// (record only), "suppressed" (held back, with why), or "" (not the
// platform's business: autonomy is off or the fix is not an automatic one).
func decideFix(mode agenticMode, killed bool, action string, appliedToday int) (outcome, reason string) {
	fix, ok := autoFixes[action]
	if !ok || mode.rank() == 0 {
		return "", ""
	}
	switch {
	case killed:
		return "suppressed", "kill_switch"
	case mode == modeObserve:
		return "observed", "observe_mode"
	case mode.rank() < fix.minMode.rank():
		return "observed", "mode_below_fix"
	case appliedToday >= maxAutoFixesPerDay:
		return "suppressed", "anti_flap"
	}
	return "applied", ""
}

// runAutoFixes looks at a verdict the device's own report produced and, as the
// organization's mode allows, applies, records or holds back the safe fixes
// of the leading cause. It never fails the caller: autonomy is a convenience
// on top of the diagnostic, which is already stored.
func (h *AgentAPIHandler) runAutoFixes(ctx context.Context, agentID, diagnosticID string, v diagnose.Verdict) {
	if h.db == nil || h.db.Pool == nil || v.Healthy || len(v.Causes) == 0 {
		return
	}
	orgID := orgIDFrom(ctx)
	if orgID == "" {
		return
	}
	cap := ""
	if c := h.cfg(); c != nil {
		cap = c.AgenticMode
	}
	set, err := loadAgenticSettings(ctx, h.db, orgID, cap)
	if err != nil {
		h.logger.Warn("agentic: settings unreadable, observing only", zap.Error(err))
		set.Effective = modeObserve.cappedBy(cap)
	}
	cause := v.Causes[0]
	for _, f := range cause.Fixes {
		if f.Tier != diagnose.TierSafeFix {
			continue
		}
		var applied int
		if _, ok := autoFixes[f.Action]; ok {
			// If the ledger cannot be read, nothing is applied: the allowance
			// cannot be checked, so the fix is left for a person.
			if err := h.db.Pool.QueryRow(ctx, `
				SELECT count(*) FROM agentic_actions
				 WHERE org_id = $1 AND agent_id = $2 AND action = $3
				   AND outcome = 'applied' AND created_at > NOW() - INTERVAL '24 hours'`,
				orgID, agentID, f.Action).Scan(&applied); err != nil {
				h.logger.Warn("agentic: ledger unreadable, holding the fix", zap.Error(err))
				continue
			}
		}
		outcome, reason := decideFix(set.Effective, set.KillSwitch, f.Action, applied)
		if outcome == "" {
			continue
		}
		var already bool
		if err := h.db.Pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM agentic_actions
			                WHERE org_id = $1 AND agent_id = $2 AND action = $3
			                  AND outcome = $4 AND reason = $5
			                  AND created_at > NOW() - make_interval(secs => $6))`,
			orgID, agentID, f.Action, outcome, reason, ledgerQuiet.Seconds()).Scan(&already); err != nil {
			h.logger.Warn("agentic: ledger unreadable, holding the fix", zap.Error(err))
			continue
		}
		if already {
			continue
		}
		var commandID interface{}
		if outcome == "applied" {
			id, ok := h.queueAutoFix(ctx, orgID, agentID, f.Action, cause.Code)
			if !ok {
				outcome, reason = "suppressed", "queue_busy"
			} else {
				commandID = id
			}
		}
		var diag interface{}
		if diagnosticID != "" {
			diag = diagnosticID
		}
		if _, err := h.db.Pool.Exec(ctx, `
			INSERT INTO agentic_actions (org_id, agent_id, action, cause, mode, outcome, reason, command_id, diagnostic_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8::uuid, $9::uuid)`,
			orgID, agentID, f.Action, cause.Code, string(set.Effective), outcome, reason, commandID, diag); err != nil {
			h.logger.Error("agentic: could not write the ledger", zap.Error(err))
			continue
		}
		detail := "action=" + f.Action + " cause=" + cause.Code + " mode=" + string(set.Effective)
		if reason != "" {
			detail += " reason=" + reason
		}
		h.logAuditEvent("agentic.fix."+outcome, agentID, outcome, detail)
		h.logAuditEventToDB(ctx, "agentic.fix."+outcome, agentID, outcome, detail)
	}
}

// queueAutoFix queues the fleet command for a fix, unless the device already
// has one of that kind waiting or its queue is full. It reports the command
// id; false means nothing was queued.
func (h *AgentAPIHandler) queueAutoFix(ctx context.Context, orgID, agentID, action, cause string) (string, bool) {
	fix := autoFixes[action]
	var waiting int
	var same bool
	if err := h.db.Pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(bool_or(kind = $3), false) FROM agent_commands
		 WHERE org_id = $1 AND agent_id = $2 AND status IN ('queued', 'delivered')`,
		orgID, agentID, fix.kind).Scan(&waiting, &same); err != nil || same || waiting >= maxQueuedCommandsPerAgent {
		return "", false
	}
	var id string
	if err := h.db.Pool.QueryRow(ctx, `
		INSERT INTO agent_commands (org_id, agent_id, kind, args, reason, expires_at)
		VALUES ($1, $2, $3, '{}', $4, NOW() + make_interval(secs => $5))
		RETURNING id::text`,
		orgID, agentID, fix.kind, "automatic fix for "+cause, autoFixLife.Seconds()).Scan(&id); err != nil {
		h.logger.Warn("agentic: could not queue a fix", zap.Error(err))
		return "", false
	}
	return id, true
}

// expireAgenticActions removes ledger rows past their retention.
func (h *AgentAPIHandler) expireAgenticActions(ctx context.Context) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	if _, err := h.db.Pool.Exec(ctx,
		//orgscope:ignore install-wide sweep: retention is a property of each row's own expires_at
		`DELETE FROM agentic_actions WHERE expires_at < NOW()`); err != nil {
		h.logger.Debug("expire agentic actions failed", zap.Error(err))
	}
}
