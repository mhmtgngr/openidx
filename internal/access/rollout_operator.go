package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/rollout"
)

// The rollout operator watches an organization's agent update and says what
// the next step is. The rules (internal/rollout) decide; this file gathers the
// evidence, keeps the proposals and, when the organization allows it, takes
// the one step that is safe to take alone: pausing a rollout that is failing.
// Widening a ring is never automatic: a person approves each step.

const (
	proposalPause   = "rollout_pause"
	proposalAdvance = "rollout_advance"
	// rolloutInterval is how often the operator looks, per organization.
	rolloutInterval = 10 * time.Minute
	// rolloutFleet is the ledger's "device" for an action on the whole fleet.
	rolloutFleet = "*"
)

// rolloutProposalRecord is one proposal as the console lists it.
type rolloutProposalRecord struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Params    json.RawMessage `json:"params"`
	Reasons   []string        `json:"reasons"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

// rolloutAssessment is GET /agent/rollout.
type rolloutAssessment struct {
	Target       string                  `json:"target"`
	TargetSource string                  `json:"target_source"` // pin | channel | ""
	Settings     agentUpdateSettings     `json:"settings"`
	Verdict      rollout.Verdict         `json:"verdict"`
	Pending      []rolloutProposalRecord `json:"pending"`
	// Mode is how far the platform may act on its own for this organization.
	Mode agenticMode `json:"mode"`
}

// settingsHash binds a proposal to the ring it was drawn from.
func settingsHash(s agentUpdateSettings) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%t|%s|%s", s.RolloutPercent, s.Paused, s.PinVersion, s.Channel)))
	return hex.EncodeToString(sum[:])
}

// rolloutInput gathers the evidence for one organization.
func (h *AgentAPIHandler) rolloutInput(ctx context.Context, orgID string) (rollout.Input, string, agentUpdateSettings, error) {
	settings := h.updateSettingsFor(ctx, orgID)
	in := rollout.Input{Now: time.Now().UTC(), Settings: rollout.Settings{Percent: settings.RolloutPercent, Paused: settings.Paused}}
	var changed *time.Time
	_ = h.db.Pool.QueryRow(ctx, `SELECT updated_at FROM org_agent_settings WHERE org_id = $1`, orgID).Scan(&changed)
	if changed != nil {
		in.Settings.ChangedAt = *changed
	}
	source := ""
	switch {
	case settings.PinVersion != "":
		in.Target, source = settings.PinVersion, "pin"
	default:
		if m, _, err := h.readMirrorManifest(settings.Channel); err == nil && m.Version != "" {
			in.Target, source = m.Version, "channel"
		}
	}

	live := fallbackLiveness
	if c := h.cfg(); c != nil && c.AgentLiveness() > 0 {
		live = c.AgentLiveness()
	}
	rows, err := h.db.Pool.Query(ctx, `
		SELECT agent_id, COALESCE(agent_version, ''), last_report_at,
		       COALESCE(update_state->>'state', ''), COALESCE(update_state->>'at', '')
		  FROM enrolled_agents WHERE org_id = $1 AND status = 'active'`, orgID)
	if err != nil {
		return in, source, settings, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, version, state, at string
		var last *time.Time
		if err := rows.Scan(&id, &version, &last, &state, &at); err != nil {
			return in, source, settings, err
		}
		d := rollout.Device{ID: id, Version: version, InRing: inRollout(id, settings.RolloutPercent),
			Live: last != nil && in.Now.Sub(*last) <= live, Update: state}
		if t, perr := time.Parse(time.RFC3339, at); perr == nil {
			d.UpdateAt = t
		}
		in.Devices = append(in.Devices, d)
	}
	return in, source, settings, rows.Err()
}

// assessRollout judges one organization's rollout.
func (h *AgentAPIHandler) assessRollout(ctx context.Context, orgID string) (rolloutAssessment, error) {
	in, source, settings, err := h.rolloutInput(ctx, orgID)
	if err != nil {
		return rolloutAssessment{}, err
	}
	a := rolloutAssessment{Target: in.Target, TargetSource: source, Settings: settings,
		Verdict: rollout.JudgeRollout(in), Pending: []rolloutProposalRecord{}}
	cap := ""
	if c := h.cfg(); c != nil {
		cap = c.AgenticMode
	}
	if set, err := loadAgenticSettings(ctx, h.db, orgID, cap); err == nil {
		a.Mode = set.Effective
	} else {
		a.Mode = modeObserve
	}
	rows, err := h.db.Pool.Query(ctx, `
		SELECT id::text, kind, params, reasons, created_at, expires_at
		  FROM agentic_proposals
		 WHERE org_id = $1 AND status = 'pending' AND expires_at > NOW()
		 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return a, err
	}
	defer rows.Close()
	for rows.Next() {
		var r rolloutProposalRecord
		var reasons []byte
		if err := rows.Scan(&r.ID, &r.Kind, &r.Params, &reasons, &r.CreatedAt, &r.ExpiresAt); err != nil {
			return a, err
		}
		_ = json.Unmarshal(reasons, &r.Reasons)
		a.Pending = append(a.Pending, r)
	}
	return a, rows.Err()
}

// HandleGetRollout is GET /agent/rollout: how the update is going and what the
// rules would do next.
func (h *AgentAPIHandler) HandleGetRollout(c *gin.Context) {
	ctx := c.Request.Context()
	orgID := orgIDFrom(ctx)
	if h.db == nil || h.db.Pool == nil || orgID == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	a, err := h.assessRollout(ctx, orgID)
	if err != nil {
		h.logger.Error("rollout assessment failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assess the rollout"})
		return
	}
	c.JSON(http.StatusOK, a)
}

func proposalKind(a rollout.Action) string {
	if a == rollout.ActionPause {
		return proposalPause
	}
	return proposalAdvance
}

// syncRolloutProposal makes the pending proposals match the verdict: one for
// the step the rules propose, none for any other. A proposal that is already
// there for the same step is left alone, so a person is not asked twice.
func (h *AgentAPIHandler) syncRolloutProposal(ctx context.Context, orgID string, a rolloutAssessment) {
	want := ""
	var params []byte
	if p := a.Verdict.Proposal; p != nil {
		want = proposalKind(p.Action)
		params, _ = json.Marshal(p)
	}
	// Anything pending that is not the wanted step is out of date.
	if _, err := h.db.Pool.Exec(ctx, `
		UPDATE agentic_proposals SET status = 'superseded', decided_at = NOW()
		 WHERE org_id = $1 AND status = 'pending' AND (kind <> $2 OR params <> $3::jsonb OR base_hash <> $4)`,
		orgID, want, nullJSON(params), settingsHash(a.Settings)); err != nil {
		h.logger.Warn("rollout: could not retire old proposals", zap.Error(err))
		return
	}
	if want == "" {
		return
	}
	reasons, _ := json.Marshal(a.Verdict.Reasons)
	if _, err := h.db.Pool.Exec(ctx, `
		INSERT INTO agentic_proposals (org_id, kind, target_type, target_id, params, reasons, base_hash)
		VALUES ($1, $2, 'org', $6::text, $3::jsonb, $4::jsonb, $5)
		ON CONFLICT (org_id, kind) WHERE status = 'pending' DO NOTHING`,
		orgID, want, string(params), string(reasons), settingsHash(a.Settings), orgID); err != nil {
		h.logger.Warn("rollout: could not record a proposal", zap.Error(err))
	}
}

// nullJSON gives a value that compares unequal to every stored params when
// there is no wanted step, so every pending proposal is retired.
func nullJSON(b []byte) string {
	if len(b) == 0 {
		return `{"none":true}`
	}
	return string(b)
}

// applyRolloutStep makes the change a proposal names, through the same write a
// person's own settings change goes through.
func (h *AgentAPIHandler) applyRolloutStep(ctx context.Context, orgID string, step rollout.Proposal, updatedBy interface{}) error {
	next := agentSettingsView{ClaimMode: h.claimModeFor(ctx, orgID), agentUpdateSettings: h.updateSettingsFor(ctx, orgID)}
	switch step.Action {
	case rollout.ActionPause:
		next.Paused = true
	case rollout.ActionAdvance:
		next.RolloutPercent = step.Percent
	default:
		return errors.New("unknown rollout step")
	}
	if msg := validUpdateSettings(next.agentUpdateSettings); msg != "" {
		return errors.New(msg)
	}
	return h.saveAgentSettings(ctx, orgID, next, updatedBy)
}

// HandleApproveRolloutProposal is POST /agent/rollout/proposals/:id/approve.
// It applies the step only if nothing has moved since it was proposed: the ring
// is the one it was drawn from and the rules still recommend the same step.
func (h *AgentAPIHandler) HandleApproveRolloutProposal(c *gin.Context) {
	ctx := c.Request.Context()
	orgID := orgIDFrom(ctx)
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil || h.db == nil || h.db.Pool == nil || orgID == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such proposal"})
		return
	}
	var kind, baseHash string
	var params []byte
	err := h.db.Pool.QueryRow(ctx, `
		SELECT kind, params, base_hash FROM agentic_proposals
		 WHERE id = $1::uuid AND org_id = $2 AND status = 'pending' AND expires_at > NOW()`, id, orgID).
		Scan(&kind, &params, &baseHash)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such proposal, or it is no longer pending"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read the proposal"})
		return
	}
	var step rollout.Proposal
	if json.Unmarshal(params, &step) != nil || proposalKind(step.Action) != kind {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "the proposal is unreadable"})
		return
	}
	stale := func(msg string) {
		//silentwrite:ok the proposal stays pending and expires by itself within hours; the caller is told the step is stale either way
		_, _ = h.db.Pool.Exec(ctx, `UPDATE agentic_proposals SET status = 'superseded', decided_at = NOW() WHERE id = $1::uuid AND org_id = $2`, id, orgID)
		c.JSON(http.StatusConflict, gin.H{"error": msg})
	}
	a, err := h.assessRollout(ctx, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assess the rollout"})
		return
	}
	if settingsHash(a.Settings) != baseHash {
		stale("the update settings changed since this was proposed")
		return
	}
	if p := a.Verdict.Proposal; p == nil || *p != step {
		stale("the rollout no longer calls for this step")
		return
	}
	var updatedBy interface{}
	if u := c.GetString("user_id"); u != "" {
		if _, perr := uuid.Parse(u); perr == nil {
			updatedBy = u
		}
	}
	if err := h.applyRolloutStep(ctx, orgID, step, updatedBy); err != nil {
		h.logger.Error("rollout: applying an approved step failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to apply the step"})
		return
	}
	if _, err := h.db.Pool.Exec(ctx, `
		UPDATE agentic_proposals SET status = 'applied', decided_by = $3::uuid, decided_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2`, id, orgID, updatedBy); err != nil {
		h.logger.Warn("rollout: could not close an applied proposal", zap.Error(err))
	}
	detail := fmt.Sprintf("kind=%s percent=%d proposal=%s", kind, step.Percent, id)
	h.logAuditEvent("agentic.proposal.approved", "", "success", detail)
	h.logAuditEventToDB(ctx, "agentic.proposal.approved", "", "success", detail)
	c.JSON(http.StatusOK, gin.H{"applied": step})
}

// HandleRejectRolloutProposal is POST /agent/rollout/proposals/:id/reject.
func (h *AgentAPIHandler) HandleRejectRolloutProposal(c *gin.Context) {
	ctx := c.Request.Context()
	orgID := orgIDFrom(ctx)
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil || h.db == nil || h.db.Pool == nil || orgID == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such proposal"})
		return
	}
	var decidedBy interface{}
	if u := c.GetString("user_id"); u != "" {
		if _, perr := uuid.Parse(u); perr == nil {
			decidedBy = u
		}
	}
	tag, err := h.db.Pool.Exec(ctx, `
		UPDATE agentic_proposals SET status = 'rejected', decided_by = $3::uuid, decided_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND status = 'pending'`, id, orgID, decidedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reject the proposal"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such proposal, or it is no longer pending"})
		return
	}
	h.logAuditEvent("agentic.proposal.rejected", "", "success", "proposal="+id)
	h.logAuditEventToDB(ctx, "agentic.proposal.rejected", "", "success", "proposal="+id)
	c.JSON(http.StatusOK, gin.H{"rejected": id})
}

// decideRolloutPause says what to do with a pause the rules call for: take it
// ("applied"), only record it ("observed"), or hold it back ("suppressed").
// "" means the platform has nothing to do (automation is off).
func decideRolloutPause(mode agenticMode, killed bool, appliedToday int) (outcome, reason string) {
	switch {
	case mode.rank() == 0:
		return "", ""
	case killed:
		return "suppressed", "kill_switch"
	case mode == modeObserve:
		return "observed", "observe_mode"
	case appliedToday >= 1:
		return "suppressed", "anti_flap"
	}
	return "applied", ""
}

// runRolloutOperator is one pass over one organization.
func (h *AgentAPIHandler) runRolloutOperator(ctx context.Context, orgID string) {
	cap := ""
	if c := h.cfg(); c != nil {
		cap = c.AgenticMode
	}
	set, err := loadAgenticSettings(ctx, h.db, orgID, cap)
	if err != nil || set.Effective.rank() == 0 {
		return
	}
	a, err := h.assessRollout(ctx, orgID)
	if err != nil {
		h.logger.Warn("rollout operator: assessment failed", zap.Error(err))
		return
	}
	if p := a.Verdict.Proposal; p != nil && p.Action == rollout.ActionPause {
		var appliedToday int
		if err := h.db.Pool.QueryRow(ctx, `
			SELECT count(*) FROM agentic_actions
			 WHERE org_id = $1 AND agent_id = $2 AND action = 'rollout_pause'
			   AND outcome = 'applied' AND created_at > NOW() - INTERVAL '24 hours'`,
			orgID, rolloutFleet).Scan(&appliedToday); err != nil {
			h.logger.Warn("rollout operator: ledger unreadable, holding the pause", zap.Error(err))
			return
		}
		outcome, reason := decideRolloutPause(set.Effective, set.KillSwitch, appliedToday)
		if outcome == "applied" {
			if err := h.applyRolloutStep(ctx, orgID, *p, nil); err != nil {
				h.logger.Error("rollout operator: pause failed", zap.Error(err))
				return
			}
			// What was proposed has been done.
			a.Settings.Paused = true
			a.Verdict.Proposal = nil
		}
		h.recordRolloutAction(ctx, orgID, set, outcome, reason)
	}
	h.syncRolloutProposal(ctx, orgID, a)
}

// recordRolloutAction writes the ledger row and the audit event for an
// automatic rollout step, once an hour at most for the same outcome.
func (h *AgentAPIHandler) recordRolloutAction(ctx context.Context, orgID string, set agenticSettings, outcome, reason string) {
	if outcome == "" {
		return
	}
	var already bool
	if err := h.db.Pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM agentic_actions
		                WHERE org_id = $1 AND agent_id = $2 AND action = 'rollout_pause'
		                  AND outcome = $3 AND reason = $4 AND created_at > NOW() - INTERVAL '1 hour')`,
		orgID, rolloutFleet, outcome, reason).Scan(&already); err != nil || already {
		return
	}
	if _, err := h.db.Pool.Exec(ctx, `
		INSERT INTO agentic_actions (org_id, agent_id, action, cause, mode, outcome, reason)
		VALUES ($1, $2, 'rollout_pause', $3, $4, $5, $6)`,
		orgID, rolloutFleet, rollout.ReasonFailures, string(set.Effective), outcome, reason); err != nil {
		h.logger.Error("rollout operator: could not write the ledger", zap.Error(err))
		return
	}
	detail := "action=rollout_pause cause=" + rollout.ReasonFailures + " mode=" + string(set.Effective)
	if reason != "" {
		detail += " reason=" + reason
	}
	h.logAuditEvent("agentic.fix."+outcome, rolloutFleet, outcome, detail)
	h.logAuditEventToDB(ctx, "agentic.fix."+outcome, rolloutFleet, outcome, detail)
}

// runRolloutOperatorAll visits every organization that has an active device.
func (h *AgentAPIHandler) runRolloutOperatorAll(ctx context.Context) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	bypass := orgctx.WithBypassRLS(ctx)
	//orgscope:ignore install-wide: the operator visits every organization that has an active device, then works inside each one's own context
	rows, err := h.db.Pool.Query(bypass, `SELECT DISTINCT org_id::text FROM enrolled_agents WHERE status = 'active'`)
	if err != nil {
		h.logger.Warn("rollout operator: could not list organizations", zap.Error(err))
		return
	}
	var orgs []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			orgs = append(orgs, id)
		}
	}
	rows.Close()
	for _, id := range orgs {
		h.runRolloutOperator(orgctx.With(ctx, orgctx.Org{ID: id}), id)
	}
	// Proposals nobody decided in time, and old decided ones.
	//silentwrite:ok an undecided proposal that is not marked expired is still ignored (every read checks expires_at) and is marked on the next pass
	_, _ = h.db.Pool.Exec(bypass,
		//orgscope:ignore install-wide sweep: retention is a property of each row's own expires_at
		`UPDATE agentic_proposals SET status = 'expired' WHERE status = 'pending' AND expires_at < NOW()`)
	//silentwrite:ok old decided proposals are only history; a failed delete leaves them for the next pass
	_, _ = h.db.Pool.Exec(bypass,
		//orgscope:ignore install-wide sweep: decided proposals are kept thirty days
		`DELETE FROM agentic_proposals WHERE status <> 'pending' AND COALESCE(decided_at, expires_at) < NOW() - INTERVAL '30 days'`)
}

// StartRolloutOperator runs the operator every interval on one replica
// (leader.RunPeriodic over the handler's Redis; none means a single instance,
// which runs it). It returns at once; the loop ends with ctx.
func (h *AgentAPIHandler) StartRolloutOperator(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = rolloutInterval
	}
	h.logger.Info("rollout operator started", zap.Duration("interval", interval))
	go leader.RunPeriodic(ctx, h.redis, h.logger, "access:rollout-operator", interval, h.runRolloutOperatorAll)
}
