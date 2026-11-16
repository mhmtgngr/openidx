package access

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// agenticMode is how far the platform may act on a device without a person.
// The words are the self-heal loop's: off does nothing, observe records what
// it would have done, tier0 applies fixes that only restart or collect, tier1
// adds fixes that change the agent's software.
type agenticMode string

const (
	modeOff     agenticMode = "off"
	modeObserve agenticMode = "observe"
	modeTier0   agenticMode = "tier0"
	modeTier1   agenticMode = "tier1"
)

func parseAgenticMode(s string) (agenticMode, bool) {
	m := agenticMode(strings.ToLower(strings.TrimSpace(s)))
	switch m {
	case modeOff, modeObserve, modeTier0, modeTier1:
		return m, true
	}
	return "", false
}

func (m agenticMode) rank() int {
	switch m {
	case modeObserve:
		return 1
	case modeTier0:
		return 2
	case modeTier1:
		return 3
	}
	return 0
}

// cappedBy returns the lower of the organization's mode and the deployment's
// cap. An empty or unknown cap does not cap.
func (m agenticMode) cappedBy(cap string) agenticMode {
	c, ok := parseAgenticMode(cap)
	if !ok || c.rank() >= m.rank() {
		return m
	}
	return c
}

// agenticSettings is one organization's autonomy setting.
type agenticSettings struct {
	// Mode is what the organization chose.
	Mode       agenticMode `json:"mode"`
	KillSwitch bool        `json:"kill_switch"`
	// Effective is Mode after the deployment's cap.
	Effective agenticMode `json:"effective_mode"`
	UpdatedAt *time.Time  `json:"updated_at,omitempty"`
}

// loadAgenticSettings reads the tenant's setting on ctx; a tenant that never
// chose gets observe with the kill switch off. A read that fails also gets
// observe: the platform records but does not act when it cannot tell.
func loadAgenticSettings(ctx context.Context, db *database.PostgresDB, orgID, cap string) (agenticSettings, error) {
	s := agenticSettings{Mode: modeObserve}
	var mode string
	var at time.Time
	err := db.Pool.QueryRow(ctx,
		`SELECT mode, kill_switch, updated_at FROM org_agentic_settings WHERE org_id = $1`,
		orgID).Scan(&mode, &s.KillSwitch, &at)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		s.Effective = modeObserve.cappedBy(cap)
		return s, err
	default:
		if m, ok := parseAgenticMode(mode); ok {
			s.Mode = m
		}
		s.UpdatedAt = &at
	}
	s.Effective = s.Mode.cappedBy(cap)
	return s, nil
}

func (s *Service) agenticCap() string {
	if s.config == nil {
		return ""
	}
	return s.config.AgenticMode
}

func (s *Service) handleGetAgenticSettings(c *gin.Context) {
	ctx := c.Request.Context()
	set, err := loadAgenticSettings(ctx, s.db, orgIDFrom(ctx), s.agenticCap())
	if err != nil {
		s.logger.Error("load agentic settings failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load the settings"})
		return
	}
	c.JSON(http.StatusOK, set)
}

// handlePutAgenticSettings changes the mode and the kill switch. Either may be
// omitted to leave it as it is. Every change is audited; the kill switch has
// its own event so "who stopped it" is one search.
func (s *Service) handlePutAgenticSettings(c *gin.Context) {
	var body struct {
		Mode       *string `json:"mode"`
		KillSwitch *bool   `json:"kill_switch"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || (body.Mode == nil && body.KillSwitch == nil) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "send mode and/or kill_switch"})
		return
	}
	ctx := c.Request.Context()
	orgID := orgIDFrom(ctx)
	cur, err := loadAgenticSettings(ctx, s.db, orgID, s.agenticCap())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load the settings"})
		return
	}
	next := cur
	if body.Mode != nil {
		m, ok := parseAgenticMode(*body.Mode)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be off, observe, tier0 or tier1"})
			return
		}
		next.Mode = m
	}
	if body.KillSwitch != nil {
		next.KillSwitch = *body.KillSwitch
	}
	var updatedBy interface{}
	actor := c.GetString("user_id")
	if _, perr := uuid.Parse(actor); perr == nil {
		updatedBy = actor
	}
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO org_agentic_settings (org_id, mode, kill_switch, updated_by, updated_at)
		VALUES ($1, $2, $3, $4::uuid, NOW())
		ON CONFLICT (org_id) DO UPDATE
		   SET mode = EXCLUDED.mode, kill_switch = EXCLUDED.kill_switch,
		       updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		orgID, string(next.Mode), next.KillSwitch, updatedBy); err != nil {
		s.logger.Error("save agentic settings failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save the settings"})
		return
	}
	if next.Mode != cur.Mode {
		s.auditAgentic(c, "agentic.settings.updated", "mode "+string(cur.Mode)+" -> "+string(next.Mode))
	}
	if next.KillSwitch != cur.KillSwitch {
		state := "off"
		if next.KillSwitch {
			state = "on"
		}
		s.auditAgentic(c, "agentic.killswitch.set", "kill switch "+state)
	}
	next.Effective = next.Mode.cappedBy(s.agenticCap())
	now := time.Now().UTC()
	next.UpdatedAt = &now
	c.JSON(http.StatusOK, next)
}

func (s *Service) auditAgentic(c *gin.Context, action, detail string) {
	s.logAuditEvent(c, action, orgIDFrom(c.Request.Context()), "organization",
		map[string]interface{}{"detail": detail})
}

// agenticActionRecord is one ledger row as the console lists it.
type agenticActionRecord struct {
	ID           string    `json:"id"`
	AgentID      string    `json:"agent_id"`
	Action       string    `json:"action"`
	Cause        string    `json:"cause"`
	Mode         string    `json:"mode"`
	Outcome      string    `json:"outcome"`
	Reason       string    `json:"reason,omitempty"`
	CommandID    string    `json:"command_id,omitempty"`
	DiagnosticID string    `json:"diagnostic_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// handleListAgenticActions lists the ledger, newest first, optionally for one
// device.
func (s *Service) handleListAgenticActions(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, agent_id, action, cause, mode, outcome, reason,
		       COALESCE(command_id::text, ''), COALESCE(diagnostic_id::text, ''), created_at
		  FROM agentic_actions
		 WHERE org_id = $1 AND ($2 = '' OR agent_id = $2)
		 ORDER BY created_at DESC, id DESC LIMIT 100`,
		orgIDFrom(ctx), c.Query("agent_id"))
	if err != nil {
		s.logger.Error("list agentic actions failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list the actions"})
		return
	}
	defer rows.Close()
	out := []agenticActionRecord{}
	for rows.Next() {
		var r agenticActionRecord
		if err := rows.Scan(&r.ID, &r.AgentID, &r.Action, &r.Cause, &r.Mode, &r.Outcome,
			&r.Reason, &r.CommandID, &r.DiagnosticID, &r.CreatedAt); err != nil {
			s.logger.Error("scan agentic action failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list the actions"})
			return
		}
		out = append(out, r)
	}
	c.JSON(http.StatusOK, gin.H{"actions": out})
}
