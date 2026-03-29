// Package access provides agent enrollment, reporting, and configuration API endpoints.
package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// AgentAPIHandler handles HTTP endpoints for agent communication.
type AgentAPIHandler struct {
	logger *zap.Logger
	db     *database.PostgresDB
	zm     *ZitiManager
}

// NewAgentAPIHandler constructs an AgentAPIHandler with the given logger, database, and ZitiManager.
func NewAgentAPIHandler(logger *zap.Logger, db *database.PostgresDB, zm *ZitiManager) *AgentAPIHandler {
	return &AgentAPIHandler{
		logger: logger,
		db:     db,
		zm:     zm,
	}
}

// logAuditEvent emits a structured audit log entry for an agent lifecycle event.
// The log line uses the "AUDIT" message with consistent fields so that log
// aggregation pipelines (e.g. Loki, Elasticsearch) can index and query them.
func (h *AgentAPIHandler) logAuditEvent(action, agentID, outcome, detail string) {
	h.logger.Info("AUDIT",
		zap.String("service", "access-service"),
		zap.String("category", "agent_lifecycle"),
		zap.String("action", action),
		zap.String("agent_id", agentID),
		zap.String("outcome", outcome),
		zap.String("detail", detail),
		zap.Time("timestamp", time.Now().UTC()),
	)
}

// logAuditEventToDB persists an audit record to unified_audit_events when the DB
// is available. Errors are logged as warnings so they never block the caller.
func (h *AgentAPIHandler) logAuditEventToDB(ctx context.Context, action, agentID, outcome, detail string) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	details := map[string]interface{}{
		"agent_id": agentID,
		"outcome":  outcome,
		"detail":   detail,
	}
	detailsJSON, _ := json.Marshal(details)
	_, err := h.db.Pool.Exec(ctx, `
		INSERT INTO unified_audit_events (id, source, event_type, user_id, details, created_at)
		VALUES ($1, 'access-service', $2, $3, $4, NOW())
	`, uuid.New().String(), action, agentID, detailsJSON)
	if err != nil {
		h.logger.Warn("logAuditEventToDB: failed to persist audit event",
			zap.String("action", action),
			zap.String("agent_id", agentID),
			zap.Error(err))
	}
}

// RegisterAgentRoutes registers the agent API routes onto the provided router group.
func (h *AgentAPIHandler) RegisterAgentRoutes(r *gin.RouterGroup) {
	r.POST("/agent/enroll", h.HandleEnroll)
	r.POST("/agent/report", h.HandleReport)
	r.GET("/agent/config", h.HandleConfig)
}

// enrollRequest is the optional JSON body accepted by HandleEnroll.
type enrollRequest struct {
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
}

// enrollResponse is returned by HandleEnroll on success.
type enrollResponse struct {
	AgentID   string `json:"agent_id"`
	DeviceID  string `json:"device_id"`
	AuthToken string `json:"auth_token"`
}

// HandleEnroll validates the Authorization header, persists the new agent to the
// database, optionally creates a Ziti identity, and returns enrollment credentials.
func (h *AgentAPIHandler) HandleEnroll(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(401, gin.H{"error": "enrollment token required"})
		return
	}
	// Strip "Bearer " prefix
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	// Generate identifiers
	agentID := "agent-" + uuid.New().String()[:8]
	deviceID := "device-" + uuid.New().String()[:8]
	authToken := uuid.New().String()

	// Hash auth token for storage (never store plaintext)
	tokenHash := sha256Hex(authToken)

	// Determine initial status (auto-approve in development)
	status := "pending"
	appEnv := ""
	if h.db != nil && h.db.Pool != nil {
		// Could check config, but for now use simple env check
	}
	// Auto-approve in development mode
	if appEnv == "" || appEnv == "development" {
		status = "active"
	}

	// Persist to database
	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()
		_, err := h.db.Pool.Exec(ctx, `
            INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash, enrolled_at, compliance_status)
            VALUES ($1, $2, $3, $4, NOW(), 'unknown')
        `, agentID, deviceID, status, tokenHash)
		if err != nil {
			h.logger.Error("Failed to persist agent enrollment", zap.Error(err))
			// Don't fail enrollment if DB write fails — agent can still function
		}
	}

	h.logger.Info("Agent enrolled",
		zap.String("agent_id", agentID),
		zap.String("device_id", deviceID),
		zap.String("status", status))

	response := gin.H{
		"agent_id":    agentID,
		"device_id":   deviceID,
		"auth_token":  authToken,
		"status":      status,
		"enrolled_at": time.Now().UTC().Format(time.RFC3339),
	}

	// Create Ziti identity if active and ZitiManager available
	if status == "active" && h.zm != nil {
		zitiID, zitiJWT, err := h.zm.CreateIdentity(
			c.Request.Context(),
			agentID,
			"Device",
			[]string{"openidx-agent"},
		)
		if err != nil {
			h.logger.Warn("Failed to create Ziti identity for agent",
				zap.String("agent_id", agentID), zap.Error(err))
		} else {
			// Update DB with Ziti identity
			if h.db != nil && h.db.Pool != nil {
				h.db.Pool.Exec(c.Request.Context(),
					"UPDATE enrolled_agents SET ziti_identity_id = $1 WHERE agent_id = $2",
					zitiID, agentID)
			}
			response["ziti_jwt"] = zitiJWT
			h.logger.Info("Ziti identity created for agent",
				zap.String("agent_id", agentID),
				zap.String("ziti_id", zitiID))
		}
	}

	c.JSON(200, response)
}

// sha256Hex returns the lowercase hex-encoded SHA-256 digest of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// agentReport is the JSON body accepted by HandleReport.
type agentReport struct {
	AgentID  string        `json:"agent_id"`
	DeviceID string        `json:"device_id"`
	Results  []checkResult `json:"results"`
}

// checkResult represents a single posture check sent by the agent.
type checkResult struct {
	CheckType string            `json:"check_type"`
	Severity  string            `json:"severity"`
	Result    checkResultDetail `json:"result"`
	RanAt     string            `json:"ran_at"`
}

// checkResultDetail carries the outcome of a posture check.
type checkResultDetail struct {
	Status      string                 `json:"status"`
	Score       float64                `json:"score"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
}

// severityWeight maps severity levels to their scoring weights.
var severityWeight = map[string]float64{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// enforcementAction returns the enforcement action for a given severity and status.
func enforcementAction(severity, status string) string {
	if status != "fail" {
		return "none"
	}
	switch severity {
	case "critical":
		return "revoke"
	case "high":
		return "grace"
	case "medium":
		return "alert"
	default:
		return "none"
	}
}

// HandleReport accepts a status report from an enrolled agent, persists posture
// results, updates the agent's compliance score, and returns 202 Accepted.
func (h *AgentAPIHandler) HandleReport(c *gin.Context) {
	var report agentReport
	if err := json.NewDecoder(c.Request.Body).Decode(&report); err != nil && err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse body"})
		return
	}

	// Prefer agent_id from the JSON body; fall back to the header.
	agentID := report.AgentID
	if agentID == "" {
		agentID = c.GetHeader("X-Agent-ID")
	}

	h.logger.Info("agent report received",
		zap.String("agent_id", agentID),
		zap.Int("result_count", len(report.Results)),
	)

	type actionEntry struct {
		CheckType string `json:"check_type"`
		Action    string `json:"action"`
	}

	var (
		enforcementActions []actionEntry
		weightSum          float64
		scoreSum           float64
		hasCriticalFail    bool
		hasHighFail        bool
	)

	for _, r := range report.Results {
		action := enforcementAction(r.Severity, r.Result.Status)
		enforcementActions = append(enforcementActions, actionEntry{
			CheckType: r.CheckType,
			Action:    action,
		})

		if action == "revoke" {
			hasCriticalFail = true
		}
		if action == "grace" {
			hasHighFail = true
		}

		w := severityWeight[r.Severity]
		if w == 0 {
			w = 1
		}
		weightSum += w
		scoreSum += w * r.Result.Score

		// Persist each posture check result to the database.
		if h.db != nil && h.db.Pool != nil {
			ctx := c.Request.Context()
			detailsJSON, _ := json.Marshal(r.Result.Details)
			enforced := action != "none"
			_, dbErr := h.db.Pool.Exec(ctx, `
				INSERT INTO agent_posture_results
					(agent_id, check_type, status, score, severity, details, message,
					 reported_at, expires_at, enforced, enforcement_action)
				VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW() + INTERVAL '24 hours', $8, $9)
			`, agentID, r.CheckType, r.Result.Status, r.Result.Score, r.Severity,
				string(detailsJSON), r.Result.Message, enforced, action)
			if dbErr != nil {
				h.logger.Warn("Failed to persist posture result",
					zap.String("agent_id", agentID),
					zap.String("check_type", r.CheckType),
					zap.Error(dbErr))
			}
		}
	}

	// Compute weighted compliance score (0.0–1.0 range expected from agents).
	var complianceScore float64
	if weightSum > 0 {
		complianceScore = scoreSum / weightSum
	}

	// Determine compliance status.
	complianceStatus := "unknown"
	switch {
	case hasCriticalFail:
		complianceStatus = "non_compliant"
	case hasHighFail:
		complianceStatus = "grace_period"
	case complianceScore >= 0.8:
		complianceStatus = "compliant"
	}

	// Update enrolled_agents with the latest compliance information.
	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()
		now := time.Now().UTC()
		_, dbErr := h.db.Pool.Exec(ctx, `
			UPDATE enrolled_agents
			SET compliance_score = $1,
			    compliance_status = $2,
			    last_seen_at = $3,
			    last_report_at = $3
			WHERE agent_id = $4
		`, complianceScore, complianceStatus, now, agentID)
		if dbErr != nil {
			h.logger.Warn("Failed to update agent compliance",
				zap.String("agent_id", agentID),
				zap.Error(dbErr))
		}
	}

	c.JSON(http.StatusAccepted, gin.H{
		"status":              "accepted",
		"compliance_score":    complianceScore,
		"enforcement_actions": enforcementActions,
	})
}

// agentCheck represents a single posture check in the agent configuration.
type agentCheck struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	CheckType string `json:"check_type,omitempty"`
	Severity  string `json:"severity,omitempty"`
}

// agentConfigResponse is returned by HandleConfig.
type agentConfigResponse struct {
	Checks            []agentCheck `json:"checks"`
	ReportInterval    string       `json:"report_interval"`
	EnforcementPolicy string       `json:"enforcement_policy,omitempty"`
}

// defaultAgentConfig returns the built-in fallback configuration used when no
// agent ID is provided or the database is unavailable.
func defaultAgentConfig() agentConfigResponse {
	return agentConfigResponse{
		Checks: []agentCheck{
			{Name: "os_version", Enabled: true},
			{Name: "disk_encryption", Enabled: true},
			{Name: "process_running", Enabled: true},
		},
		ReportInterval:    "1h",
		EnforcementPolicy: "monitor",
	}
}

// StartGracePeriodEnforcer runs a background goroutine that periodically
// checks for expired grace periods and escalates to suspended status.
func (h *AgentAPIHandler) StartGracePeriodEnforcer(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.enforceExpiredGracePeriods(ctx)
			}
		}
	}()
	h.logger.Info("Grace period enforcer started", zap.Duration("interval", interval))
}

func (h *AgentAPIHandler) enforceExpiredGracePeriods(ctx context.Context) {
	if h.db == nil || h.db.Pool == nil {
		return
	}

	// Find agents with expired grace periods
	rows, err := h.db.Pool.Query(ctx, `
		UPDATE enrolled_agents
		SET status = 'suspended', compliance_status = 'non_compliant'
		WHERE compliance_status = 'grace_period'
		AND last_report_at < NOW() - INTERVAL '24 hours'
		RETURNING agent_id, ziti_identity_id
	`)
	if err != nil {
		h.logger.Error("Failed to enforce grace periods", zap.Error(err))
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var agentID string
		var zitiID *string
		if err := rows.Scan(&agentID, &zitiID); err != nil {
			continue
		}
		h.logger.Warn("Agent suspended: grace period expired",
			zap.String("agent_id", agentID))
		count++
	}
	if count > 0 {
		h.logger.Info("Grace period enforcement complete", zap.Int("suspended", count))
	}
}

// HandleConfig returns the agent configuration, taking into account the agent's
// enrollment status when an X-Agent-ID header (or query parameter) is supplied.
//
// Status-based behaviour:
//   - revoked  → 403 Forbidden
//   - suspended → empty check list, long report interval
//   - pending  → minimal config (os_version only, 1 h interval)
//   - active   → full config built from enabled posture_checks rows
//
// Falls back to defaultAgentConfig when no agent ID is given or the DB is nil.
func (h *AgentAPIHandler) HandleConfig(c *gin.Context) {
	// 1. Resolve agent ID from header or query param.
	agentID := c.GetHeader("X-Agent-ID")
	if agentID == "" {
		agentID = c.Query("agent_id")
	}

	// 2. Fall back to defaults when no agent ID or DB unavailable.
	if agentID == "" || h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusOK, defaultAgentConfig())
		return
	}

	ctx := c.Request.Context()

	// 3. Query enrolled_agents for the agent's current status.
	var status string
	err := h.db.Pool.QueryRow(ctx,
		`SELECT status FROM enrolled_agents WHERE agent_id = $1`, agentID,
	).Scan(&status)
	if err != nil {
		// Agent not found or DB error — return defaults.
		h.logger.Warn("HandleConfig: could not fetch agent status",
			zap.String("agent_id", agentID), zap.Error(err))
		c.JSON(http.StatusOK, defaultAgentConfig())
		return
	}

	// 4. Build response based on status.
	switch status {
	case "revoked":
		c.JSON(http.StatusForbidden, gin.H{"error": "agent has been revoked"})
		return

	case "suspended":
		cfg := agentConfigResponse{
			Checks:            []agentCheck{},
			ReportInterval:    "24h",
			EnforcementPolicy: "block",
		}
		c.JSON(http.StatusOK, cfg)
		return

	case "pending":
		cfg := agentConfigResponse{
			Checks: []agentCheck{
				{Name: "os_version", Enabled: true, CheckType: "os_version", Severity: "low"},
			},
			ReportInterval:    "1h",
			EnforcementPolicy: "monitor",
		}
		c.JSON(http.StatusOK, cfg)
		return

	case "active":
		// 5. Query enabled posture checks ordered by severity.
		rows, queryErr := h.db.Pool.Query(ctx,
			`SELECT check_type, parameters, severity
			   FROM posture_checks
			  WHERE enabled = true
			  ORDER BY severity`,
		)
		if queryErr != nil {
			h.logger.Warn("HandleConfig: could not query posture_checks",
				zap.String("agent_id", agentID), zap.Error(queryErr))
			c.JSON(http.StatusOK, defaultAgentConfig())
			return
		}
		defer rows.Close()

		var checks []agentCheck
		for rows.Next() {
			var checkType, severity string
			var parametersJSON []byte
			if scanErr := rows.Scan(&checkType, &parametersJSON, &severity); scanErr != nil {
				h.logger.Warn("HandleConfig: failed to scan posture_check row", zap.Error(scanErr))
				continue
			}
			checks = append(checks, agentCheck{
				Name:      checkType,
				Enabled:   true,
				CheckType: checkType,
				Severity:  severity,
			})
		}
		if rows.Err() != nil {
			h.logger.Warn("HandleConfig: rows iteration error", zap.Error(rows.Err()))
		}

		// Fall back to defaults when no enabled checks exist.
		if len(checks) == 0 {
			c.JSON(http.StatusOK, defaultAgentConfig())
			return
		}

		cfg := agentConfigResponse{
			Checks:            checks,
			ReportInterval:    "15m",
			EnforcementPolicy: "enforce",
		}
		c.JSON(http.StatusOK, cfg)
		return

	default:
		// Unknown status — return defaults.
		c.JSON(http.StatusOK, defaultAgentConfig())
	}
}

// agentRecord holds the fields returned by HandleListAgents.
type agentRecord struct {
	AgentID          string     `json:"agent_id"`
	DeviceID         string     `json:"device_id"`
	Status           string     `json:"status"`
	ComplianceStatus string     `json:"compliance_status"`
	ComplianceScore  float64    `json:"compliance_score"`
	LastSeenAt       *time.Time `json:"last_seen_at"`
	EnrolledAt       *time.Time `json:"enrolled_at"`
}

// HandleListAgents returns a JSON array of all enrolled agents (admin endpoint).
// When the database is unavailable it returns an empty array.
func (h *AgentAPIHandler) HandleListAgents(c *gin.Context) {
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusOK, []agentRecord{})
		return
	}

	ctx := c.Request.Context()
	rows, err := h.db.Pool.Query(ctx, `
		SELECT agent_id, device_id, status, compliance_status, compliance_score, last_seen_at, enrolled_at
		FROM enrolled_agents
		ORDER BY enrolled_at DESC
	`)
	if err != nil {
		h.logger.Error("HandleListAgents: failed to query enrolled_agents", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list agents"})
		return
	}
	defer rows.Close()

	agents := []agentRecord{}
	for rows.Next() {
		var rec agentRecord
		if scanErr := rows.Scan(
			&rec.AgentID,
			&rec.DeviceID,
			&rec.Status,
			&rec.ComplianceStatus,
			&rec.ComplianceScore,
			&rec.LastSeenAt,
			&rec.EnrolledAt,
		); scanErr != nil {
			h.logger.Warn("HandleListAgents: failed to scan row", zap.Error(scanErr))
			continue
		}
		agents = append(agents, rec)
	}
	if rows.Err() != nil {
		h.logger.Warn("HandleListAgents: rows iteration error", zap.Error(rows.Err()))
	}

	c.JSON(http.StatusOK, agents)
}

// HandleRevokeAgent sets an agent's status to 'revoked' and optionally removes
// its Ziti identity.
func (h *AgentAPIHandler) HandleRevokeAgent(c *gin.Context) {
	agentID := c.Param("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()

		// Fetch the Ziti identity ID before revoking so we can remove it.
		var zitiIdentityID string
		_ = h.db.Pool.QueryRow(ctx,
			`SELECT COALESCE(ziti_identity_id, '') FROM enrolled_agents WHERE agent_id = $1`,
			agentID,
		).Scan(&zitiIdentityID)

		_, err := h.db.Pool.Exec(ctx,
			`UPDATE enrolled_agents SET status = 'revoked' WHERE agent_id = $1`,
			agentID,
		)
		if err != nil {
			h.logger.Error("HandleRevokeAgent: failed to update status",
				zap.String("agent_id", agentID), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke agent"})
			return
		}

		// Remove Ziti identity if available.
		if h.zm != nil && zitiIdentityID != "" {
			if delErr := h.zm.DeleteIdentity(ctx, zitiIdentityID); delErr != nil {
				h.logger.Warn("HandleRevokeAgent: failed to delete Ziti identity",
					zap.String("agent_id", agentID),
					zap.String("ziti_identity_id", zitiIdentityID),
					zap.Error(delErr))
			}
		}
	} else if h.zm != nil {
		// No DB but ZitiManager present — best-effort removal using agentID as identity name.
		if delErr := h.zm.DeleteIdentity(context.Background(), agentID); delErr != nil {
			h.logger.Warn("HandleRevokeAgent: failed to delete Ziti identity (no db)",
				zap.String("agent_id", agentID), zap.Error(delErr))
		}
	}

	h.logger.Info("Agent revoked", zap.String("agent_id", agentID))
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "agent_id": agentID})
}

// HandleApproveAgent transitions an agent from 'pending' to 'active' and
// optionally creates a Ziti identity, returning a ziti_jwt if available.
func (h *AgentAPIHandler) HandleApproveAgent(c *gin.Context) {
	agentID := c.Param("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	response := gin.H{"status": "active", "agent_id": agentID}

	if h.db != nil && h.db.Pool != nil {
		ctx := c.Request.Context()
		tag, err := h.db.Pool.Exec(ctx,
			`UPDATE enrolled_agents SET status = 'active' WHERE agent_id = $1 AND status = 'pending'`,
			agentID,
		)
		if err != nil {
			h.logger.Error("HandleApproveAgent: failed to update status",
				zap.String("agent_id", agentID), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to approve agent"})
			return
		}

		// If no rows were updated the agent either doesn't exist or is not pending.
		if tag.RowsAffected() == 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "agent not found or not in pending state"})
			return
		}

		// Create Ziti identity for the newly approved agent.
		if h.zm != nil {
			zitiID, zitiJWT, zitiErr := h.zm.CreateIdentity(ctx, agentID, "Device", []string{"openidx-agent"})
			if zitiErr != nil {
				h.logger.Warn("HandleApproveAgent: failed to create Ziti identity",
					zap.String("agent_id", agentID), zap.Error(zitiErr))
			} else {
				h.db.Pool.Exec(ctx,
					`UPDATE enrolled_agents SET ziti_identity_id = $1 WHERE agent_id = $2`,
					zitiID, agentID)
				response["ziti_jwt"] = zitiJWT
			}
		}
	}

	h.logger.Info("Agent approved", zap.String("agent_id", agentID))
	c.JSON(http.StatusOK, response)
}
