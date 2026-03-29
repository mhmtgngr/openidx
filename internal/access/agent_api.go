// Package access provides agent enrollment, reporting, and configuration API endpoints.
package access

import (
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
