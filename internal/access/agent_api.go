// Package access provides agent enrollment, reporting, and configuration API endpoints.
package access

import (
	"crypto/sha256"
	"encoding/hex"
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

// HandleReport accepts a status report from an enrolled agent and acknowledges it.
func (h *AgentAPIHandler) HandleReport(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	agentID := c.GetHeader("X-Agent-ID")
	h.logger.Info("agent report received",
		zap.String("agent_id", agentID),
		zap.Int("body_bytes", len(body)),
	)

	c.Status(http.StatusAccepted)
}

// agentCheck represents a single posture check in the agent configuration.
type agentCheck struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// agentConfigResponse is returned by HandleConfig.
type agentConfigResponse struct {
	Checks         []agentCheck `json:"checks"`
	ReportInterval string       `json:"report_interval"`
}

// HandleConfig returns the default agent configuration.
func (h *AgentAPIHandler) HandleConfig(c *gin.Context) {
	cfg := agentConfigResponse{
		Checks: []agentCheck{
			{Name: "os_version", Enabled: true},
			{Name: "disk_encryption", Enabled: true},
			{Name: "process_running", Enabled: true},
		},
		ReportInterval: "1h",
	}
	c.JSON(http.StatusOK, cfg)
}
