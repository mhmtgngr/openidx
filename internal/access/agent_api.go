// Package access provides agent enrollment, reporting, and configuration API endpoints.
package access

import (
	"io"
	"net/http"

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

// HandleEnroll validates the Authorization header and returns a new set of
// identifiers for the enrolling agent.
func (h *AgentAPIHandler) HandleEnroll(c *gin.Context) {
	if c.GetHeader("Authorization") == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
		return
	}

	resp := enrollResponse{
		AgentID:   uuid.New().String(),
		DeviceID:  uuid.New().String(),
		AuthToken: uuid.New().String(),
	}

	h.logger.Info("agent enrolled",
		zap.String("agent_id", resp.AgentID),
		zap.String("device_id", resp.DeviceID),
	)

	c.JSON(http.StatusOK, resp)
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
