package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AIAgent represents an AI agent identity
type AIAgent struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	AgentType     string          `json:"agent_type"`
	OwnerID       *string         `json:"owner_id"`
	OwnerEmail    string          `json:"owner_email,omitempty"`
	Status        string          `json:"status"`
	Capabilities  json.RawMessage `json:"capabilities"`
	TrustLevel    string          `json:"trust_level"`
	RateLimits    json.RawMessage `json:"rate_limits"`
	AllowedScopes []string        `json:"allowed_scopes"`
	IPAllowlist   []string        `json:"ip_allowlist"`
	Metadata      json.RawMessage `json:"metadata"`
	LastActiveAt  *time.Time      `json:"last_active_at"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// AIAgentCredential represents authentication credentials for an agent
type AIAgentCredential struct {
	ID             string     `json:"id"`
	AgentID        string     `json:"agent_id"`
	CredentialType string     `json:"credential_type"`
	KeyPrefix      string     `json:"key_prefix"`
	Status         string     `json:"status"`
	ExpiresAt      *time.Time `json:"expires_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	RotatedAt      *time.Time `json:"rotated_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

// AIAgentPermission represents a permission grant for an agent
type AIAgentPermission struct {
	ID           string          `json:"id"`
	AgentID      string          `json:"agent_id"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *string         `json:"resource_id"`
	Actions      []string        `json:"actions"`
	Conditions   json.RawMessage `json:"conditions"`
	ExpiresAt    *time.Time      `json:"expires_at"`
	CreatedAt    time.Time       `json:"created_at"`
}

// AIAgentActivity represents an activity log entry for an agent
type AIAgentActivity struct {
	ID           string          `json:"id"`
	AgentID      string          `json:"agent_id"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Outcome      string          `json:"outcome"`
	Details      json.RawMessage `json:"details"`
	IPAddress    string          `json:"ip_address"`
	DurationMs   int             `json:"duration_ms"`
	CreatedAt    time.Time       `json:"created_at"`
}

// --- Handlers ---

func (s *Service) handleListAIAgents(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	status := c.DefaultQuery("status", "")
	agentType := c.DefaultQuery("type", "")

	query := `SELECT a.id, a.name, a.description, a.agent_type, a.owner_id,
		COALESCE(u.email, ''), a.status, a.capabilities, a.trust_level,
		a.rate_limits, a.allowed_scopes, a.ip_allowlist, a.metadata,
		a.last_active_at, a.created_at, a.updated_at
		FROM ai_agents a LEFT JOIN users u ON a.owner_id = u.id WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if status != "" {
		query += fmt.Sprintf(" AND a.status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	if agentType != "" {
		query += fmt.Sprintf(" AND a.agent_type = $%d", argIdx)
		args = append(args, agentType)
		argIdx++
	}
	query += " ORDER BY a.created_at DESC"

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		s.logger.Error("failed to list AI agents", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list agents"})
		return
	}
	defer rows.Close()

	agents := []AIAgent{}
	for rows.Next() {
		var a AIAgent
		err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.AgentType, &a.OwnerID,
			&a.OwnerEmail, &a.Status, &a.Capabilities, &a.TrustLevel,
			&a.RateLimits, &a.AllowedScopes, &a.IPAllowlist, &a.Metadata,
			&a.LastActiveAt, &a.CreatedAt, &a.UpdatedAt)
		if err != nil {
			s.logger.Error("failed to scan agent", zap.Error(err))
			continue
		}
		agents = append(agents, a)
	}

	c.JSON(http.StatusOK, gin.H{"data": agents, "total": len(agents)})
}

func (s *Service) handleCreateAIAgent(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()

	var req struct {
		Name          string          `json:"name" binding:"required"`
		Description   string          `json:"description"`
		AgentType     string          `json:"agent_type"`
		OwnerID       *string         `json:"owner_id"`
		Capabilities  json.RawMessage `json:"capabilities"`
		TrustLevel    string          `json:"trust_level"`
		RateLimits    json.RawMessage `json:"rate_limits"`
		AllowedScopes []string        `json:"allowed_scopes"`
		IPAllowlist   []string        `json:"ip_allowlist"`
		Metadata      json.RawMessage `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.AgentType == "" {
		req.AgentType = "assistant"
	}
	if req.TrustLevel == "" {
		req.TrustLevel = "low"
	}
	if req.Capabilities == nil {
		req.Capabilities = json.RawMessage(`[]`)
	}
	if req.RateLimits == nil {
		req.RateLimits = json.RawMessage(`{"requests_per_minute": 60, "requests_per_hour": 1000}`)
	}
	if req.Metadata == nil {
		req.Metadata = json.RawMessage(`{}`)
	}

	var agent AIAgent
	err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO ai_agents (name, description, agent_type, owner_id, capabilities, trust_level, rate_limits, allowed_scopes, ip_allowlist, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, name, description, agent_type, owner_id, status, capabilities, trust_level, rate_limits, allowed_scopes, ip_allowlist, metadata, last_active_at, created_at, updated_at`,
		req.Name, req.Description, req.AgentType, req.OwnerID, req.Capabilities,
		req.TrustLevel, req.RateLimits, req.AllowedScopes, req.IPAllowlist, req.Metadata,
	).Scan(&agent.ID, &agent.Name, &agent.Description, &agent.AgentType, &agent.OwnerID,
		&agent.Status, &agent.Capabilities, &agent.TrustLevel, &agent.RateLimits,
		&agent.AllowedScopes, &agent.IPAllowlist, &agent.Metadata, &agent.LastActiveAt,
		&agent.CreatedAt, &agent.UpdatedAt)
	if err != nil {
		s.logger.Error("failed to create AI agent", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create agent"})
		return
	}

	// Generate initial API key
	apiKey, keyPrefix, keyHash := generateAgentAPIKey()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO ai_agent_credentials (agent_id, credential_type, key_prefix, key_hash, expires_at)
		VALUES ($1, 'api_key', $2, $3, $4)`,
		agent.ID, keyPrefix, keyHash, time.Now().Add(365*24*time.Hour))
	if err != nil {
		s.logger.Error("failed to create agent credential", zap.Error(err))
	}

	c.JSON(http.StatusCreated, gin.H{"data": agent, "api_key": apiKey})
}

func (s *Service) handleGetAIAgent(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var agent AIAgent
	err := s.db.Pool.QueryRow(ctx, `
		SELECT a.id, a.name, a.description, a.agent_type, a.owner_id,
			COALESCE(u.email, ''), a.status, a.capabilities, a.trust_level,
			a.rate_limits, a.allowed_scopes, a.ip_allowlist, a.metadata,
			a.last_active_at, a.created_at, a.updated_at
		FROM ai_agents a LEFT JOIN users u ON a.owner_id = u.id
		WHERE a.id = $1`, id,
	).Scan(&agent.ID, &agent.Name, &agent.Description, &agent.AgentType, &agent.OwnerID,
		&agent.OwnerEmail, &agent.Status, &agent.Capabilities, &agent.TrustLevel,
		&agent.RateLimits, &agent.AllowedScopes, &agent.IPAllowlist, &agent.Metadata,
		&agent.LastActiveAt, &agent.CreatedAt, &agent.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	// Fetch credentials summary
	creds := []AIAgentCredential{}
	credRows, err := s.db.Pool.Query(ctx, `
		SELECT id, agent_id, credential_type, COALESCE(key_prefix, ''), status, expires_at, last_used_at, rotated_at, created_at
		FROM ai_agent_credentials WHERE agent_id = $1 ORDER BY created_at DESC`, id)
	if err == nil {
		defer credRows.Close()
		for credRows.Next() {
			var cr AIAgentCredential
			credRows.Scan(&cr.ID, &cr.AgentID, &cr.CredentialType, &cr.KeyPrefix, &cr.Status, &cr.ExpiresAt, &cr.LastUsedAt, &cr.RotatedAt, &cr.CreatedAt)
			creds = append(creds, cr)
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": agent, "credentials": creds})
}

func (s *Service) handleUpdateAIAgent(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var req struct {
		Name          *string          `json:"name"`
		Description   *string          `json:"description"`
		AgentType     *string          `json:"agent_type"`
		OwnerID       *string          `json:"owner_id"`
		Capabilities  *json.RawMessage `json:"capabilities"`
		TrustLevel    *string          `json:"trust_level"`
		RateLimits    *json.RawMessage `json:"rate_limits"`
		AllowedScopes *[]string        `json:"allowed_scopes"`
		IPAllowlist   *[]string        `json:"ip_allowlist"`
		Metadata      *json.RawMessage `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build dynamic update
	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description = $%d", argIdx))
		args = append(args, *req.Description)
		argIdx++
	}
	if req.AgentType != nil {
		sets = append(sets, fmt.Sprintf("agent_type = $%d", argIdx))
		args = append(args, *req.AgentType)
		argIdx++
	}
	if req.OwnerID != nil {
		sets = append(sets, fmt.Sprintf("owner_id = $%d", argIdx))
		args = append(args, *req.OwnerID)
		argIdx++
	}
	if req.Capabilities != nil {
		sets = append(sets, fmt.Sprintf("capabilities = $%d", argIdx))
		args = append(args, *req.Capabilities)
		argIdx++
	}
	if req.TrustLevel != nil {
		sets = append(sets, fmt.Sprintf("trust_level = $%d", argIdx))
		args = append(args, *req.TrustLevel)
		argIdx++
	}
	if req.RateLimits != nil {
		sets = append(sets, fmt.Sprintf("rate_limits = $%d", argIdx))
		args = append(args, *req.RateLimits)
		argIdx++
	}
	if req.AllowedScopes != nil {
		sets = append(sets, fmt.Sprintf("allowed_scopes = $%d", argIdx))
		args = append(args, *req.AllowedScopes)
		argIdx++
	}
	if req.IPAllowlist != nil {
		sets = append(sets, fmt.Sprintf("ip_allowlist = $%d", argIdx))
		args = append(args, *req.IPAllowlist)
		argIdx++
	}
	if req.Metadata != nil {
		sets = append(sets, fmt.Sprintf("metadata = $%d", argIdx))
		args = append(args, *req.Metadata)
		argIdx++
	}

	if len(sets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	sets = append(sets, "updated_at = NOW()")
	query := fmt.Sprintf("UPDATE ai_agents SET %s WHERE id = $%d RETURNING id", joinStrings(sets, ", "), argIdx)
	args = append(args, id)

	var updatedID string
	err := s.db.Pool.QueryRow(ctx, query, args...).Scan(&updatedID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "agent updated", "id": updatedID})
}

func (s *Service) handleDeleteAIAgent(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	tag, err := s.db.Pool.Exec(ctx, "DELETE FROM ai_agents WHERE id = $1", id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "agent deleted"})
}

func (s *Service) handleSuspendAIAgent(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	tag, err := s.db.Pool.Exec(ctx, "UPDATE ai_agents SET status = 'suspended', updated_at = NOW() WHERE id = $1 AND status != 'suspended'", id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found or already suspended"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "agent suspended"})
}

func (s *Service) handleActivateAIAgent(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	tag, err := s.db.Pool.Exec(ctx, "UPDATE ai_agents SET status = 'active', updated_at = NOW() WHERE id = $1 AND status = 'suspended'", id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found or not suspended"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "agent activated"})
}

func (s *Service) handleRotateAIAgentCredentials(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	// Revoke existing credentials
	_, _ = s.db.Pool.Exec(ctx, "UPDATE ai_agent_credentials SET status = 'revoked' WHERE agent_id = $1 AND status = 'active'", id)

	// Generate new key
	apiKey, keyPrefix, keyHash := generateAgentAPIKey()
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO ai_agent_credentials (agent_id, credential_type, key_prefix, key_hash, expires_at, rotated_at)
		VALUES ($1, 'api_key', $2, $3, $4, NOW())`,
		id, keyPrefix, keyHash, time.Now().Add(365*24*time.Hour))
	if err != nil {
		s.logger.Error("failed to rotate agent credentials", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rotate credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "credentials rotated", "api_key": apiKey})
}

func (s *Service) handleListAIAgentActivity(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, agent_id, action, COALESCE(resource_type, ''), COALESCE(resource_id, ''),
			outcome, details, COALESCE(ip_address, ''), COALESCE(duration_ms, 0), created_at
		FROM ai_agent_activity WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 100`, id)
	if err != nil {
		s.logger.Error("failed to list agent activity", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list activity"})
		return
	}
	defer rows.Close()

	activities := []AIAgentActivity{}
	for rows.Next() {
		var a AIAgentActivity
		rows.Scan(&a.ID, &a.AgentID, &a.Action, &a.ResourceType, &a.ResourceID,
			&a.Outcome, &a.Details, &a.IPAddress, &a.DurationMs, &a.CreatedAt)
		activities = append(activities, a)
	}

	c.JSON(http.StatusOK, gin.H{"data": activities, "total": len(activities)})
}

func (s *Service) handleListAIAgentPermissions(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, agent_id, resource_type, resource_id, actions, conditions, expires_at, created_at
		FROM ai_agent_permissions WHERE agent_id = $1 ORDER BY created_at DESC`, id)
	if err != nil {
		s.logger.Error("failed to list agent permissions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list permissions"})
		return
	}
	defer rows.Close()

	perms := []AIAgentPermission{}
	for rows.Next() {
		var p AIAgentPermission
		rows.Scan(&p.ID, &p.AgentID, &p.ResourceType, &p.ResourceID, &p.Actions, &p.Conditions, &p.ExpiresAt, &p.CreatedAt)
		perms = append(perms, p)
	}

	c.JSON(http.StatusOK, gin.H{"data": perms, "total": len(perms)})
}

func (s *Service) handleGrantAIAgentPermission(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var req struct {
		ResourceType string          `json:"resource_type" binding:"required"`
		ResourceID   *string         `json:"resource_id"`
		Actions      []string        `json:"actions" binding:"required"`
		Conditions   json.RawMessage `json:"conditions"`
		ExpiresAt    *time.Time      `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Conditions == nil {
		req.Conditions = json.RawMessage(`{}`)
	}

	var perm AIAgentPermission
	err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO ai_agent_permissions (agent_id, resource_type, resource_id, actions, conditions, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, agent_id, resource_type, resource_id, actions, conditions, expires_at, created_at`,
		id, req.ResourceType, req.ResourceID, req.Actions, req.Conditions, req.ExpiresAt,
	).Scan(&perm.ID, &perm.AgentID, &perm.ResourceType, &perm.ResourceID, &perm.Actions,
		&perm.Conditions, &perm.ExpiresAt, &perm.CreatedAt)
	if err != nil {
		s.logger.Error("failed to grant agent permission", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to grant permission"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": perm})
}

func (s *Service) handleRevokeAIAgentPermission(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	permID := c.Param("permId")

	tag, err := s.db.Pool.Exec(ctx, "DELETE FROM ai_agent_permissions WHERE id = $1", permID)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "permission not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "permission revoked"})
}

func (s *Service) handleAIAgentAnalytics(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	ctx := c.Request.Context()
	result := make(map[string]interface{})

	// Total and active agents
	var total, active, suspended int
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ai_agents").Scan(&total)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ai_agents WHERE status = 'active'").Scan(&active)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ai_agents WHERE status = 'suspended'").Scan(&suspended)
	result["total_agents"] = total
	result["active_agents"] = active
	result["suspended_agents"] = suspended

	// Agents by type
	typeRows, err := s.db.Pool.Query(ctx, "SELECT agent_type, COUNT(*) FROM ai_agents GROUP BY agent_type ORDER BY COUNT(*) DESC")
	if err == nil {
		defer typeRows.Close()
		byType := []map[string]interface{}{}
		for typeRows.Next() {
			var t string
			var cnt int
			typeRows.Scan(&t, &cnt)
			byType = append(byType, map[string]interface{}{"type": t, "count": cnt})
		}
		result["by_type"] = byType
	}

	// Top agents by activity (last 24h)
	topRows, err := s.db.Pool.Query(ctx, `
		SELECT a.id, a.name, a.agent_type, COUNT(act.id) as activity_count
		FROM ai_agents a LEFT JOIN ai_agent_activity act ON a.id = act.agent_id AND act.created_at > NOW() - INTERVAL '24 hours'
		GROUP BY a.id, a.name, a.agent_type ORDER BY activity_count DESC LIMIT 10`)
	if err == nil {
		defer topRows.Close()
		topAgents := []map[string]interface{}{}
		for topRows.Next() {
			var id, name, aType string
			var cnt int
			topRows.Scan(&id, &name, &aType, &cnt)
			topAgents = append(topAgents, map[string]interface{}{"id": id, "name": name, "type": aType, "activity_count": cnt})
		}
		result["top_agents_24h"] = topAgents
	}

	// Agents with expiring credentials (next 30 days)
	var expiringCreds int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT agent_id) FROM ai_agent_credentials
		WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < NOW() + INTERVAL '30 days'`).Scan(&expiringCreds)
	result["expiring_credentials_30d"] = expiringCreds

	// Recent failures
	var recentFailures int
	s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM ai_agent_activity
		WHERE outcome = 'failure' AND created_at > NOW() - INTERVAL '24 hours'`).Scan(&recentFailures)
	result["recent_failures_24h"] = recentFailures

	c.JSON(http.StatusOK, result)
}

// --- Helpers ---

func generateAgentAPIKey() (plainKey, prefix, hash string) {
	b := make([]byte, 32)
	rand.Read(b)
	plainKey = "oix_agent_" + hex.EncodeToString(b)
	prefix = plainKey[:16]
	h := sha256.Sum256([]byte(plainKey))
	hash = hex.EncodeToString(h[:])
	return
}

func joinStrings(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
