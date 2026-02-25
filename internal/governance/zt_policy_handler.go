// Package governance provides HTTP handlers for Zero Trust policy management
package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// rateLimitEntry tracks rate limit state per client
type rateLimitEntry struct {
	count     int64
	resetTime time.Time
}

// rateLimitStore tracks in-memory rate limits
var rateLimitStore = struct {
	sync.RWMutex
	entries map[string]*rateLimitEntry
}{
	entries: make(map[string]*rateLimitEntry),
}

// ZTPolicyHandler handles HTTP requests for policy management
type ZTPolicyHandler struct {
	store     *ZTPolicyStore
	eval      *ZTPolicyEvaluator
	logger    *zap.Logger
}

// NewZTPolicyHandler creates a new policy handler
func NewZTPolicyHandler(store *ZTPolicyStore, logger *zap.Logger) *ZTPolicyHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ZTPolicyHandler{
		store:  store,
		eval:   NewZTPolicyEvaluator(),
		logger: logger.With(zap.String("handler", "zt_policy")),
	}
}

// RegisterRoutes registers all policy routes
func (h *ZTPolicyHandler) RegisterRoutes(r gin.IRouter) {
	policies := r.Group("/api/v1/policies")
	{
		policies.POST("", h.CreatePolicy)
		policies.GET("", h.ListPolicies)
		policies.GET("/count", h.CountPolicies)
		policies.GET("/:id", h.GetPolicy)
		policies.PUT("/:id", h.UpdatePolicy)
		policies.DELETE("/:id", h.DeletePolicy)
		policies.PATCH("/:id/enable", h.SetPolicyEnabled)
		policies.POST("/evaluate", h.EvaluatePolicies)
		policies.GET("/:id/versions", h.GetPolicyHistory)
		policies.GET("/:id/versions/:version", h.GetPolicyVersion)
	}
}

// CreatePolicyRequest represents the request to create a policy
type CreatePolicyRequest struct {
	Name        string         `json:"name" binding:"required"`
	Description string         `json:"description"`
	Effect      PolicyEffect   `json:"effect" binding:"required,oneof=allow deny"`
	Conditions  ConditionGroup `json:"conditions" binding:"required"`
	Priority    int            `json:"priority"`
	TenantID    string         `json:"tenant_id"`
	Metadata    json.RawMessage `json:"metadata"`
}

// UpdatePolicyRequest represents the request to update a policy
type UpdatePolicyRequest struct {
	Name        *string        `json:"name"`
	Description *string        `json:"description"`
	Effect      *PolicyEffect  `json:"effect" binding:"omitempty,oneof=allow deny"`
	Conditions  *ConditionGroup `json:"conditions"`
	Priority    *int           `json:"priority"`
	Enabled     *bool          `json:"enabled"`
	TenantID    *string        `json:"tenant_id"`
	Metadata    json.RawMessage `json:"metadata"`
}

// EvaluateRequest represents the request to evaluate policies
type EvaluateRequest struct {
	Subject  Subject         `json:"subject" binding:"required"`
	Resource Resource        `json:"resource" binding:"required"`
	Action   string          `json:"action" binding:"required"`
	Context  EvaluationContext `json:"context"`
}

// CreatePolicy handles POST /api/v1/policies
func (h *ZTPolicyHandler) CreatePolicy(c *gin.Context) {
	var req CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		userID = "system"
	}

	policy := ZTPolicy{
		Name:        req.Name,
		Description: req.Description,
		Effect:      req.Effect,
		Conditions:  req.Conditions,
		Priority:    req.Priority,
		TenantID:    req.TenantID,
		Metadata:    req.Metadata,
		Enabled:     true,
	}

	created, err := h.store.Create(c.Request.Context(), policy, userID.(string))
	if err != nil {
		h.logger.Error("Failed to create policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create policy"})
		return
	}

	// Reload evaluator
	h.reloadEvaluator(c)

	c.JSON(http.StatusCreated, created)
}

// ListPolicies handles GET /api/v1/policies
func (h *ZTPolicyHandler) ListPolicies(c *gin.Context) {
	filter := &PolicyFilter{}

	if tenantID := c.Query("tenant_id"); tenantID != "" {
		filter.TenantID = tenantID
	}

	if enabledStr := c.Query("enabled"); enabledStr != "" {
		enabled := enabledStr == "true"
		filter.Enabled = &enabled
	}

	if effect := c.Query("effect"); effect != "" {
		filter.Effect = effect
	}

	policies, err := h.store.List(c.Request.Context(), filter)
	if err != nil {
		h.logger.Error("Failed to list policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"policies": policies,
		"count":    len(policies),
	})
}

// CountPolicies handles GET /api/v1/policies/count
func (h *ZTPolicyHandler) CountPolicies(c *gin.Context) {
	filter := &PolicyFilter{}

	if tenantID := c.Query("tenant_id"); tenantID != "" {
		filter.TenantID = tenantID
	}

	if enabledStr := c.Query("enabled"); enabledStr != "" {
		enabled := enabledStr == "true"
		filter.Enabled = &enabled
	}

	if effect := c.Query("effect"); effect != "" {
		filter.Effect = effect
	}

	count, err := h.store.Count(c.Request.Context(), filter)
	if err != nil {
		h.logger.Error("Failed to count policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"count": count})
}

// GetPolicy handles GET /api/v1/policies/:id
func (h *ZTPolicyHandler) GetPolicy(c *gin.Context) {
	id := c.Param("id")

	policy, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		if err.Error() == "policy not found: "+id {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("Failed to get policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get policy"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// UpdatePolicy handles PUT /api/v1/policies/:id
func (h *ZTPolicyHandler) UpdatePolicy(c *gin.Context) {
	id := c.Param("id")

	var req UpdatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing policy
	current, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		if err.Error() == "policy not found: "+id {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("Failed to get policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get policy"})
		return
	}

	// Update fields from request
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.Description != nil {
		current.Description = *req.Description
	}
	if req.Effect != nil {
		current.Effect = *req.Effect
	}
	if req.Conditions != nil {
		current.Conditions = *req.Conditions
	}
	if req.Priority != nil {
		current.Priority = *req.Priority
	}
	if req.Enabled != nil {
		current.Enabled = *req.Enabled
	}
	if req.TenantID != nil {
		current.TenantID = *req.TenantID
	}
	if req.Metadata != nil {
		current.Metadata = req.Metadata
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		userID = "system"
	}

	updated, err := h.store.Update(c.Request.Context(), *current, userID.(string))
	if err != nil {
		h.logger.Error("Failed to update policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update policy"})
		return
	}

	// Reload evaluator
	h.reloadEvaluator(c)

	c.JSON(http.StatusOK, updated)
}

// DeletePolicy handles DELETE /api/v1/policies/:id
func (h *ZTPolicyHandler) DeletePolicy(c *gin.Context) {
	id := c.Param("id")

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		userID = "system"
	}

	if err := h.store.Delete(c.Request.Context(), id, userID.(string)); err != nil {
		if err.Error() == "policy not found: "+id {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("Failed to delete policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete policy"})
		return
	}

	// Reload evaluator
	h.reloadEvaluator(c)

	c.JSON(http.StatusOK, gin.H{"message": "policy deleted"})
}

// SetPolicyEnabled handles PATCH /api/v1/policies/:id/enable
func (h *ZTPolicyHandler) SetPolicyEnabled(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		userID = "system"
	}

	if err := h.store.SetEnabled(c.Request.Context(), id, req.Enabled, userID.(string)); err != nil {
		if err.Error() == "policy not found: "+id {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("Failed to set policy enabled", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update policy"})
		return
	}

	// Reload evaluator
	h.reloadEvaluator(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "policy updated",
		"enabled": req.Enabled,
	})
}

// EvaluatePolicies handles POST /api/v1/policies/evaluate
// CRITICAL: Rate limiting is applied to prevent DoS attacks on policy evaluation
func (h *ZTPolicyHandler) EvaluatePolicies(c *gin.Context) {
	// Apply a basic per-IP rate limit for policy evaluation
	// This prevents DoS while allowing legitimate high-volume evaluation
	clientIP := c.ClientIP()
	const maxRequestsPerMinute = 100
	const windowDuration = time.Minute

	now := time.Now()
	rateLimitKey := fmt.Sprintf("policy_eval:%s", clientIP)

	// Check rate limit
	rateLimitStore.RLock()
	entry, exists := rateLimitStore.entries[rateLimitKey]
	rateLimitStore.RUnlock()

	if !exists || now.After(entry.resetTime) {
		// Create new entry or expired entry
		rateLimitStore.Lock()
		rateLimitStore.entries[rateLimitKey] = &rateLimitEntry{
			count:     1,
			resetTime: now.Add(windowDuration),
		}
		rateLimitStore.Unlock()
	} else {
		// Increment counter
		rateLimitStore.Lock()
		entry.count++
		count := entry.count
		rateLimitStore.Unlock()

		if count > maxRequestsPerMinute {
			h.logger.Warn("Policy evaluation rate limit exceeded",
				zap.String("client_ip", clientIP),
				zap.Int64("count", count))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded, please retry later",
			})
			return
		}
	}

	var req EvaluateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set default time if not provided
	if req.Context.Time.IsZero() {
		req.Context.Time = time.Now()
	}

	// Reload evaluator to ensure we have latest policies
	if err := h.reloadEvaluator(c); err != nil {
		h.logger.Error("Failed to reload evaluator", zap.Error(err))
		// Continue with cached policies
	}

	input := ZTPolicyInput{
		Subject:  req.Subject,
		Resource: req.Resource,
		Action:   req.Action,
		Context:  req.Context,
	}

	result := h.eval.Evaluate(input)

	// Log evaluation
	h.logger.Info("Policy evaluation",
		zap.String("subject", input.Subject.ID),
		zap.String("resource", input.Resource.ID),
		zap.String("action", input.Action),
		zap.Bool("allowed", result.Allowed),
		zap.Duration("duration", result.Duration),
	)

	c.JSON(http.StatusOK, result)
}

// GetPolicyHistory handles GET /api/v1/policies/:id/versions
func (h *ZTPolicyHandler) GetPolicyHistory(c *gin.Context) {
	id := c.Param("id")

	history, err := h.store.GetHistory(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get policy history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get policy history"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"policy_id": id,
		"versions":  history,
		"count":     len(history),
	})
}

// GetPolicyVersion handles GET /api/v1/policies/:id/versions/:version
func (h *ZTPolicyHandler) GetPolicyVersion(c *gin.Context) {
	id := c.Param("id")
	versionStr := c.Param("version")

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid version number"})
		return
	}

	policy, err := h.store.GetByVersion(c.Request.Context(), id, version)
	if err != nil {
		if err.Error() == "policy version not found: "+id+"@"+strconv.Itoa(version) {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy version not found"})
			return
		}
		h.logger.Error("Failed to get policy version", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get policy version"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// reloadEvaluator reloads the policy evaluator with latest policies
func (h *ZTPolicyHandler) reloadEvaluator(c *gin.Context) error {
	eval, err := h.store.LoadAllEvaluator(c.Request.Context())
	if err != nil {
		return err
	}
	h.eval = eval
	return nil
}

// GetEvaluator returns the current policy evaluator
// Useful for direct evaluation from other services
func (h *ZTPolicyHandler) GetEvaluator() *ZTPolicyEvaluator {
	return h.eval
}

// RefreshEvaluator manually refreshes the evaluator from the database
func (h *ZTPolicyHandler) RefreshEvaluator(ctx context.Context) error {
	eval, err := h.store.LoadAllEvaluator(ctx)
	if err != nil {
		return err
	}
	h.eval = eval
	return nil
}

// Middleware that can be used to protect routes with Zero Trust policies
// This middleware evaluates policies and denies access if not allowed
func (h *ZTPolicyHandler) PolicyMiddleware(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract subject from context (set by auth middleware)
		subject := Subject{
			ID:       "anonymous",
			Type:     "user",
			Roles:    []string{},
			Groups:   []string{},
			Authenticated: false,
		}

		if userID, exists := c.Get("user_id"); exists {
			subject.ID = userID.(string)
			subject.Authenticated = true
		}

		if roles, exists := c.Get("roles"); exists {
			if r, ok := roles.([]string); ok {
				subject.Roles = r
			}
		}

		if groups, exists := c.Get("groups"); exists {
			if g, ok := groups.([]string); ok {
				subject.Groups = g
			}
		}

		// Extract resource info from path
		resource := Resource{
			Type: c.Request.URL.Path,
			ID:   c.Param("id"),
		}

		// Build context
		ctx := EvaluationContext{
			IPAddress: c.ClientIP(),
			UserAgent: c.GetHeader("User-Agent"),
			Time:      time.Now(),
		}

		input := ZTPolicyInput{
			Subject:  subject,
			Resource: resource,
			Action:   action,
			Context:  ctx,
		}

		result := h.eval.Evaluate(input)
		if !result.Allowed {
			h.logger.Warn("Access denied by policy",
				zap.String("subject", subject.ID),
				zap.String("action", action),
				zap.String("reason", result.Reason),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"error":  "access denied",
				"reason": result.Reason,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ValidatePolicy validates a policy without saving it
func (h *ZTPolicyHandler) ValidatePolicy(c *gin.Context) {
	var req CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate conditions
	if err := h.validateConditionGroup(req.Conditions); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid conditions",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": true})
}

// validateConditionGroup recursively validates a condition group
func (h *ZTPolicyHandler) validateConditionGroup(group ConditionGroup) error {
	validOperators := map[LogicalOperator]bool{
		OpAnd: true,
		OpOr:  true,
		OpNot: true,
	}

	if !validOperators[group.Operator] {
		return fmt.Errorf("invalid operator: %s", group.Operator)
	}

	// Validate conditions
	for _, cond := range group.Conditions {
		if err := h.validateCondition(cond); err != nil {
			return err
		}
	}

	// Validate nested groups
	for _, nested := range group.Groups {
		if err := h.validateConditionGroup(nested); err != nil {
			return err
		}
	}

	return nil
}

// validateCondition validates a single condition
func (h *ZTPolicyHandler) validateCondition(cond Condition) error {
	validOperators := map[string]bool{
		OpEquals:        true,
		OpNotEquals:     true,
		OpContains:      true,
		OpNotContains:   true,
		OpStartsWith:    true,
		OpEndsWith:      true,
		OpIn:            true,
		OpNotIn:         true,
		OpGreaterThan:   true,
		OpLessThan:      true,
		OpRegex:         true,
		OpIPInRange:     true,
		OpTimeInRange:   true,
		OpDayOfWeek:     true,
		OpHasRole:       true,
		OpHasGroup:      true,
		OpHasAttribute:  true,
		OpDeviceTrusted: true,
		OpLocationMatch: true,
	}

	if !validOperators[cond.Operator] {
		return fmt.Errorf("invalid condition operator: %s", cond.Operator)
	}

	if cond.Field == "" {
		return fmt.Errorf("field is required")
	}

	return nil
}
