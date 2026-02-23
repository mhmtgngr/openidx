// Package audit provides HTTP handlers for tamper-evident audit logging
package audit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler provides HTTP handlers for audit operations
type Handler struct {
	store    *Store
	searcher *Searcher
	logger   *zap.Logger
}

// NewHandler creates a new audit handler
func NewHandler(store *Store, searcher *Searcher, logger *zap.Logger) *Handler {
	return &Handler{
		store:    store,
		searcher: searcher,
		logger:   logger.With(zap.String("component", "audit-handler")),
	}
}

// RegisterRoutes registers audit routes with the Gin router
func (h *Handler) RegisterRoutes(r *gin.RouterGroup) {
	// All audit routes require audit:read permission
	audit := r.Group("")
	audit.Use(RequirePermission("audit", "read"))
	{
		// Search audit events
		audit.GET("/events", h.SearchEvents)

		// Get a specific event by ID
		audit.GET("/events/:id", h.GetEvent)

		// Verify integrity of the audit chain
		audit.GET("/integrity", h.VerifyIntegrity)

		// Get statistics
		audit.GET("/statistics", h.GetStatistics)

		// Get timeline for an entity
		audit.GET("/timeline", h.GetTimeline)
	}

	// Write operations require audit:write permission
	write := r.Group("")
	write.Use(RequirePermission("audit", "write"))
	{
		// Write a single audit event
		write.POST("/events", h.WriteEvent)
	}
}

// RequirePermission is a middleware that checks for a specific permission
// This integrates with the existing middleware.RequirePermission from the codebase
func RequirePermission(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if permissions are available in context
		permissions, exists := c.Get("permissions")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "permissions not found in context",
			})
			return
		}

		// Type assert to the expected permission entry type
		permEntries, ok := permissions.([]interface{})
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "invalid permissions format",
			})
			return
		}

		// Check if the required permission exists
		for _, p := range permEntries {
			if perm, ok := p.(map[string]interface{}); ok {
				if permRes, ok := perm["resource"].(string); ok {
					if permAct, ok := perm["action"].(string); ok {
						if permRes == resource && permAct == action {
							c.Next()
							return
						}
					}
				}
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "missing permission: " + resource + ":" + action,
		})
	}
}

// SearchEvents handles GET /api/v1/audit/events
// Query params: actor, action, resource_type, outcome, from, to, after_id, limit
func (h *Handler) SearchEvents(c *gin.Context) {
	// Get tenant ID from context (set by auth middleware)
	tenantID, _ := c.Get("tenant_id")
	if tenantIDStr, ok := tenantID.(string); ok {
		// Use the tenant ID from context
		tenantID = tenantIDStr
	} else {
		tenantID = ""
	}

	// Build search query from query parameters
	query := &SearchQuery{
		ActorID:      c.Query("actor"),
		Action:       c.Query("action"),
		ResourceType: c.Query("resource_type"),
		Outcome:      c.Query("outcome"),
		TenantID:     tenantID.(string),
		CorrelationID: c.Query("correlation_id"),
		IP:           c.Query("ip"),
		AfterID:      c.Query("after_id"),
	}

	// Parse time range
	if from := c.Query("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from time format, use RFC3339"})
			return
		}
		query.From = t
	}

	if to := c.Query("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to time format, use RFC3339"})
			return
		}
		query.To = t
	}

	// Parse limit
	if limit := c.Query("limit"); limit != "" {
		l, err := strconv.Atoi(limit)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		query.Limit = l
	}

	// Validate query
	if err := query.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Execute search
	result, err := h.searcher.Search(c.Request.Context(), query)
	if err != nil {
		h.logger.Error("failed to search audit events", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to search events"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetEvent handles GET /api/v1/audit/events/:id
func (h *Handler) GetEvent(c *gin.Context) {
	eventID := c.Param("id")

	event, err := h.store.ReadByID(c.Request.Context(), eventID)
	if err != nil {
		if err.Error() == "audit event not found: "+eventID {
			c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
			return
		}
		h.logger.Error("failed to read audit event", zap.String("event_id", eventID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read event"})
		return
	}

	c.JSON(http.StatusOK, event)
}

// WriteEvent handles POST /api/v1/audit/events
func (h *Handler) WriteEvent(c *gin.Context) {
	var event AuditEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set tenant ID from context if not provided
	if event.TenantID == "" {
		if tenantID, exists := c.Get("tenant_id"); exists {
			if tenantIDStr, ok := tenantID.(string); ok {
				event.TenantID = tenantIDStr
			}
		}
	}

	// Set actor from context if not provided
	if event.ActorID == "" {
		if userID, exists := c.Get("user_id"); exists {
			if userIDStr, ok := userID.(string); ok {
				event.ActorID = userIDStr
				event.ActorType = ActorTypeUser
			}
		}
	}

	// Set request context from the HTTP request
	if event.IP == "" {
		event.IP = c.ClientIP()
	}
	if event.UserAgent == "" {
		event.UserAgent = c.GetHeader("User-Agent")
	}
	if event.CorrelationID == "" {
		event.CorrelationID = c.GetHeader("X-Request-ID")
		if event.CorrelationID == "" {
			event.CorrelationID = c.GetHeader("X-Correlation-ID")
		}
	}

	// Write event
	if err := h.store.Write(c.Request.Context(), &event); err != nil {
		h.logger.Error("failed to write audit event", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to write event"})
		return
	}

	c.JSON(http.StatusCreated, event)
}

// VerifyIntegrity handles GET /api/v1/audit/integrity
// Query params: tenant_id
func (h *Handler) VerifyIntegrity(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		// Use tenant from context
		if t, exists := c.Get("tenant_id"); exists {
			tenantID = t.(string)
		}
	}

	report, err := h.store.VerifyIntegrity(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to verify integrity", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify integrity"})
		return
	}

	c.JSON(http.StatusOK, report)
}

// GetStatistics handles GET /api/v1/audit/statistics
// Query params: from, to
func (h *Handler) GetStatistics(c *gin.Context) {
	// Get tenant ID
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		if t, exists := c.Get("tenant_id"); exists {
			tenantID = t.(string)
		}
	}

	// Parse time range (default to last 30 days)
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -30)

	if fromStr := c.Query("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from time format"})
			return
		}
		from = t
	}

	if toStr := c.Query("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to time format"})
			return
		}
		to = t
	}

	stats, err := h.searcher.GetStatistics(c.Request.Context(), tenantID, from, to)
	if err != nil {
		h.logger.Error("failed to get statistics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get statistics"})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetTimeline handles GET /api/v1/audit/timeline
// Query params: entity_type, entity_id, from, to, limit
func (h *Handler) GetTimeline(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		if t, exists := c.Get("tenant_id"); exists {
			tenantID = t.(string)
		}
	}

	entityType := c.Query("entity_type")
	entityID := c.Query("entity_id")

	if entityType == "" || entityID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entity_type and entity_id are required"})
		return
	}

	// Parse time range
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -30)

	if fromStr := c.Query("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from time format"})
			return
		}
		from = t
	}

	if toStr := c.Query("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to time format"})
			return
		}
		to = t
	}

	// Parse limit
	limit := 50
	if limitStr := c.Query("limit"); limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		limit = l
		if limit > 100 {
			limit = 100
		}
	}

	events, err := h.searcher.GetTimeline(c.Request.Context(), entityType, entityID, tenantID, from, to, limit)
	if err != nil {
		h.logger.Error("failed to get timeline", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get timeline"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"count":  len(events),
	})
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// newErrorResponse creates a new error response
func newErrorResponse(err error) ErrorResponse {
	resp := ErrorResponse{Error: err.Error()}

	// Add specific error codes for known error types
	switch {
	case IsTampered(err):
		resp.Code = "TAMPER_DETECTED"
	case IsChainBreak(err):
		resp.Code = "CHAIN_BREAK"
	}

	return resp
}

// LogUnauthorizedAccess logs unauthorized access attempts
func (h *Handler) LogUnauthorizedAccess(c *gin.Context, resource, action string) {
	// Create an audit event for the unauthorized access
	event := NewAuditEvent("access.denied").
		WithActor("", ActorTypeUser). // Actor unknown since auth failed
		WithResource(resource, "").
		WithOutcome(OutcomeDenied).
		WithRequestContext(c.ClientIP(), c.GetHeader("User-Agent"), c.GetHeader("X-Request-ID")).
		WithMetadata("attempted_action", action).
		WithMetadata("path", c.Request.URL.Path)

	// Fire and forget - don't block the response
	_ = h.store.Write(c.Request.Context(), event)
}
