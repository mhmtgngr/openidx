// Package feature provides HTTP handlers for managing feature flags
package feature

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler provides HTTP handlers for feature flag management
type Handler struct {
	service *Service
	logger  *zap.Logger
}

// NewHandler creates a new feature flag handler
func NewHandler(service *Service, logger *zap.Logger) *Handler {
	return &Handler{
		service: service,
		logger:  logger.With(zap.String("component", "feature_flag_handler")),
	}
}

// RegisterRoutes registers all feature flag routes
func (h *Handler) RegisterRoutes(r *gin.RouterGroup) {
	features := r.Group("/features")
	{
		features.GET("", h.ListFlags)
		features.GET("/:name", h.GetFlag)
		features.POST("", h.CreateFlag)
		features.PUT("/:name", h.UpdateFlag)
		features.DELETE("/:name", h.DeleteFlag)
		features.POST("/:name/enable", h.EnableFlag)
		features.POST("/:name/disable", h.DisableFlag)
		features.GET("/metrics", h.GetMetrics)
		features.POST("/refresh", h.RefreshCache)
		features.GET("/:name/variant/:userId", h.GetUserVariant)
		features.PUT("/:name/variant/:userId", h.SetUserVariant)
		features.GET("/:name/config/:variant", h.GetVariantConfig)
	}
}

// ListFlags returns all feature flags
// @Summary List all feature flags
// @Tags features
// @Produce json
// @Success 200 {array} Flag
// @Router /api/v1/features [get]
func (h *Handler) ListFlags(c *gin.Context) {
	ctx := c.Request.Context()

	flags, err := h.service.ListFlags(ctx)
	if err != nil {
		h.logger.Error("Failed to list flags", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list feature flags"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"flags": flags,
		"count": len(flags),
	})
}

// GetFlag returns a specific feature flag
// @Summary Get a feature flag
// @Tags features
// @Param name path string true "Flag name"
// @Produce json
// @Success 200 {object} Flag
// @Failure 404 {object} map[string]string
// @Router /api/v1/features/{name} [get]
func (h *Handler) GetFlag(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Param("name")

	flag, err := h.service.GetFlagConfig(ctx, name)
	if err != nil {
		if err == ErrFlagNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Feature flag not found"})
			return
		}
		h.logger.Error("Failed to get flag", zap.String("flag", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get feature flag"})
		return
	}

	c.JSON(http.StatusOK, flag)
}

// CreateFlag creates a new feature flag
// @Summary Create a feature flag
// @Tags features
// @Accept json
// @Param request body FlagConfig true "Flag configuration"
// @Produce json
// @Success 201 {object} Flag
// @Failure 400 {object} map[string]string
// @Router /api/v1/features [post]
func (h *Handler) CreateFlag(c *gin.Context) {
	ctx := c.Request.Context()
	actor := h.getActor(c)

	var config FlagConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Use name from path if not in body
	if config.Name == "" {
		config.Name = c.Param("name")
	}

	if config.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Flag name is required"})
		return
	}

	if err := h.service.SetFlag(ctx, config.Name, &config, actor); err != nil {
		h.logger.Error("Failed to create flag", zap.String("flag", config.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create feature flag"})
		return
	}

	flag, _ := h.service.GetFlagConfig(ctx, config.Name)
	c.JSON(http.StatusCreated, flag)
}

// UpdateFlag updates an existing feature flag
// @Summary Update a feature flag
// @Tags features
// @Accept json
// @Param name path string true "Flag name"
// @Param request body FlagConfig true "Flag configuration"
// @Produce json
// @Success 200 {object} Flag
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/features/{name} [put]
func (h *Handler) UpdateFlag(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Param("name")
	actor := h.getActor(c)

	var config FlagConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config.Name = name

	if err := h.service.SetFlag(ctx, name, &config, actor); err != nil {
		h.logger.Error("Failed to update flag", zap.String("flag", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update feature flag"})
		return
	}

	flag, _ := h.service.GetFlagConfig(ctx, name)
	c.JSON(http.StatusOK, flag)
}

// DeleteFlag deletes a feature flag
// @Summary Delete a feature flag
// @Tags features
// @Param name path string true "Flag name"
// @Produce json
// @Success 204
// @Failure 404 {object} map[string]string
// @Router /api/v1/features/{name} [delete]
func (h *Handler) DeleteFlag(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Param("name")
	actor := h.getActor(c)

	if err := h.service.DeleteFlag(ctx, name, actor); err != nil {
		if err == ErrFlagNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Feature flag not found"})
			return
		}
		h.logger.Error("Failed to delete flag", zap.String("flag", name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete feature flag"})
		return
	}

	c.Status(http.StatusNoContent)
}

// EnableFlag enables a feature flag
// @Summary Enable a feature flag
// @Tags features
// @Param name path string true "Flag name"
// @Produce json
// @Success 200 {object} Flag
// @Failure 404 {object} map[string]string
// @Router /api/v1/features/{name}/enable [post]
func (h *Handler) EnableFlag(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Param("name")
	actor := h.getActor(c)

	flag, err := h.service.GetFlagConfig(ctx, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Feature flag not found"})
		return
	}

	config := &FlagConfig{
		Name:          name,
		Enabled:       true,
		Percentage:    flag.Percentage,
		UserWhitelist: flag.UserWhitelist,
		UserBlacklist: flag.UserBlacklist,
		Description:   flag.Description,
		Variant:       flag.Variant,
		Variants:      flag.Variants,
		Metadata:      flag.Metadata,
	}

	if err := h.service.SetFlag(ctx, name, config, actor); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable feature flag"})
		return
	}

	updatedFlag, _ := h.service.GetFlagConfig(ctx, name)
	c.JSON(http.StatusOK, updatedFlag)
}

// DisableFlag disables a feature flag
// @Summary Disable a feature flag
// @Tags features
// @Param name path string true "Flag name"
// @Produce json
// @Success 200 {object} Flag
// @Failure 404 {object} map[string]string
// @Router /api/v1/features/{name}/disable [post]
func (h *Handler) DisableFlag(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Param("name")
	actor := h.getActor(c)

	flag, err := h.service.GetFlagConfig(ctx, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Feature flag not found"})
		return
	}

	config := &FlagConfig{
		Name:          name,
		Enabled:       false,
		Percentage:    flag.Percentage,
		UserWhitelist: flag.UserWhitelist,
		UserBlacklist: flag.UserBlacklist,
		Description:   flag.Description,
		Variant:       flag.Variant,
		Variants:      flag.Variants,
		Metadata:      flag.Metadata,
	}

	if err := h.service.SetFlag(ctx, name, config, actor); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable feature flag"})
		return
	}

	updatedFlag, _ := h.service.GetFlagConfig(ctx, name)
	c.JSON(http.StatusOK, updatedFlag)
}

// GetMetrics returns feature flag metrics
// @Summary Get feature flag metrics
// @Tags features
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/features/metrics [get]
func (h *Handler) GetMetrics(c *gin.Context) {
	ctx := c.Request.Context()

	metrics, err := h.service.GetMetrics(ctx)
	if err != nil {
		h.logger.Error("Failed to get metrics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get metrics"})
		return
	}

	c.JSON(http.StatusOK, metrics)
}

// RefreshCache refreshes the local cache from the backing store
// @Summary Refresh feature flag cache
// @Tags features
// @Produce json
// @Success 200 {object} map[string]string
// @Router /api/v1/features/refresh [post]
func (h *Handler) RefreshCache(c *gin.Context) {
	ctx := c.Request.Context()

	if err := h.service.RefreshCache(ctx); err != nil {
		h.logger.Error("Failed to refresh cache", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh cache"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "Cache refreshed successfully",
		"refreshed_at":  time.Now().Format(time.RFC3339),
	})
}

// GetUserVariant returns the variant for a specific user
// @Summary Get user's A/B test variant
// @Tags features
// @Param name path string true "Flag name"
// @Param userId path string true "User ID"
// @Produce json
// @Success 200 {object} map[string]string
// @Router /api/v1/features/{name}/variant/{userId} [get]
func (h *Handler) GetUserVariant(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Param("name")
	userID := c.Param("userId")

	variant, err := h.service.GetVariant(ctx, name, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Feature flag not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"flag":    name,
		"user_id": userID,
		"variant": variant,
	})
}

// SetUserVariant explicitly sets a variant for a user
// @Summary Set user's A/B test variant
// @Tags features
// @Accept json
// @Param name path string true "Flag name"
// @Param userId path string true "User ID"
// @Param request body map[string]string true "Variant name"
// @Produce json
// @Success 200 {object} map[string]string
// @Router /api/v1/features/{name}/variant/{userId} [put]
func (h *Handler) SetUserVariant(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Param("name")
	userID := c.Param("userId")
	actor := h.getActor(c)

	var req struct {
		Variant string `json:"variant" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.SetUserVariant(ctx, name, userID, req.Variant, actor); err != nil {
		h.logger.Error("Failed to set user variant",
			zap.String("flag", name),
			zap.String("user_id", userID),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set user variant"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Variant set successfully",
		"flag":    name,
		"user_id": userID,
		"variant": req.Variant,
	})
}

// GetVariantConfig returns the configuration for a specific variant
// @Summary Get variant configuration
// @Tags features
// @Param name path string true "Flag name"
// @Param variant path string true "Variant name"
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/features/{name}/config/{variant} [get]
func (h *Handler) GetVariantConfig(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Param("name")
	variant := c.Param("variant")

	config, err := h.service.GetVariantConfig(ctx, name, variant)
	if err != nil {
		if err == ErrVariantNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Variant not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get variant config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"flag":    name,
		"variant": variant,
		"config":  config,
	})
}

// CheckFlag checks if a flag is enabled for the current user
// @Summary Check if flag is enabled for user
// @Tags features
// @Param name query string true "Flag name"
// @Param userId query string true "User ID"
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/features/check [get]
func (h *Handler) CheckFlag(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Query("name")
	userID := c.Query("user_id")

	if name == "" || userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and user_id are required"})
		return
	}

	enabled := h.service.IsEnabled(ctx, name, userID)

	variant, _ := h.service.GetVariant(ctx, name, userID)

	c.JSON(http.StatusOK, gin.H{
		"flag":    name,
		"user_id": userID,
		"enabled": enabled,
		"variant": variant,
	})
}

// EnablePercentage enables a flag for a percentage of users
// @Summary Set percentage rollout
// @Tags features
// @Param name path string true "Flag name"
// @Accept json
// @Param request body map[string]int true "Percentage"
// @Produce json
// @Success 200 {object} Flag
// @Router /api/v1/features/{name}/percentage [post]
func (h *Handler) EnablePercentage(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Param("name")
	actor := h.getActor(c)

	var req struct {
		Percentage int `json:"percentage" binding:"required,min=0,max=100"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	flag, err := h.service.GetFlagConfig(ctx, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Feature flag not found"})
		return
	}

	config := &FlagConfig{
		Name:          name,
		Enabled:       true,
		Percentage:    req.Percentage,
		UserWhitelist: flag.UserWhitelist,
		UserBlacklist: flag.UserBlacklist,
		Description:   flag.Description,
		Variant:       flag.Variant,
		Variants:      flag.Variants,
		Metadata:      flag.Metadata,
	}

	if err := h.service.SetFlag(ctx, name, config, actor); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update flag"})
		return
	}

	updatedFlag, _ := h.service.GetFlagConfig(ctx, name)
	c.JSON(http.StatusOK, updatedFlag)
}

// BulkUpdateFlags updates multiple flags at once
// @Summary Bulk update feature flags
// @Tags features
// @Accept json
// @Param request body map[string]FlagConfig true "Flags to update"
// @Produce json
// @Success 200 {object} map[string]string
// @Router /api/v1/features/bulk [post]
func (h *Handler) BulkUpdateFlags(c *gin.Context) {
	ctx := c.Request.Context()
	actor := h.getActor(c)

	var updates map[string]FlagConfig
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	results := make(map[string]string)
	for name, config := range updates {
		config.Name = name
		if err := h.service.SetFlag(ctx, name, &config, actor); err != nil {
			results[name] = "failed: " + err.Error()
		} else {
			results[name] = "success"
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Bulk update completed",
		"results": results,
		"total":   len(updates),
		"success": countSuccess(results),
		"failed":  countFailed(results),
	})
}

// getActor extracts the actor (user) from the request context
func (h *Handler) getActor(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	if email, exists := c.Get("email"); exists {
		if e, ok := email.(string); ok {
			return e
		}
	}
	return "unknown"
}

func countSuccess(results map[string]string) int {
	count := 0
	for _, v := range results {
		if v == "success" {
			count++
		}
	}
	return count
}

func countFailed(results map[string]string) int {
	count := 0
	for _, v := range results {
		if v != "success" {
			count++
		}
	}
	return count
}

// ListFlagsQuery returns flags with optional filtering
// @Summary List feature flags with filters
// @Tags features
// @Param enabled query bool false "Filter by enabled status"
// @Param limit query int false "Limit results" default(100)
// @Param offset query int false "Offset results" default(0)
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/features/list [get]
func (h *Handler) ListFlagsQuery(c *gin.Context) {
	ctx := c.Request.Context()

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	enabledStr := c.Query("enabled")

	flags, err := h.service.ListFlags(ctx)
	if err != nil {
		h.logger.Error("Failed to list flags", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list feature flags"})
		return
	}

	// Filter by enabled status if specified
	var filtered []*Flag
	if enabledStr != "" {
		enabled := enabledStr == "true"
		for _, flag := range flags {
			if flag.Enabled == enabled {
				filtered = append(filtered, flag)
			}
		}
	} else {
		filtered = flags
	}

	// Apply pagination
	total := len(filtered)
	if offset >= total {
		c.JSON(http.StatusOK, gin.H{
			"flags": []*Flag{},
			"count": 0,
			"total": total,
		})
		return
	}

	end := offset + limit
	if end > total {
		end = total
	}

	paginated := filtered[offset:end]

	c.JSON(http.StatusOK, gin.H{
		"flags": paginated,
		"count": len(paginated),
		"total": total,
		"offset": offset,
		"limit": limit,
	})
}

// GetFlagUsage returns usage statistics for a specific flag
// @Summary Get flag usage statistics
// @Tags features
// @Param name path string true "Flag name"
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/features/{name}/usage [get]
func (h *Handler) GetFlagUsage(c *gin.Context) {
	ctx := c.Request.Context()
	name := c.Param("name")

	flag, err := h.service.GetFlagConfig(ctx, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Feature flag not found"})
		return
	}

	// Calculate estimated user reach
	estimatedReach := 0
	if flag.Enabled {
		if flag.Percentage == 100 {
			estimatedReach = 100
		} else if len(flag.UserWhitelist) > 0 {
			estimatedReach = 100 // Whitelist means guaranteed for those users
		} else {
			estimatedReach = flag.Percentage
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"flag":             name,
		"enabled":          flag.Enabled,
		"percentage":       flag.Percentage,
		"estimated_reach":  estimatedReach,
		"whitelisted_users": len(flag.UserWhitelist),
		"blacklisted_users": len(flag.UserBlacklist),
		"has_variants":     len(flag.Variants) > 0,
		"variant_count":    len(flag.Variants),
		"created_at":       flag.CreatedAt,
		"updated_at":       flag.UpdatedAt,
		"updated_by":       flag.UpdatedBy,
	})
}
