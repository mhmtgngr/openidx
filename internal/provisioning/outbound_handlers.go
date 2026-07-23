package provisioning

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/scimclient"
	"go.uber.org/zap"
)

// This file exposes the admin HTTP surface for OUTBOUND SCIM provisioning:
// managing downstream SCIM target apps, testing connectivity, triggering a full
// reconcile, and inspecting per-target status. Routes are registered under
// /api/v1/provisioning/targets by RegisterOutboundRoutes.

// RegisterOutboundRoutes wires the outbound-SCIM admin endpoints onto an
// existing authenticated router group. Called from RegisterRoutes.
func (s *Service) registerOutboundRoutes(group *gin.RouterGroup) {
	t := group.Group("/targets")
	{
		t.GET("", s.handleListTargets)
		t.POST("", s.handleCreateTarget)
		t.GET("/:id", s.handleGetTarget)
		t.PUT("/:id", s.handleUpdateTarget)
		t.DELETE("/:id", s.handleDeleteTarget)
		t.POST("/:id/test", s.handleTestTarget)
		t.POST("/:id/sync", s.handleSyncTarget)
		t.GET("/:id/status", s.handleTargetStatus)
	}
}

// orgIDFromRequest resolves the caller's org id, or "" when running
// single-tenant (no org context / default org). Errors from a missing resolver
// are treated as single-tenant rather than 500 so the endpoints work in both
// deployment modes, matching the rest of the service.
func orgIDFromRequest(ctx context.Context) string {
	org, err := orgctx.From(ctx)
	if err != nil {
		return ""
	}
	return org.ID
}

func (s *Service) handleListTargets(c *gin.Context) {
	orgID := orgIDFromRequest(c.Request.Context())
	targets, err := s.ListTargetApps(c.Request.Context(), orgID)
	if err != nil {
		s.logger.Error("list scim targets failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if targets == nil {
		targets = []TargetApp{}
	}
	c.JSON(http.StatusOK, gin.H{"targets": targets})
}

func (s *Service) handleCreateTarget(c *gin.Context) {
	var in TargetAppInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	orgID := orgIDFromRequest(c.Request.Context())
	target, err := s.CreateTargetApp(c.Request.Context(), orgID, &in)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.logger.Info("outbound SCIM target created",
		zap.String("id", target.ID), zap.String("name", target.Name), zap.String("base_url", target.BaseURL))
	c.JSON(http.StatusCreated, target)
}

func (s *Service) handleGetTarget(c *gin.Context) {
	orgID := orgIDFromRequest(c.Request.Context())
	target, err := s.GetTargetApp(c.Request.Context(), orgID, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}
	c.JSON(http.StatusOK, target)
}

func (s *Service) handleUpdateTarget(c *gin.Context) {
	var in TargetAppInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	orgID := orgIDFromRequest(c.Request.Context())
	target, err := s.UpdateTargetApp(c.Request.Context(), orgID, c.Param("id"), &in)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, target)
}

func (s *Service) handleDeleteTarget(c *gin.Context) {
	orgID := orgIDFromRequest(c.Request.Context())
	if err := s.DeleteTargetApp(c.Request.Context(), orgID, c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// handleTestTarget probes the target's ServiceProviderConfig to verify the base
// URL is reachable and the credentials are accepted, without mutating anything.
func (s *Service) handleTestTarget(c *gin.Context) {
	orgID := orgIDFromRequest(c.Request.Context())
	id := c.Param("id")
	target, err := s.GetTargetApp(c.Request.Context(), orgID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}
	token, err := s.bearerTokenFor(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve credentials"})
		return
	}
	client, err := scimclient.New(scimclient.Config{BaseURL: target.BaseURL, Bearer: token})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	spc, err := client.Probe(ctx)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"patch_supported":  spc.Patch.Supported,
		"filter_supported": spc.Filter.Supported,
	})
}

// handleSyncTarget enqueues a full reconcile: a create/update op for every
// local user (and group, if the target provisions groups) so the target is
// brought into line with the current directory. The worker drains it
// asynchronously.
func (s *Service) handleSyncTarget(c *gin.Context) {
	orgID := orgIDFromRequest(c.Request.Context())
	id := c.Param("id")
	target, err := s.GetTargetApp(c.Request.Context(), orgID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}
	enqueued, err := s.EnqueueFullSync(c.Request.Context(), orgID, target)
	if err != nil {
		s.logger.Error("outbound SCIM full sync enqueue failed", zap.String("target", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue sync"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "sync enqueued", "enqueued": enqueued})
}

// handleTargetStatus reports per-target provisioning counts (records by status,
// queue depth) for the admin UI.
func (s *Service) handleTargetStatus(c *gin.Context) {
	orgID := orgIDFromRequest(c.Request.Context())
	id := c.Param("id")
	if _, err := s.GetTargetApp(c.Request.Context(), orgID, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}
	status, err := s.TargetStatus(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, status)
}
