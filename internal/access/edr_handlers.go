package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// Admin HTTP surface for EDR/MDM posture sources, under
// /api/v1/access/ziti/posture/edr. Registered by RegisterRoutes.

// requireEDROrg resolves the caller's org id, refusing the request when there is
// none.
//
// It used to return "" instead, and the store paired that with an
// OR-empty-string escape hatch on get, list and delete — so an absent
// organization meant EVERY organization. Nothing reached it, because
// TenantResolver runs in front of these routes and either attaches an
// organization or aborts, but the wildcard contradicts the FORCE RLS belt v165
// applies, under which an unscoped read returns nothing rather than everything.
func requireEDROrg(c *gin.Context) (string, bool) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil || org.ID == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return "", false
	}
	return org.ID, true
}

func (s *Service) handleListEDRSources(c *gin.Context) {
	orgID, ok := requireEDROrg(c)
	if !ok {
		return
	}
	sources, err := s.ListEDRSources(c.Request.Context(), orgID)
	if err != nil {
		s.logger.Error("list edr sources failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if sources == nil {
		sources = []EDRSource{}
	}
	c.JSON(http.StatusOK, gin.H{"sources": sources})
}

func (s *Service) handleCreateEDRSource(c *gin.Context) {
	var in EDRSourceInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	orgID, ok := requireEDROrg(c)
	if !ok {
		return
	}
	src, err := s.CreateEDRSource(c.Request.Context(), orgID, &in)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.logger.Info("EDR source created",
		zap.String("id", src.ID), zap.String("provider", src.Provider), zap.String("name", src.Name))
	c.JSON(http.StatusCreated, src)
}

func (s *Service) handleGetEDRSource(c *gin.Context) {
	orgID, ok := requireEDROrg(c)
	if !ok {
		return
	}
	src, err := s.GetEDRSource(c.Request.Context(), orgID, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}
	c.JSON(http.StatusOK, src)
}

func (s *Service) handleDeleteEDRSource(c *gin.Context) {
	orgID, ok := requireEDROrg(c)
	if !ok {
		return
	}
	if err := s.DeleteEDRSource(c.Request.Context(), orgID, c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// handleTestEDRSource verifies connectivity + credentials without side effects.
func (s *Service) handleTestEDRSource(c *gin.Context) {
	id := c.Param("id")
	orgID, ok := requireEDROrg(c)
	if !ok {
		return
	}
	if _, err := s.GetEDRSource(c.Request.Context(), orgID, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}
	conn, _, err := s.connectorForSource(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := conn.TestConnection(c.Request.Context()); err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// handleSyncEDRSource runs an ingestion pass now and returns the summary.
func (s *Service) handleSyncEDRSource(c *gin.Context) {
	id := c.Param("id")
	orgID, ok := requireEDROrg(c)
	if !ok {
		return
	}
	if _, err := s.GetEDRSource(c.Request.Context(), orgID, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}
	status, err := s.syncEDRSource(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, status)
}
