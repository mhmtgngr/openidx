package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// Admin HTTP surface for EDR/MDM posture sources, under
// /api/v1/access/ziti/posture/edr. Registered by RegisterRoutes.

func edrOrgID(c *gin.Context) string {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		return ""
	}
	return org.ID
}

func (s *Service) handleListEDRSources(c *gin.Context) {
	sources, err := s.ListEDRSources(c.Request.Context(), edrOrgID(c))
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
	src, err := s.CreateEDRSource(c.Request.Context(), edrOrgID(c), &in)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.logger.Info("EDR source created",
		zap.String("id", src.ID), zap.String("provider", src.Provider), zap.String("name", src.Name))
	c.JSON(http.StatusCreated, src)
}

func (s *Service) handleGetEDRSource(c *gin.Context) {
	src, err := s.GetEDRSource(c.Request.Context(), edrOrgID(c), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}
	c.JSON(http.StatusOK, src)
}

func (s *Service) handleDeleteEDRSource(c *gin.Context) {
	if err := s.DeleteEDRSource(c.Request.Context(), edrOrgID(c), c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// handleTestEDRSource verifies connectivity + credentials without side effects.
func (s *Service) handleTestEDRSource(c *gin.Context) {
	id := c.Param("id")
	if _, err := s.GetEDRSource(c.Request.Context(), edrOrgID(c), id); err != nil {
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
	if _, err := s.GetEDRSource(c.Request.Context(), edrOrgID(c), id); err != nil {
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
