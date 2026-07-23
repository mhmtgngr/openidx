package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// MCP gateway admin API: register/list/delete MCP servers and manage the
// per-tool allowlist. Registered under /api/v1/mcp by RegisterRoutes.

func (s *Service) handleListMCPServers(c *gin.Context) {
	servers, err := s.ListMCPServers(c.Request.Context(), mcpOrgID(c))
	if err != nil {
		s.logger.Error("list mcp servers failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if servers == nil {
		servers = []MCPServer{}
	}
	c.JSON(http.StatusOK, gin.H{"servers": servers})
}

func (s *Service) handleCreateMCPServer(c *gin.Context) {
	var in MCPServerInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	server, err := s.CreateMCPServer(c.Request.Context(), mcpOrgID(c), &in)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.logger.Info("MCP server registered", zap.String("id", server.ID), zap.String("name", server.Name))
	c.JSON(http.StatusCreated, server)
}

func (s *Service) handleDeleteMCPServer(c *gin.Context) {
	if err := s.DeleteMCPServer(c.Request.Context(), mcpOrgID(c), c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (s *Service) handleAddMCPToolPolicy(c *gin.Context) {
	var in MCPToolPolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.AddMCPToolPolicy(c.Request.Context(), mcpOrgID(c), c.Param("id"), &in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"status": "policy added"})
}
