package access

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// handleGetSyncStatus returns the current user-to-Ziti sync state.
// GET /api/v1/access/ziti/sync/status
func (s *Service) handleGetSyncStatus(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	status, err := s.zitiManager.GetSyncStatus(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, status)
}

// handleSyncAllUsers triggers a full batch sync of all unsynced users.
// POST /api/v1/access/ziti/sync/users
func (s *Service) handleSyncAllUsers(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	result, err := s.zitiManager.SyncAllUsersToZiti(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleSyncSingleUser syncs a specific user to Ziti.
// POST /api/v1/access/ziti/sync/users/:userId
func (s *Service) handleSyncSingleUser(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	userID := c.Param("userId")
	result, err := s.zitiManager.SyncUserToZiti(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleSyncAllGroups refreshes group-based role attributes for all linked identities.
// POST /api/v1/access/ziti/sync/groups
func (s *Service) handleSyncAllGroups(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	result, err := s.zitiManager.SyncAllGroupAttributes(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}
