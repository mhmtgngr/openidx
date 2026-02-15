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

// handleGetUnsyncedUsers returns the list of users without Ziti identities.
// GET /api/v1/access/ziti/sync/unsynced
func (s *Service) handleGetUnsyncedUsers(c *gin.Context) {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti not configured"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT u.id, u.username, u.email, u.first_name, u.last_name
		FROM users u
		LEFT JOIN ziti_identities zi ON zi.user_id = u.id
		WHERE zi.id IS NULL AND u.enabled = true
		ORDER BY u.username
		LIMIT 50
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type UnsyncedUser struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	var users []UnsyncedUser
	for rows.Next() {
		var u UnsyncedUser
		var firstName, lastName *string
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &firstName, &lastName); err != nil {
			continue
		}
		if firstName != nil {
			u.FirstName = *firstName
		}
		if lastName != nil {
			u.LastName = *lastName
		}
		users = append(users, u)
	}
	if users == nil {
		users = []UnsyncedUser{}
	}
	c.JSON(http.StatusOK, users)
}

// handleGetMyZitiIdentity returns the current user's Ziti identity (self-service).
// GET /api/v1/access/ziti/sync/my-identity
func (s *Service) handleGetMyZitiIdentity(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		// In dev mode, try query param
		userID = c.Query("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
	}

	var zitiID, name string
	var enrolled bool
	var attrs []string
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT zi.ziti_id, zi.name, zi.enrolled, zi.attributes
		FROM ziti_identities zi
		WHERE zi.user_id = $1
	`, userID).Scan(&zitiID, &name, &enrolled, &attrs)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"linked": false})
		return
	}

	result := gin.H{
		"linked":     true,
		"ziti_id":    zitiID,
		"name":       name,
		"enrolled":   enrolled,
		"attributes": attrs,
	}

	// If not enrolled, try to get enrollment JWT
	if !enrolled {
		var enrollmentJWT *string
		_ = s.db.Pool.QueryRow(c.Request.Context(),
			"SELECT enrollment_jwt FROM ziti_identities WHERE ziti_id=$1", zitiID).Scan(&enrollmentJWT)
		if enrollmentJWT != nil && *enrollmentJWT != "" {
			result["enrollment_jwt"] = *enrollmentJWT
		} else if s.zitiManager != nil {
			jwt, jwtErr := s.zitiManager.GetIdentityEnrollmentJWT(c.Request.Context(), zitiID)
			if jwtErr == nil && jwt != "" {
				result["enrollment_jwt"] = jwt
			}
		}
	}

	c.JSON(http.StatusOK, result)
}

// handleGetUserZitiMap returns a mapping of user IDs to their Ziti identity info.
// GET /api/v1/access/ziti/sync/user-map
func (s *Service) handleGetUserZitiMap(c *gin.Context) {
	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT zi.user_id, zi.ziti_id, zi.name, zi.enrolled, zi.attributes
		FROM ziti_identities zi
		WHERE zi.user_id IS NOT NULL
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type ZitiInfo struct {
		ZitiID     string   `json:"ziti_id"`
		Name       string   `json:"name"`
		Enrolled   bool     `json:"enrolled"`
		Attributes []string `json:"attributes"`
	}
	result := make(map[string]ZitiInfo)
	for rows.Next() {
		var userID, zitiID, name string
		var enrolled bool
		var attrs []string
		if err := rows.Scan(&userID, &zitiID, &name, &enrolled, &attrs); err != nil {
			continue
		}
		if attrs == nil {
			attrs = []string{}
		}
		result[userID] = ZitiInfo{ZitiID: zitiID, Name: name, Enrolled: enrolled, Attributes: attrs}
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
