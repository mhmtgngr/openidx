package access

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// Ziti Session Visibility handlers
// ---------------------------------------------------------------------------

func (s *Service) handleListZitiSessions(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	path := "/edge/management/v1/sessions?limit=200"
	if sessionType := c.Query("type"); sessionType != "" {
		path += "&filter=type%3D%22" + sessionType + "%22"
	}

	respData, statusCode, err := s.zitiManager.MgmtRequest("GET", path, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode)})
		return
	}

	var resp struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse response"})
		return
	}

	type sessionIdentity struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	type sessionService struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	type zitiSession struct {
		ID        string           `json:"id"`
		Type      string           `json:"type"`
		Identity  *sessionIdentity `json:"identity,omitempty"`
		Service   *sessionService  `json:"service,omitempty"`
		CreatedAt string           `json:"createdAt"`
		UpdatedAt string           `json:"updatedAt"`
	}

	// Parse each session; Ziti embeds identity/service as nested _links or inline objects
	var results []zitiSession
	for _, raw := range resp.Data {
		var entry struct {
			ID        string          `json:"id"`
			Type      string          `json:"type"`
			CreatedAt string          `json:"createdAt"`
			UpdatedAt string          `json:"updatedAt"`
			Token     string          `json:"token"`
			Identity  json.RawMessage `json:"identity,omitempty"`
			Service   json.RawMessage `json:"service,omitempty"`
			// Alternative: identityId / serviceId
			IdentityID string `json:"identityId,omitempty"`
			ServiceID  string `json:"serviceId,omitempty"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			continue
		}

		sess := zitiSession{
			ID:        entry.ID,
			Type:      entry.Type,
			CreatedAt: entry.CreatedAt,
			UpdatedAt: entry.UpdatedAt,
		}

		// Try to parse embedded identity object
		if len(entry.Identity) > 0 {
			var ident sessionIdentity
			if err := json.Unmarshal(entry.Identity, &ident); err == nil && ident.ID != "" {
				sess.Identity = &ident
			}
		}
		if sess.Identity == nil && entry.IdentityID != "" {
			sess.Identity = &sessionIdentity{ID: entry.IdentityID, Name: entry.IdentityID}
		}

		// Try to parse embedded service object
		if len(entry.Service) > 0 {
			var svc sessionService
			if err := json.Unmarshal(entry.Service, &svc); err == nil && svc.ID != "" {
				sess.Service = &svc
			}
		}
		if sess.Service == nil && entry.ServiceID != "" {
			sess.Service = &sessionService{ID: entry.ServiceID, Name: entry.ServiceID}
		}

		results = append(results, sess)
	}

	c.JSON(http.StatusOK, results)
}

func (s *Service) handleDeleteZitiSession(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	_, statusCode, err := s.zitiManager.MgmtRequest("DELETE", "/edge/management/v1/sessions/"+id, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode)})
		return
	}
	// Audit log the termination
	s.logAuditEvent(c, "ziti_session_terminated", id, "ziti_session", map[string]interface{}{
		"session_id": id,
	})

	c.JSON(http.StatusOK, gin.H{"message": "session terminated"})
}

func (s *Service) handleBatchDeleteZitiSessions(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	var req struct {
		IdentityID string `json:"identity_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// List all sessions
	respData, statusCode, err := s.zitiManager.MgmtRequest("GET", "/edge/management/v1/sessions?limit=500", nil)
	if err != nil || statusCode != http.StatusOK {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}

	var resp struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse sessions"})
		return
	}

	terminated := 0
	for _, raw := range resp.Data {
		var entry struct {
			ID         string          `json:"id"`
			Identity   json.RawMessage `json:"identity,omitempty"`
			IdentityID string          `json:"identityId,omitempty"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			continue
		}

		// Check identity match - try embedded object first, then flat field
		matchedIdentity := entry.IdentityID
		if matchedIdentity == "" && len(entry.Identity) > 0 {
			var ident struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(entry.Identity, &ident) == nil {
				matchedIdentity = ident.ID
			}
		}

		if matchedIdentity == req.IdentityID {
			_, sc, delErr := s.zitiManager.MgmtRequest("DELETE", "/edge/management/v1/sessions/"+entry.ID, nil)
			if delErr == nil && (sc == http.StatusOK || sc == http.StatusNoContent) {
				terminated++
			}
		}
	}

	s.logAuditEvent(c, "ziti_sessions_batch_terminated", req.IdentityID, "ziti_identity", map[string]interface{}{
		"identity_id":         req.IdentityID,
		"sessions_terminated": terminated,
	})

	c.JSON(http.StatusOK, gin.H{
		"message":             "sessions terminated",
		"sessions_terminated": terminated,
	})
}
