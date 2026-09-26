package access

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// ---------------------------------------------------------------------------
// Ziti Session Visibility handlers
// ---------------------------------------------------------------------------

// handleListZitiSessions lists the controller's sessions: who is connected to
// which service. An install administrator sees them all; anyone else sees the
// sessions between their organization's identities and its services (see
// ziti_scope.go).
func (s *Service) handleListZitiSessions(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	view, ok := s.zitiViewFor(c)
	if !ok {
		return
	}

	path := "/edge/management/v1/sessions?limit=200"
	if sessionType := c.Query("type"); sessionType != "" {
		path += "&filter=type%3D%22" + sessionType + "%22"
	}

	respData, statusCode, err := s.ziti().MgmtRequest("GET", path, nil)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list ziti sessions", err), s.logger)
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

	var ownIdentities, ownServices map[string]bool
	if !view.install {
		ctx := c.Request.Context()
		if ownIdentities, err = s.ownedZitiIdentities(ctx, view.orgID); err == nil {
			ownServices, _, err = s.ownedZitiServices(ctx, view.orgID)
		}
		if err != nil {
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("list ziti sessions", err), s.logger)
			return
		}
	}

	type zitiSession struct {
		ID        string         `json:"id"`
		Type      string         `json:"type"`
		Identity  *zitiEntityRef `json:"identity,omitempty"`
		Service   *zitiEntityRef `json:"service,omitempty"`
		CreatedAt string         `json:"createdAt"`
		UpdatedAt string         `json:"updatedAt"`
	}

	var results []zitiSession
	for _, raw := range resp.Data {
		var entry struct {
			ID        string `json:"id"`
			Type      string `json:"type"`
			CreatedAt string `json:"createdAt"`
			UpdatedAt string `json:"updatedAt"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			continue
		}
		identity, service := zitiSessionEnds(raw)
		if !view.install && (!ownIdentities[identity.ID] || !ownServices[service.ID]) {
			continue
		}

		sess := zitiSession{
			ID:        entry.ID,
			Type:      entry.Type,
			CreatedAt: entry.CreatedAt,
			UpdatedAt: entry.UpdatedAt,
		}
		if identity.ID != "" {
			sess.Identity = &identity
		}
		if service.ID != "" {
			sess.Service = &service
		}
		results = append(results, sess)
	}

	c.JSON(http.StatusOK, results)
}

// handleDeleteZitiSession ends one controller session. An organization's admin
// ends the organization's own sessions (ownsZitiSession) and gets the 404 an
// unknown id gets for any other; an install administrator ends any.
func (s *Service) handleDeleteZitiSession(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	view, ok := s.zitiViewFor(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if !view.install {
		owned, err := s.ownsZitiSession(c.Request.Context(), view.orgID, id)
		if err != nil {
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete ziti session", err), s.logger)
			return
		}
		if !owned {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
			return
		}
	}
	_, statusCode, err := s.ziti().MgmtRequest("DELETE", "/edge/management/v1/sessions/"+id, nil)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete ziti session", err), s.logger)
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

// handleBatchDeleteZitiSessions ends every session one identity holds. An
// organization's admin names one of the organization's identities, and gets
// the 404 an unknown one gets for any other; an install administrator any.
func (s *Service) handleBatchDeleteZitiSessions(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	view, ok := s.zitiViewFor(c)
	if !ok {
		return
	}

	var req struct {
		IdentityID string `json:"identity_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !view.install {
		owned, err := s.ownsZitiIdentity(c.Request.Context(), view.orgID, req.IdentityID)
		if err != nil {
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("terminate ziti sessions", err), s.logger)
			return
		}
		if !owned {
			c.JSON(http.StatusNotFound, gin.H{"error": "ziti identity not found"})
			return
		}
	}

	// List all sessions
	respData, statusCode, err := s.ziti().MgmtRequest("GET", "/edge/management/v1/sessions?limit=500", nil)
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
			_, sc, delErr := s.ziti().MgmtRequest("DELETE", "/edge/management/v1/sessions/"+entry.ID, nil)
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
