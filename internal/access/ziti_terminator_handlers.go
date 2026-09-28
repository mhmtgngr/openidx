package access

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gin-gonic/gin"
	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// ---------------------------------------------------------------------------
// Ziti Terminator handlers
// ---------------------------------------------------------------------------

// zitiTerminator is the part of a controller terminator the API returns: which
// router hosts which service, and at what address.
type zitiTerminator struct {
	ID         string         `json:"id"`
	ServiceID  string         `json:"serviceId"`
	Service    *zitiEntityRef `json:"service,omitempty"`
	RouterID   string         `json:"routerId"`
	Router     *zitiEntityRef `json:"router,omitempty"`
	Binding    string         `json:"binding"`
	Address    string         `json:"address"`
	Cost       int            `json:"cost"`
	Precedence string         `json:"precedence"`
	CreatedAt  string         `json:"createdAt"`
	UpdatedAt  string         `json:"updatedAt"`
}

// serviceID is the terminator's service, whichever way the controller spelled it.
func (t zitiTerminator) serviceID() string {
	if t.ServiceID != "" {
		return t.ServiceID
	}
	if t.Service != nil {
		return t.Service.ID
	}
	return ""
}

// handleListTerminators lists the controller's terminators, each naming the
// address a service is hosted at. An install administrator sees them all;
// anyone else sees the terminators of their organization's services.
func (s *Service) handleListTerminators(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	view, ok := s.zitiViewFor(c)
	if !ok {
		return
	}
	var own map[string]bool
	if !view.install {
		var err error
		if own, _, err = s.ownedZitiServices(c.Request.Context(), view.orgID); err != nil {
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("list terminators", err), s.logger)
			return
		}
	}
	respData, statusCode, err := s.ziti().MgmtRequest("GET", "/edge/management/v1/terminators?limit=500", nil)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list terminators", err), s.logger)
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

	var results []zitiTerminator
	for _, raw := range resp.Data {
		var t zitiTerminator
		if err := json.Unmarshal(raw, &t); err == nil && (view.install || own[t.serviceID()]) {
			results = append(results, t)
		}
	}
	c.JSON(http.StatusOK, results)
}

// handleGetTerminator returns one terminator, the controller's own record of it.
// Anyone but an install administrator gets it only when it hosts one of their
// organization's services, and the 404 an unknown id gets otherwise.
func (s *Service) handleGetTerminator(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	view, ok := s.zitiViewFor(c)
	if !ok {
		return
	}
	id := c.Param("id")
	respData, statusCode, err := s.ziti().MgmtRequest("GET", "/edge/management/v1/terminators/"+url.PathEscape(id), nil)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get terminator", err), s.logger)
		return
	}
	// One answer for an id the controller does not know and one the caller may
	// not see, so the answer does not say which terminators exist.
	if statusCode == http.StatusNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error": "terminator not found"})
		return
	}
	if statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode)})
		return
	}
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse response"})
		return
	}
	if !view.install {
		var t zitiTerminator
		_ = json.Unmarshal(resp.Data, &t)
		own, _, err := s.ownedZitiServices(c.Request.Context(), view.orgID)
		if err != nil {
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("get terminator", err), s.logger)
			return
		}
		if !own[t.serviceID()] {
			c.JSON(http.StatusNotFound, gin.H{"error": "terminator not found"})
			return
		}
	}
	c.Data(http.StatusOK, "application/json", resp.Data)
}

// handleDeleteTerminator removes one terminator. An organization's admin
// removes those of the organization's own services and gets the 404 an unknown
// id gets for any other; an install administrator removes any.
func (s *Service) handleDeleteTerminator(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	view, ok := s.zitiViewFor(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if !view.install {
		owned, err := s.ownsZitiTerminator(c.Request.Context(), view.orgID, id)
		if err != nil {
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete terminator", err), s.logger)
			return
		}
		if !owned {
			c.JSON(http.StatusNotFound, gin.H{"error": "terminator not found"})
			return
		}
	}
	_, statusCode, err := s.ziti().MgmtRequest("DELETE", "/edge/management/v1/terminators/"+url.PathEscape(id), nil)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete terminator", err), s.logger)
		return
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "terminator deleted"})
}
