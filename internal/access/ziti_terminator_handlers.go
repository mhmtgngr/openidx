package access

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// Ziti Terminator handlers
// ---------------------------------------------------------------------------

func (s *Service) handleListTerminators(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	respData, statusCode, err := s.zitiManager.MgmtRequest("GET", "/edge/management/v1/terminators?limit=500", nil)
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

	type terminatorRef struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	type terminator struct {
		ID         string         `json:"id"`
		ServiceID  string         `json:"serviceId"`
		Service    *terminatorRef `json:"service,omitempty"`
		RouterID   string         `json:"routerId"`
		Router     *terminatorRef `json:"router,omitempty"`
		Binding    string         `json:"binding"`
		Address    string         `json:"address"`
		Cost       int            `json:"cost"`
		Precedence string         `json:"precedence"`
		CreatedAt  string         `json:"createdAt"`
		UpdatedAt  string         `json:"updatedAt"`
	}

	var results []terminator
	for _, raw := range resp.Data {
		var t terminator
		if err := json.Unmarshal(raw, &t); err == nil {
			results = append(results, t)
		}
	}
	c.JSON(http.StatusOK, results)
}

func (s *Service) handleGetTerminator(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	respData, statusCode, err := s.zitiManager.MgmtRequest("GET", "/edge/management/v1/terminators/"+id, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
	c.Data(http.StatusOK, "application/json", resp.Data)
}

func (s *Service) handleDeleteTerminator(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	_, statusCode, err := s.zitiManager.MgmtRequest("DELETE", "/edge/management/v1/terminators/"+id, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "terminator deleted"})
}
