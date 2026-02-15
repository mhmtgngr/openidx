package access

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// Config Type & Config CRUD handlers
// ---------------------------------------------------------------------------

func (s *Service) handleListConfigTypes(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	respData, statusCode, err := s.zitiManager.MgmtRequest("GET", "/edge/management/v1/config-types?limit=500", nil)
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

	type configType struct {
		ID     string          `json:"id"`
		Name   string          `json:"name"`
		Schema json.RawMessage `json:"schema,omitempty"`
	}
	var results []configType
	for _, raw := range resp.Data {
		var ct configType
		if err := json.Unmarshal(raw, &ct); err == nil {
			results = append(results, ct)
		}
	}
	c.JSON(http.StatusOK, results)
}

func (s *Service) handleListConfigs(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	respData, statusCode, err := s.zitiManager.MgmtRequest("GET", "/edge/management/v1/configs?limit=500", nil)
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

	type configEntry struct {
		ID           string          `json:"id"`
		Name         string          `json:"name"`
		ConfigTypeID string          `json:"configTypeId"`
		ConfigType   json.RawMessage `json:"configType,omitempty"`
		Data         json.RawMessage `json:"data"`
	}
	var results []configEntry
	for _, raw := range resp.Data {
		var ce configEntry
		if err := json.Unmarshal(raw, &ce); err == nil {
			results = append(results, ce)
		}
	}
	c.JSON(http.StatusOK, results)
}

func (s *Service) handleCreateConfig(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	var req struct {
		Name         string          `json:"name"`
		ConfigTypeID string          `json:"configTypeId"`
		Data         json.RawMessage `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" || req.ConfigTypeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and configTypeId are required"})
		return
	}

	payload := map[string]interface{}{
		"name":         req.Name,
		"configTypeId": req.ConfigTypeID,
		"data":         req.Data,
	}
	body, _ := json.Marshal(payload)
	respData, statusCode, err := s.zitiManager.MgmtRequest("POST", "/edge/management/v1/configs", body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode), "details": string(respData)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "config created"})
}

func (s *Service) handleUpdateConfig(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	var req struct {
		Name string          `json:"name"`
		Data json.RawMessage `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	payload := map[string]interface{}{
		"name": req.Name,
		"data": req.Data,
	}
	body, _ := json.Marshal(payload)
	respData, statusCode, err := s.zitiManager.MgmtRequest("PUT", "/edge/management/v1/configs/"+id, body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode), "details": string(respData)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "config updated"})
}

func (s *Service) handleDeleteConfig(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	_, statusCode, err := s.zitiManager.MgmtRequest("DELETE", "/edge/management/v1/configs/"+id, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "config deleted"})
}
