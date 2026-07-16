package access

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// ---------------------------------------------------------------------------
// Auth Policy CRUD handlers
// ---------------------------------------------------------------------------

func (s *Service) handleListAuthPolicies(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	respData, statusCode, err := s.ziti().MgmtRequest("GET", "/edge/management/v1/auth-policies?limit=500", nil)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list auth policies", err), s.logger)
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

	type authPolicy struct {
		ID        string                 `json:"id"`
		Name      string                 `json:"name"`
		Primary   map[string]interface{} `json:"primary"`
		Secondary map[string]interface{} `json:"secondary"`
	}
	var results []authPolicy
	for _, raw := range resp.Data {
		var ap authPolicy
		if err := json.Unmarshal(raw, &ap); err == nil {
			results = append(results, ap)
		}
	}
	c.JSON(http.StatusOK, results)
}

func (s *Service) handleCreateAuthPolicy(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	var req struct {
		Name      string                 `json:"name"`
		Primary   map[string]interface{} `json:"primary"`
		Secondary map[string]interface{} `json:"secondary"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	body, _ := json.Marshal(req)
	respData, statusCode, err := s.ziti().MgmtRequest("POST", "/edge/management/v1/auth-policies", body)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("create auth policy", err), s.logger)
		return
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode), "details": string(respData)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "auth policy created"})
}

func (s *Service) handleUpdateAuthPolicy(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	var req struct {
		Name      string                 `json:"name"`
		Primary   map[string]interface{} `json:"primary"`
		Secondary map[string]interface{} `json:"secondary"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	body, _ := json.Marshal(req)
	respData, statusCode, err := s.ziti().MgmtRequest("PUT", "/edge/management/v1/auth-policies/"+id, body)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("update auth policy", err), s.logger)
		return
	}
	if statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode), "details": string(respData)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "auth policy updated"})
}

func (s *Service) handleDeleteAuthPolicy(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	_, statusCode, err := s.ziti().MgmtRequest("DELETE", "/edge/management/v1/auth-policies/"+id, nil)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete auth policy", err), s.logger)
		return
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "auth policy deleted"})
}

// ---------------------------------------------------------------------------
// JWT Signer CRUD handlers
// ---------------------------------------------------------------------------

func (s *Service) handleListJWTSigners(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	respData, statusCode, err := s.ziti().MgmtRequest("GET", "/edge/management/v1/external-jwt-signers?limit=500", nil)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list j w t signers", err), s.logger)
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

	type jwtSigner struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Issuer          string `json:"issuer"`
		Audience        string `json:"audience"`
		JwksEndpoint    string `json:"jwksEndpoint"`
		ClaimsProperty  string `json:"claimsProperty"`
		UseExternalId   bool   `json:"useExternalId"`
		Enabled         bool   `json:"enabled"`
		ExternalAuthUrl string `json:"externalAuthUrl,omitempty"`
	}
	var results []jwtSigner
	for _, raw := range resp.Data {
		var js jwtSigner
		if err := json.Unmarshal(raw, &js); err == nil {
			results = append(results, js)
		}
	}
	c.JSON(http.StatusOK, results)
}

func (s *Service) handleCreateJWTSigner(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	var req struct {
		Name            string `json:"name"`
		Issuer          string `json:"issuer"`
		Audience        string `json:"audience"`
		JwksEndpoint    string `json:"jwksEndpoint"`
		ClaimsProperty  string `json:"claimsProperty"`
		UseExternalId   bool   `json:"useExternalId"`
		Enabled         bool   `json:"enabled"`
		ExternalAuthUrl string `json:"externalAuthUrl,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" || req.Issuer == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and issuer are required"})
		return
	}

	body, _ := json.Marshal(req)
	respData, statusCode, err := s.ziti().MgmtRequest("POST", "/edge/management/v1/external-jwt-signers", body)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("create j w t signer", err), s.logger)
		return
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode), "details": string(respData)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "JWT signer created"})
}

func (s *Service) handleUpdateJWTSigner(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	var req struct {
		Name            string `json:"name"`
		Issuer          string `json:"issuer"`
		Audience        string `json:"audience"`
		JwksEndpoint    string `json:"jwksEndpoint"`
		ClaimsProperty  string `json:"claimsProperty"`
		UseExternalId   bool   `json:"useExternalId"`
		Enabled         bool   `json:"enabled"`
		ExternalAuthUrl string `json:"externalAuthUrl,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	body, _ := json.Marshal(req)
	respData, statusCode, err := s.ziti().MgmtRequest("PUT", "/edge/management/v1/external-jwt-signers/"+id, body)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("update j w t signer", err), s.logger)
		return
	}
	if statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode), "details": string(respData)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "JWT signer updated"})
}

func (s *Service) handleDeleteJWTSigner(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	_, statusCode, err := s.ziti().MgmtRequest("DELETE", "/edge/management/v1/external-jwt-signers/"+id, nil)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete j w t signer", err), s.logger)
		return
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "JWT signer deleted"})
}
