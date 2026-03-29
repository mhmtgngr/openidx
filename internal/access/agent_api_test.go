package access

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newTestAgentHandler returns an AgentAPIHandler suitable for unit tests.
func newTestAgentHandler() *AgentAPIHandler {
	logger := zap.NewNop()
	return NewAgentAPIHandler(logger, nil, nil)
}

// TestAgentEnroll_ValidToken verifies that a POST to /agent/enroll with an
// Authorization header returns 200 and non-empty agent_id, device_id, auth_token.
func TestAgentEnroll_ValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/enroll", handler.HandleEnroll)

	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	c.Request = req

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp enrollResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.AgentID)
	assert.NotEmpty(t, resp.DeviceID)
	assert.NotEmpty(t, resp.AuthToken)
}

// TestAgentEnroll_MissingToken verifies that a request without Authorization
// returns 401.
func TestAgentEnroll_MissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/enroll", handler.HandleEnroll)

	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestAgentReport_Accepted verifies that a POST to /agent/report with a JSON
// body is acknowledged with 202.
func TestAgentReport_Accepted(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/report", handler.HandleReport)

	body, _ := json.Marshal(map[string]interface{}{
		"agent_id": "test-agent-id",
		"status":   "healthy",
	})
	req := httptest.NewRequest(http.MethodPost, "/agent/report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", "test-agent-id")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
}

// TestAgentConfig_ReturnsDefaults verifies that a GET to /agent/config returns
// 200 with a checks array and report_interval field.
func TestAgentConfig_ReturnsDefaults(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.GET("/agent/config", handler.HandleConfig)

	req := httptest.NewRequest(http.MethodGet, "/agent/config", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp agentConfigResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Checks)
	assert.Equal(t, 3, len(resp.Checks))
	assert.Equal(t, "1h", resp.ReportInterval)
}

// TestAgentEnroll_ResponseFields verifies that a successful enroll response
// includes the status and enrolled_at fields in addition to the core identifiers.
func TestAgentEnroll_ResponseFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/enroll", handler.HandleEnroll)

	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp["agent_id"], "agent_id should be present")
	assert.NotEmpty(t, resp["device_id"], "device_id should be present")
	assert.NotEmpty(t, resp["auth_token"], "auth_token should be present")
	assert.NotEmpty(t, resp["status"], "status should be present")
	assert.NotEmpty(t, resp["enrolled_at"], "enrolled_at should be present")

	// In development mode (no real DB) status should be auto-approved to "active"
	assert.Equal(t, "active", resp["status"])
}

// TestRegisterAgentRoutes verifies that all three routes are registered and
// respond to the correct HTTP methods.
func TestRegisterAgentRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := newTestAgentHandler()
	group := router.Group("/")
	handler.RegisterAgentRoutes(group)

	// /agent/enroll — requires Authorization header
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	req.Header.Set("Authorization", "Bearer tok")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// /agent/report
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/agent/report", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)

	// /agent/config
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/agent/config", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
