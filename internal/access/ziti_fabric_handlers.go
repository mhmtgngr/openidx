package access

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func (s *Service) zitiUnavailable(c *gin.Context) bool {
	if s.zitiManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Ziti manager is not available"})
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Fabric & Router handlers
// ---------------------------------------------------------------------------

func (s *Service) handleGetFabricOverview(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	overview, err := s.zitiManager.GetFabricOverview(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to get fabric overview", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, overview)
}

func (s *Service) handleListEdgeRouters(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	routers, err := s.zitiManager.ListEdgeRouters(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list edge routers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, routers)
}

func (s *Service) handleGetEdgeRouter(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	router, err := s.zitiManager.GetEdgeRouter(c.Request.Context(), id)
	if err != nil {
		s.logger.Error("failed to get edge router", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, router)
}

func (s *Service) handleGetHealth(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	status, err := s.zitiManager.HealthCheck(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to get health status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, status)
}

func (s *Service) handleReconnect(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	if err := s.zitiManager.Reconnect(c.Request.Context()); err != nil {
		s.logger.Error("failed to reconnect to Ziti controller", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "reconnected successfully"})
}

func (s *Service) handleGetMetrics(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	metricType := c.Query("type")
	if metricType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "query parameter 'type' is required"})
		return
	}

	sinceStr := c.DefaultQuery("since", "")
	var since time.Time
	if sinceStr != "" {
		parsed, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'since' parameter, expected RFC3339 format"})
			return
		}
		since = parsed
	}

	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil || parsed < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'limit' parameter"})
			return
		}
		limit = parsed
	}

	metrics, err := s.zitiManager.GetMetrics(c.Request.Context(), metricType, since, limit)
	if err != nil {
		s.logger.Error("failed to get metrics", zap.String("type", metricType), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, metrics)
}

func (s *Service) handleListServicePolicies(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	policies, err := s.zitiManager.ListServicePolicies(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list service policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policies)
}

// ---------------------------------------------------------------------------
// Ziti Service connectivity test
// ---------------------------------------------------------------------------

func (s *Service) handleTestZitiService(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	serviceID := c.Param("id")

	// Look up the service to get the Ziti service name
	var zitiID, name, host string
	var port int
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT ziti_id, name, host, port FROM ziti_services WHERE id = $1`, serviceID).
		Scan(&zitiID, &name, &host, &port)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found"})
		return
	}

	result := gin.H{
		"service_id":   serviceID,
		"service_name": name,
		"tests":        gin.H{},
		"tested_at":    time.Now(),
	}
	allOK := true

	// Test 1: Check Ziti service exists on controller
	start := time.Now()
	svc, svcErr := s.zitiManager.GetServiceByName(name)
	if svcErr != nil {
		result["tests"] = gin.H{
			"ziti_lookup": gin.H{"success": false, "error": svcErr.Error(), "latency_ms": time.Since(start).Milliseconds()},
		}
		result["success"] = false
		c.JSON(http.StatusOK, result)
		return
	}
	tests := gin.H{
		"ziti_lookup": gin.H{"success": true, "latency_ms": time.Since(start).Milliseconds(), "ziti_id": svc.ID},
	}

	// Test 2: Try to dial the service through Ziti overlay
	start = time.Now()
	reachable, dialErr := s.zitiManager.TestServiceDial(c.Request.Context(), name)
	dialResult := gin.H{
		"success":    reachable,
		"latency_ms": time.Since(start).Milliseconds(),
	}
	if dialErr != nil {
		dialResult["error"] = dialErr.Error()
	}
	if !reachable {
		allOK = false
	}
	tests["ziti_dial"] = dialResult

	// Test 3: Direct TCP connectivity to upstream
	if host != "" && port > 0 {
		tcpResult := s.testTCPConnectivity(c.Request.Context(), host, port)
		tests["upstream_tcp"] = gin.H{
			"success":    tcpResult.Success,
			"latency_ms": tcpResult.LatencyMs,
			"error":      tcpResult.ErrorMessage,
		}
		if !tcpResult.Success {
			allOK = false
		}
	}

	result["tests"] = tests
	result["success"] = allOK
	c.JSON(http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// Edge Router Policy CRUD handlers
// ---------------------------------------------------------------------------

func (s *Service) handleListEdgeRouterPolicies(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	policies, err := s.zitiManager.ListEdgeRouterPolicies(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list edge router policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policies)
}

func (s *Service) handleCreateEdgeRouterPolicy(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	var req struct {
		Name            string   `json:"name"`
		EdgeRouterRoles []string `json:"edgeRouterRoles"`
		IdentityRoles   []string `json:"identityRoles"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	payload := map[string]interface{}{
		"name":            req.Name,
		"edgeRouterRoles": req.EdgeRouterRoles,
		"identityRoles":   req.IdentityRoles,
	}
	body, _ := json.Marshal(payload)
	respData, statusCode, err := s.zitiManager.MgmtRequest("POST", "/edge/management/v1/edge-router-policies", body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode), "details": string(respData)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "edge router policy created"})
}

func (s *Service) handleUpdateEdgeRouterPolicy(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	var req struct {
		Name            string   `json:"name"`
		EdgeRouterRoles []string `json:"edgeRouterRoles"`
		IdentityRoles   []string `json:"identityRoles"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	payload := map[string]interface{}{
		"name":            req.Name,
		"edgeRouterRoles": req.EdgeRouterRoles,
		"identityRoles":   req.IdentityRoles,
	}
	body, _ := json.Marshal(payload)
	respData, statusCode, err := s.zitiManager.MgmtRequest("PUT", "/edge/management/v1/edge-router-policies/"+id, body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if statusCode != http.StatusOK {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode), "details": string(respData)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "edge router policy updated"})
}

func (s *Service) handleDeleteEdgeRouterPolicy(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	_, statusCode, err := s.zitiManager.MgmtRequest("DELETE", "/edge/management/v1/edge-router-policies/"+id, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		c.JSON(statusCode, gin.H{"error": "Ziti controller returned " + strconv.Itoa(statusCode)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "edge router policy deleted"})
}

// ---------------------------------------------------------------------------
// Posture Check handlers
// ---------------------------------------------------------------------------

func (s *Service) handleListPostureChecks(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	checks, err := s.zitiManager.ListPostureChecks(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list posture checks", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, checks)
}

func (s *Service) handleCreatePostureCheck(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	var check PostureCheck
	if err := c.ShouldBindJSON(&check); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.zitiManager.CreatePostureCheck(c.Request.Context(), &check); err != nil {
		s.logger.Error("failed to create posture check", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, check)
}

func (s *Service) handleUpdatePostureCheck(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	var check PostureCheck
	if err := c.ShouldBindJSON(&check); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.zitiManager.UpdatePostureCheck(c.Request.Context(), id, &check); err != nil {
		s.logger.Error("failed to update posture check", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, check)
}

func (s *Service) handleDeletePostureCheck(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	if err := s.zitiManager.DeletePostureCheck(c.Request.Context(), id); err != nil {
		s.logger.Error("failed to delete posture check", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

func (s *Service) handleGetIdentityPosture(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	identityID := c.Param("id")
	results, err := s.zitiManager.GetIdentityPostureStatus(c.Request.Context(), identityID)
	if err != nil {
		s.logger.Error("failed to get identity posture status", zap.String("identityID", identityID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, results)
}

func (s *Service) handleEvaluateIdentityPosture(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	identityID := c.Param("id")
	passed, results, err := s.zitiManager.EvaluateIdentityPosture(c.Request.Context(), identityID)
	if err != nil {
		s.logger.Error("failed to evaluate identity posture", zap.String("identityID", identityID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"passed":  passed,
		"results": results,
	})
}

func (s *Service) handleGetPostureSummary(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	summary, err := s.zitiManager.GetPostureCheckSummary(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to get posture check summary", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, summary)
}

func (s *Service) handleSubmitDevicePosture(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	var req struct {
		IdentityID string            `json:"identity_id" binding:"required"`
		Posture    DevicePostureData `json:"posture" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	report, err := s.zitiManager.EvaluateDeviceHealth(c.Request.Context(), req.IdentityID, &req.Posture)
	if err != nil {
		s.logger.Error("Device posture evaluation failed",
			zap.String("identity_id", req.IdentityID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.logAuditEvent(c, "device_posture_evaluated", req.IdentityID, "ziti_identity", map[string]interface{}{
		"overall_passed": report.OverallPassed,
		"score":          report.Score,
		"critical":       report.Critical,
		"high":           report.High,
	})

	c.JSON(http.StatusOK, report)
}

// ---------------------------------------------------------------------------
// Policy Sync handlers
// ---------------------------------------------------------------------------

func (s *Service) handleListPolicySyncStates(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	states, err := s.zitiManager.ListPolicySyncStates(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list policy sync states", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, states)
}

func (s *Service) handleSyncGovernancePolicy(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	var req struct {
		GovernancePolicyID string                 `json:"governance_policy_id"`
		Config             map[string]interface{} `json:"config"`
		AutoFetch          bool                   `json:"auto_fetch"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.GovernancePolicyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "governance_policy_id is required"})
		return
	}

	config := req.Config
	if req.AutoFetch || len(config) == 0 {
		// Fetch and transform the governance policy automatically
		policy, err := s.zitiManager.FetchGovernancePolicy(c.Request.Context(), req.GovernancePolicyID)
		if err != nil {
			s.logger.Error("failed to fetch governance policy", zap.String("policyID", req.GovernancePolicyID), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch governance policy: " + err.Error()})
			return
		}
		config = TransformGovernancePolicyToZiti(policy)
	}

	if err := s.zitiManager.SyncGovernancePolicy(c.Request.Context(), req.GovernancePolicyID, config); err != nil {
		s.logger.Error("failed to sync governance policy", zap.String("policyID", req.GovernancePolicyID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "policy synced successfully", "auto_fetched": req.AutoFetch || len(req.Config) == 0})
}

func (s *Service) handleTriggerPolicySync(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	if err := s.zitiManager.TriggerPolicySync(c.Request.Context(), id); err != nil {
		s.logger.Error("failed to trigger policy sync", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "policy sync triggered"})
}

func (s *Service) handleDeletePolicySyncState(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	if err := s.zitiManager.DeletePolicySyncState(c.Request.Context(), id); err != nil {
		s.logger.Error("failed to delete policy sync state", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// ---------------------------------------------------------------------------
// Service Policy CRUD handlers
// ---------------------------------------------------------------------------

func (s *Service) handleCreateServicePolicy(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	var req struct {
		Name          string   `json:"name" binding:"required"`
		Type          string   `json:"type" binding:"required"`
		ServiceRoles  []string `json:"service_roles" binding:"required"`
		IdentityRoles []string `json:"identity_roles" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Type != "Dial" && req.Type != "Bind" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be 'Dial' or 'Bind'"})
		return
	}

	zitiID, err := s.zitiManager.CreateServicePolicy(c.Request.Context(), req.Name, req.Type, req.ServiceRoles, req.IdentityRoles)
	if err != nil {
		s.logger.Error("failed to create service policy", zap.String("name", req.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Persist to DB
	serviceRolesJSON, _ := json.Marshal(req.ServiceRoles)
	identityRolesJSON, _ := json.Marshal(req.IdentityRoles)

	var id string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles, is_system)
		 VALUES ($1, $2, $3, $4, $5, false) RETURNING id`,
		zitiID, req.Name, req.Type, serviceRolesJSON, identityRolesJSON).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to persist service policy to DB", zap.Error(err))
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":             id,
		"ziti_id":        zitiID,
		"name":           req.Name,
		"type":           req.Type,
		"service_roles":  req.ServiceRoles,
		"identity_roles": req.IdentityRoles,
	})
}

func (s *Service) handleUpdateServicePolicy(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	id := c.Param("id")

	var req struct {
		Name          string   `json:"name" binding:"required"`
		Type          string   `json:"type" binding:"required"`
		ServiceRoles  []string `json:"service_roles" binding:"required"`
		IdentityRoles []string `json:"identity_roles" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Type != "Dial" && req.Type != "Bind" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be 'Dial' or 'Bind'"})
		return
	}

	// Look up ziti_id and check if system policy
	var zitiID string
	var isSystem bool
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT ziti_id, COALESCE(is_system, false) FROM ziti_service_policies WHERE id=$1", id).Scan(&zitiID, &isSystem)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service policy not found"})
		return
	}
	if isSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot modify system-managed policies"})
		return
	}

	if err := s.zitiManager.UpdateServicePolicy(c.Request.Context(), zitiID, req.Name, req.Type, req.ServiceRoles, req.IdentityRoles); err != nil {
		s.logger.Error("failed to update service policy", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Update DB
	serviceRolesJSON, _ := json.Marshal(req.ServiceRoles)
	identityRolesJSON, _ := json.Marshal(req.IdentityRoles)
	s.db.Pool.Exec(c.Request.Context(),
		`UPDATE ziti_service_policies SET name=$1, policy_type=$2, service_roles=$3, identity_roles=$4 WHERE id=$5`,
		req.Name, req.Type, serviceRolesJSON, identityRolesJSON, id)

	c.JSON(http.StatusOK, gin.H{
		"id":             id,
		"ziti_id":        zitiID,
		"name":           req.Name,
		"type":           req.Type,
		"service_roles":  req.ServiceRoles,
		"identity_roles": req.IdentityRoles,
	})
}

func (s *Service) handleDeleteServicePolicy(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	id := c.Param("id")

	var zitiID string
	var isSystem bool
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT ziti_id, COALESCE(is_system, false) FROM ziti_service_policies WHERE id=$1", id).Scan(&zitiID, &isSystem)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service policy not found"})
		return
	}
	if isSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete system-managed policies"})
		return
	}

	if err := s.zitiManager.DeleteServicePolicy(c.Request.Context(), zitiID); err != nil {
		s.logger.Error("failed to delete service policy from controller", zap.String("id", id), zap.Error(err))
	}

	s.db.Pool.Exec(c.Request.Context(), "DELETE FROM ziti_service_policies WHERE id=$1", id)

	c.JSON(http.StatusNoContent, nil)
}

// ---------------------------------------------------------------------------
// Identity attribute management
// ---------------------------------------------------------------------------

func (s *Service) handlePatchIdentityAttributes(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}

	id := c.Param("id")

	var req struct {
		Attributes []string `json:"attributes" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Look up ziti_id from DB
	var zitiID string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT ziti_id FROM ziti_identities WHERE id=$1", id).Scan(&zitiID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ziti identity not found"})
		return
	}

	if err := s.zitiManager.PatchIdentityRoleAttributes(c.Request.Context(), zitiID, req.Attributes); err != nil {
		s.logger.Error("failed to patch identity attributes", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Update DB
	attrsJSON, _ := json.Marshal(req.Attributes)
	s.db.Pool.Exec(c.Request.Context(),
		"UPDATE ziti_identities SET attributes=$1, updated_at=NOW() WHERE id=$2", attrsJSON, id)

	c.JSON(http.StatusOK, gin.H{
		"id":         id,
		"ziti_id":    zitiID,
		"attributes": req.Attributes,
		"message":    "identity attributes updated",
	})
}

// ---------------------------------------------------------------------------
// Certificate handlers
// ---------------------------------------------------------------------------

func (s *Service) handleListCertificates(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	certs, err := s.zitiManager.ListZitiCertificates(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list certificates", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, certs)
}

func (s *Service) handleGetCertExpiryAlerts(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	thresholdDays := 30
	if v := c.Query("threshold_days"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'threshold_days' parameter"})
			return
		}
		thresholdDays = parsed
	}
	certs, err := s.zitiManager.GetCertificateExpiryAlerts(c.Request.Context(), thresholdDays)
	if err != nil {
		s.logger.Error("failed to get certificate expiry alerts", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, certs)
}

func (s *Service) handleRotateCertificate(c *gin.Context) {
	if s.zitiUnavailable(c) {
		return
	}
	id := c.Param("id")
	if err := s.zitiManager.RotateCertificate(c.Request.Context(), id); err != nil {
		s.logger.Error("failed to rotate certificate", zap.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "certificate rotated successfully"})
}
