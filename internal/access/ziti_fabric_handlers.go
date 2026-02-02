package access

import (
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
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.GovernancePolicyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "governance_policy_id is required"})
		return
	}
	if err := s.zitiManager.SyncGovernancePolicy(c.Request.Context(), req.GovernancePolicyID, req.Config); err != nil {
		s.logger.Error("failed to sync governance policy", zap.String("policyID", req.GovernancePolicyID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "policy synced successfully"})
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
