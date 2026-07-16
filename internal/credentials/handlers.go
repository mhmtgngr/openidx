package credentials

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// RegisterRoutes mounts the credential rotation API under an already-admin-guarded group.
// The caller passes a group that has tenant-resolution + auth applied
// (same middleware the admin-api vault resources use).
func (s *Service) RegisterRoutes(g *gin.RouterGroup) {
	g.POST("/vault/rotation-policies", s.handleCreatePolicy)
	g.GET("/vault/rotation-policies", s.handleListPolicies)
	g.GET("/vault/rotation-policies/:id", s.handleGetPolicy)
	g.PUT("/vault/rotation-policies/:id", s.handleUpdatePolicy)
	g.DELETE("/vault/rotation-policies/:id", s.handleDeletePolicy)
	g.POST("/vault/secrets/:id/rotate", s.handleRotateNow)         // admin-only (group is RequireAdmin)
	g.GET("/vault/secrets/:id/rotations", s.handleRotationHistory) // org-scoped via RLS
}

func (s *Service) handleCreatePolicy(c *gin.Context) {
	var in PolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	policy, err := s.CreatePolicy(c.Request.Context(), in)
	if err != nil {
		if errors.Is(err, ErrInvalidPolicy) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrSecretNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "secret not found or not accessible"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("create policy", err), s.logger)
		return
	}
	c.JSON(http.StatusCreated, policy)
}

func (s *Service) handleListPolicies(c *gin.Context) {
	policies, err := s.ListPolicies(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list policies", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

func (s *Service) handleGetPolicy(c *gin.Context) {
	policy, err := s.GetPolicy(c.Request.Context(), c.Param("id"))
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get policy", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, policy)
}

func (s *Service) handleUpdatePolicy(c *gin.Context) {
	var in PolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	policy, err := s.UpdatePolicy(c.Request.Context(), c.Param("id"), in)
	if err != nil {
		if errors.Is(err, ErrInvalidPolicy) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrPolicyNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("update policy", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, policy)
}

func (s *Service) handleDeletePolicy(c *gin.Context) {
	if err := s.DeletePolicy(c.Request.Context(), c.Param("id")); err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete policy", err), s.logger)
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Service) handleRotateNow(c *gin.Context) {
	secretID := c.Param("id")
	policyID, err := s.policyIDForSecret(c.Request.Context(), secretID)
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "no rotation policy configured for this secret"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("rotate now", err), s.logger)
		return
	}
	if err := s.RotateSecret(c.Request.Context(), policyID, "on_demand"); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("rotate now", err), s.logger)
		return
	}
	run, err := s.LatestRotationRun(c.Request.Context(), secretID)
	if err != nil {
		// Rotation completed; just return 200 without ledger detail.
		c.JSON(http.StatusOK, gin.H{"status": "completed"})
		return
	}
	c.JSON(http.StatusOK, run)
}

func (s *Service) handleRotationHistory(c *gin.Context) {
	runs, err := s.RotationHistory(c.Request.Context(), c.Param("id"))
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("rotation history", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, gin.H{"rotations": runs})
}
