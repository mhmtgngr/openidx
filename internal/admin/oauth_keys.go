package admin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/signingkeys"
)

// OAuth signing key management. Keys live install-wide in oauth_signing_keys
// (v79) and are consumed by the oauth service, which signs with the active
// key and serves every verification key from JWKS. Rotation here takes
// effect on the oauth service within its signer refresh interval (≤5m); the
// retired key keeps verifying outstanding tokens until its grace expires, so
// rotation is never a token-invalidation event.

type signingKeyView struct {
	Kid         string     `json:"kid"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
}

func (s *Service) signingKeyStore() *signingkeys.Store {
	return signingkeys.NewStore(s.db.Pool, s.config.EncryptionKey, s.logger)
}

// handleListOAuthSigningKeys returns metadata for every signing key (never
// private material).
func (s *Service) handleListOAuthSigningKeys(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	keys, err := s.signingKeyStore().List(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list OAuth signing keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list signing keys"})
		return
	}
	views := make([]signingKeyView, 0, len(keys))
	for _, k := range keys {
		views = append(views, signingKeyView{
			Kid: k.Kid, Status: k.Status, CreatedAt: k.CreatedAt,
			ActivatedAt: k.ActivatedAt, RetiredAt: k.RetiredAt, NotAfter: k.NotAfter,
		})
	}
	c.JSON(http.StatusOK, gin.H{"keys": views})
}

// handleRotateOAuthSigningKey generates a fresh active key and retires the
// current one with a verification grace (default 30 days, 1–365).
func (s *Service) handleRotateOAuthSigningKey(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	var req struct {
		GraceDays int `json:"grace_days"`
	}
	// Body is optional; ignore bind errors from an empty body.
	_ = c.ShouldBindJSON(&req)
	if req.GraceDays == 0 {
		req.GraceDays = 30
	}
	if req.GraceDays < 1 || req.GraceDays > 365 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "grace_days must be between 1 and 365"})
		return
	}

	ctx := c.Request.Context()
	newKey, err := s.signingKeyStore().Rotate(ctx, time.Duration(req.GraceDays)*24*time.Hour)
	if err != nil {
		s.logger.Error("OAuth signing key rotation failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "rotation failed"})
		return
	}

	_ = s.RecordAdminAction(
		ctx,
		c.GetString("user_id"),
		c.GetString("email"),
		"rotate_oauth_signing_key",
		"oauth_signing_key",
		newKey.Kid,
		"OAuth Signing Key",
		c.ClientIP(),
		c.Request.UserAgent(),
		c.GetString("request_id"),
		nil,
		map[string]interface{}{"new_kid": newKey.Kid, "grace_days": req.GraceDays},
	)

	c.JSON(http.StatusOK, gin.H{
		"kid":        newKey.Kid,
		"status":     "active",
		"grace_days": req.GraceDays,
		"note":       "the oauth service signs with the new key within its refresh interval; the previous key remains valid for verification until its grace expires",
	})
}
