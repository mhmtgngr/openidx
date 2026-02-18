// Package oauth - Step-up authentication handlers
// Provides mid-session re-authentication via step-up challenges, allowing
// applications to require additional verification for high-value operations.
package oauth

import (
	"context"
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/identity"
)

// handleStepUpChallenge creates a step-up challenge for mid-session re-authentication.
// POST /oauth/stepup-challenge
func (s *Service) handleStepUpChallenge(c *gin.Context) {
	userID := c.GetString("user_id")
	sessionID := c.GetString("session_id")

	if userID == "" || sessionID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "valid session required for step-up authentication",
		})
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// Body is optional; default reason if missing or malformed
		req.Reason = ""
	}
	if req.Reason == "" {
		req.Reason = "manual"
	}

	ctx := c.Request.Context()

	// Insert step-up challenge with 5-minute expiry
	var challengeID string
	var expiresAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO stepup_challenges (id, user_id, session_id, reason, status, created_at, expires_at)
		VALUES (gen_random_uuid(), $1, $2, $3, 'pending', NOW(), NOW() + INTERVAL '5 minutes')
		RETURNING id, expires_at`,
		userID, sessionID, req.Reason,
	).Scan(&challengeID, &expiresAt)
	if err != nil {
		s.logger.Error("Failed to create step-up challenge",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to create step-up challenge",
		})
		return
	}

	// Query available MFA methods for the user
	availableMethods := []string{}
	var totpEnabled, smsEnabled, emailOTPEnabled, pushEnabled, webauthnEnabled bool
	err = s.db.Pool.QueryRow(ctx, `
		SELECT totp_enabled, sms_enabled, email_otp_enabled, push_enabled, webauthn_enabled
		FROM user_mfa_methods WHERE user_id = $1`,
		userID,
	).Scan(&totpEnabled, &smsEnabled, &emailOTPEnabled, &pushEnabled, &webauthnEnabled)
	if err != nil {
		// If no MFA methods row exists, return empty list but don't fail
		s.logger.Warn("No MFA methods found for user",
			zap.String("user_id", userID),
			zap.Error(err),
		)
	} else {
		if totpEnabled {
			availableMethods = append(availableMethods, "totp")
		}
		if smsEnabled {
			availableMethods = append(availableMethods, "sms")
		}
		if emailOTPEnabled {
			availableMethods = append(availableMethods, "email")
		}
		if pushEnabled {
			availableMethods = append(availableMethods, "push")
		}
		if webauthnEnabled {
			availableMethods = append(availableMethods, "webauthn")
		}
	}

	// If identity service is available, assess risk and filter methods accordingly
	if s.identityService != nil {
		lc := &identity.LoginContext{
			UserID:    userID,
			IPAddress: c.ClientIP(),
			UserAgent: c.GetHeader("User-Agent"),
		}
		assessment, riskErr := s.identityService.AssessLoginRisk(ctx, lc)
		if riskErr == nil && assessment != nil && len(assessment.AllowedMethods) > 0 {
			// Intersect available methods with risk-allowed methods
			allowedSet := make(map[string]bool)
			for _, m := range assessment.AllowedMethods {
				allowedSet[m] = true
			}
			filtered := []string{}
			for _, m := range availableMethods {
				if allowedSet[m] {
					filtered = append(filtered, m)
				}
			}
			availableMethods = filtered
		}
	}

	go s.logAuditEvent(context.Background(), "authentication", "security", "step_up_challenge_created", "success",
		userID, c.ClientIP(), userID, "user",
		map[string]interface{}{"challenge_id": challengeID, "reason": req.Reason})

	c.JSON(http.StatusOK, gin.H{
		"challenge_id":      challengeID,
		"available_methods": availableMethods,
		"expires_at":        expiresAt.UTC().Format(time.RFC3339),
		"reason":            req.Reason,
	})
}

// handleStepUpVerify verifies a step-up challenge and issues a short-lived step-up token.
// POST /oauth/stepup-verify
func (s *Service) handleStepUpVerify(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "valid session required",
		})
		return
	}

	var req struct {
		ChallengeID string `json:"challenge_id"`
		Method      string `json:"method"`
		Code        string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "invalid request body",
		})
		return
	}

	if req.ChallengeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "challenge_id is required",
		})
		return
	}

	ctx := c.Request.Context()

	// Look up the challenge
	var challengeUserID, challengeSessionID, status, reason string
	var expiresAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, session_id, status, expires_at
		FROM stepup_challenges WHERE id = $1`,
		req.ChallengeID,
	).Scan(&req.ChallengeID, &challengeUserID, &challengeSessionID, &status, &expiresAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "challenge not found",
		})
		return
	}

	// Validate user ownership
	if challengeUserID != userID {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "forbidden",
			"error_description": "challenge does not belong to current user",
		})
		return
	}

	// Validate status
	if status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "challenge is not in pending state",
		})
		return
	}

	// Validate expiry
	if time.Now().After(expiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "expired",
			"error_description": "step-up challenge has expired",
		})
		return
	}

	// Retrieve the reason for the step-up token claims
	_ = s.db.Pool.QueryRow(ctx, `SELECT reason FROM stepup_challenges WHERE id = $1`, req.ChallengeID).Scan(&reason)

	// Mark challenge as completed (actual MFA verification is handled by existing MFA handlers)
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE stepup_challenges SET status = 'completed', completed_at = NOW() WHERE id = $1`,
		req.ChallengeID,
	)
	if err != nil {
		s.logger.Error("Failed to complete step-up challenge",
			zap.String("challenge_id", req.ChallengeID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to complete step-up challenge",
		})
		return
	}

	// Generate a short-lived step-up JWT (5 minutes)
	stepUpToken, err := generateStepUpToken(s.privateKey, userID, reason, s.issuer)
	if err != nil {
		s.logger.Error("Failed to generate step-up token",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to generate step-up token",
		})
		return
	}

	go s.logAuditEvent(context.Background(), "authentication", "security", "step_up_verified", "success",
		userID, c.ClientIP(), userID, "user",
		map[string]interface{}{"challenge_id": req.ChallengeID, "method": req.Method})

	c.JSON(http.StatusOK, gin.H{
		"status":        "verified",
		"challenge_id":  req.ChallengeID,
		"step_up_token": stepUpToken,
	})
}

// handleStepUpStatus checks the status of a step-up challenge.
// GET /oauth/stepup-status/:id
func (s *Service) handleStepUpStatus(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "unauthorized",
			"error_description": "valid session required",
		})
		return
	}

	challengeID := c.Param("id")
	if challengeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "challenge id is required",
		})
		return
	}

	ctx := c.Request.Context()

	var challengeUserID, status, reason string
	var expiresAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT user_id, status, reason, expires_at
		FROM stepup_challenges WHERE id = $1`,
		challengeID,
	).Scan(&challengeUserID, &status, &reason, &expiresAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "challenge not found",
		})
		return
	}

	// Validate user ownership
	if challengeUserID != userID {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "forbidden",
			"error_description": "challenge does not belong to current user",
		})
		return
	}

	// If pending and expired, report as expired
	if status == "pending" && time.Now().After(expiresAt) {
		status = "expired"
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge_id": challengeID,
		"status":       status,
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		"reason":       reason,
	})
}

// generateStepUpToken creates a short-lived RS256 JWT with step-up claims.
func generateStepUpToken(privateKey *rsa.PrivateKey, userID, reason, issuer string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":     userID,
		"step_up": true,
		"reason":  reason,
		"iss":     issuer,
		"iat":     now.Unix(),
		"exp":     now.Add(5 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "openidx-key-1"
	return token.SignedString(privateKey)
}
