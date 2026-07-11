// Package oauth - Step-up authentication handlers
// Provides mid-session re-authentication via step-up challenges, allowing
// applications to require additional verification for high-value operations.
package oauth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openidx/openidx/internal/common/orgctx"
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

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Insert step-up challenge with 5-minute expiry
	var challengeID string
	var expiresAt time.Time
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO stepup_challenges (id, user_id, session_id, reason, status, created_at, expires_at, org_id)
		VALUES (gen_random_uuid(), $1, $2, $3, 'pending', NOW(), NOW() + INTERVAL '5 minutes', $4)
		RETURNING id, expires_at`,
		userID, sessionID, req.Reason, org.ID,
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

	// Determine available MFA methods from the real enrollment tables via the
	// identity service (mfa_totp, mfa_sms, mfa_email_otp, mfa_push_devices,
	// mfa_webauthn). The previous lookup read user_mfa_methods, a view that only
	// legacy SQL files defined and the migration runner never creates, so it
	// errored on every call and each challenge advertised an empty method list.
	// A lookup failure still yields an empty list — never a skipped step-up —
	// because verification below independently requires a real factor check.
	availableMethods := []string{}
	if s.identityService != nil {
		enrolled, mErr := s.identityService.GetUserMFAMethods(ctx, userID)
		if mErr != nil {
			s.logger.Warn("Failed to look up MFA methods for step-up",
				zap.String("user_id", userID),
				zap.Error(mErr),
			)
		} else {
			for _, m := range []string{"totp", "sms", "email", "push", "webauthn"} {
				if enrolled[m] {
					availableMethods = append(availableMethods, m)
				}
			}
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

	// Log audit event in background with timeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logAuditEvent(ctx, "authentication", "security", "step_up_challenge_created", "success",
			userID, c.ClientIP(), userID, "user",
			map[string]interface{}{"challenge_id": challengeID, "reason": req.Reason})
	}()

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

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Look up the challenge
	var challengeUserID, challengeSessionID, status, reason string
	var expiresAt time.Time
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, session_id, status, expires_at
		FROM stepup_challenges WHERE id = $1 AND org_id = $2`,
		req.ChallengeID, org.ID,
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

	// The submitted factor MUST actually verify before the challenge is
	// completed and a step-up token issued. Previously this handler marked the
	// challenge completed and minted a signed step_up JWT without ever checking
	// req.Code — any authenticated session could rubber-stamp a step-up.
	if req.Method == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "method is required",
		})
		return
	}
	verified, verifyErr := s.verifyStepUpFactor(ctx, userID, req.Method, req.Code, c.ClientIP(), c.GetHeader("User-Agent"))
	if verifyErr != nil || !verified {
		// Sanitize request-derived values before logging so a CR/LF in the body
		// cannot forge or split log entries (CWE-117 log injection).
		errMsg := ""
		if verifyErr != nil {
			errMsg = sanitizeForLog(verifyErr.Error())
		}
		s.logger.Warn("Step-up verification failed",
			zap.String("user_id", sanitizeForLog(userID)),
			zap.String("challenge_id", sanitizeForLog(req.ChallengeID)),
			zap.String("method", sanitizeForLog(req.Method)),
			zap.String("error", errMsg),
		)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.logAuditEvent(ctx, "authentication", "security", "step_up_failed", "failure",
				userID, c.ClientIP(), userID, "user",
				map[string]interface{}{"challenge_id": req.ChallengeID, "method": req.Method})
		}()
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_mfa_code",
			"error_description": "verification failed",
		})
		return
	}

	// Retrieve the reason for the step-up token claims
	_ = s.db.Pool.QueryRow(ctx, `SELECT reason FROM stepup_challenges WHERE id = $1 AND org_id = $2`, req.ChallengeID, org.ID).Scan(&reason)

	// Mark challenge as completed now that the factor is verified
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE stepup_challenges SET status = 'completed', completed_at = NOW() WHERE id = $1 AND org_id = $2`,
		req.ChallengeID, org.ID,
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

	// Log audit event in background with timeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logAuditEvent(ctx, "authentication", "security", "step_up_verified", "success",
			userID, c.ClientIP(), userID, "user",
			map[string]interface{}{"challenge_id": req.ChallengeID, "method": req.Method})
	}()

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

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	var challengeUserID, status, reason string
	var expiresAt time.Time
	err = s.db.Pool.QueryRow(ctx, `
		SELECT user_id, status, reason, expires_at
		FROM stepup_challenges WHERE id = $1 AND org_id = $2`,
		challengeID, org.ID,
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

// sanitizeForLog strips CR/LF from user-supplied values before they are written
// to logs, preventing forged or split log entries (CWE-117 log injection).
func sanitizeForLog(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// verifyStepUpFactor verifies an MFA factor for step-up authentication using the
// same verifiers as the primary login MFA flow (handleMFAVerify). It returns true
// only when the supplied credential is genuinely valid for the user, so a step-up
// token is never issued without a real second-factor check.
func (s *Service) verifyStepUpFactor(ctx context.Context, userID, method, code, clientIP, userAgent string) (bool, error) {
	switch method {
	case "totp":
		return s.identityService.VerifyTOTP(ctx, userID, code)
	case "backup":
		return s.identityService.VerifyBackupCode(ctx, userID, code)
	case "bypass":
		return s.identityService.VerifyBypassCode(ctx, userID, code, clientIP, userAgent)
	case "sms", "email":
		if err := s.identityService.VerifyOTP(ctx, userID, method, code); err != nil {
			return false, err
		}
		return true, nil
	case "webauthn":
		user, err := s.identityService.GetUser(ctx, userID)
		if err != nil {
			return false, err
		}
		parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(code))
		if err != nil {
			return false, err
		}
		if _, err := s.identityService.FinishWebAuthnAuthentication(ctx, user.UserName, parsed); err != nil {
			return false, err
		}
		return true, nil
	case "push":
		challenge, err := s.identityService.GetPushMFAChallenge(ctx, code)
		if err != nil {
			return false, err
		}
		if challenge.UserID != userID || challenge.Status != "approved" || time.Now().After(challenge.ExpiresAt) {
			return false, nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported MFA method: %s", method)
	}
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
