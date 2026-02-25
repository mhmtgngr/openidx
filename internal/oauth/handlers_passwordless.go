// Package oauth - Passwordless authentication OAuth handlers
// Implements passkey, magic link, QR login, and MFA OTP delivery flows.
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"go.uber.org/zap"
)

// validUUIDPattern validates UUID format only (RFC 4122)
// Pattern matches: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx where x is hexadecimal digit
// This prevents Redis key injection by strictly limiting to UUID format
var validUUIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// isValidSessionID validates session token format to prevent Redis key injection attacks
// RESTRICTED TO UUID FORMAT ONLY for JWT session IDs to prevent injection attacks
func isValidSessionID(sessionID string) bool {
	// Strict UUID format validation (36 characters with hyphens in specific positions)
	// This prevents path traversal and injection attacks while allowing legitimate UUIDs
	if len(sessionID) != 36 {
		return false
	}
	return validUUIDPattern.MatchString(sessionID)
}

// handleMFASendOTP triggers SMS or Email OTP delivery during the login MFA flow.
// POST /oauth/mfa-send-otp
func (s *Service) handleMFASendOTP(c *gin.Context) {
	var req struct {
		MFASession string `json:"mfa_session"`
		Method     string `json:"method"` // "sms" or "email"
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}

	if req.MFASession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "mfa_session is required"})
		return
	}

	// CRITICAL: Validate mfa_session format to prevent Redis key injection
	if !isValidSessionID(req.MFASession) {
		s.logger.Warn("Invalid mfa_session format detected", zap.String("session", req.MFASession))
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid mfa_session format"})
		return
	}

	if req.Method != "sms" && req.Method != "email" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "method must be 'sms' or 'email'"})
		return
	}

	// Retrieve MFA session from Redis
	mfaDataJSON, err := s.redis.Client.Get(c.Request.Context(), "mfa_session:"+req.MFASession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired MFA session"})
		return
	}

	var mfaData map[string]string
	if err := json.Unmarshal([]byte(mfaDataJSON), &mfaData); err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": "failed to parse MFA session"})
		return
	}

	userID := mfaData["user_id"]
	if userID == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "MFA session missing user identity"})
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	ctx := c.Request.Context()

	switch req.Method {
	case "sms":
		_, err = s.identityService.CreateSMSChallenge(ctx, userID, clientIP, userAgent)
	case "email":
		_, err = s.identityService.CreateEmailOTPChallenge(ctx, userID, clientIP, userAgent)
	}

	if err != nil {
		s.logger.Error("Failed to send OTP", zap.String("method", req.Method), zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": "failed to send verification code"})
		return
	}

	go s.logAuditEvent(context.Background(), "authentication", "security", "mfa_otp_sent", "success",
		userID, clientIP, userID, "user",
		map[string]interface{}{"method": req.Method})

	c.JSON(200, gin.H{"message": fmt.Sprintf("Verification code sent via %s", req.Method)})
}

// handlePasskeyBegin starts passkey-first (discoverable credential) authentication.
// POST /oauth/passkey-begin
func (s *Service) handlePasskeyBegin(c *gin.Context) {
	var req struct {
		LoginSession string `json:"login_session"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}

	if req.LoginSession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "login_session is required"})
		return
	}

	// CRITICAL: Validate login_session format to prevent Redis key injection
	if !isValidSessionID(req.LoginSession) {
		s.logger.Warn("Invalid login_session format detected", zap.String("session", req.LoginSession))
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid login_session format"})
		return
	}

	ctx := c.Request.Context()

	// Validate login_session exists in Redis
	_, err := s.redis.Client.Get(ctx, "login_session:"+req.LoginSession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired login session"})
		return
	}

	// Begin discoverable (usernameless) WebAuthn authentication
	options, sessionData, err := s.identityService.BeginWebAuthnDiscoverableAuthentication(ctx)
	if err != nil {
		s.logger.Error("Failed to begin passkey authentication", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": "failed to initiate passkey authentication"})
		return
	}

	// Store the WebAuthn session data in Redis, keyed by login_session
	sessionDataJSON, err := json.Marshal(sessionData)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": "failed to store passkey session"})
		return
	}
	s.redis.Client.Set(ctx, "passkey_session:"+req.LoginSession, string(sessionDataJSON), 5*time.Minute)

	c.JSON(200, options)
}

// handlePasskeyFinish completes passkey-first authentication and issues an authorization code.
// POST /oauth/passkey-finish
func (s *Service) handlePasskeyFinish(c *gin.Context) {
	var req struct {
		LoginSession string          `json:"login_session"`
		Credential   json.RawMessage `json:"credential"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}

	if req.LoginSession == "" || len(req.Credential) == 0 {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "login_session and credential are required"})
		return
	}

	// CRITICAL: Validate login_session format to prevent Redis key injection
	if !isValidSessionID(req.LoginSession) {
		s.logger.Warn("Invalid login_session format in passkey finish")
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid login_session format"})
		return
	}

	ctx := c.Request.Context()

	// Retrieve login_session oauth params from Redis
	paramsJSON, err := s.redis.Client.Get(ctx, "login_session:"+req.LoginSession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired login session"})
		return
	}

	var oauthParams map[string]string
	if err := json.Unmarshal([]byte(paramsJSON), &oauthParams); err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": "failed to parse login session"})
		return
	}

	// Retrieve passkey session data from Redis
	sessionDataJSON, err := s.redis.Client.Get(ctx, "passkey_session:"+req.LoginSession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "passkey session expired or not found"})
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionDataJSON), &sessionData); err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": "failed to parse passkey session"})
		return
	}

	// Parse the credential assertion response body
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(string(req.Credential)))
	if err != nil {
		s.logger.Error("Failed to parse passkey credential", zap.Error(err))
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid passkey credential"})
		return
	}

	// Finish discoverable authentication — returns the authenticated user ID
	userID, err := s.identityService.FinishWebAuthnDiscoverableAuthentication(ctx, &sessionData, parsedResponse)
	if err != nil {
		s.logger.Error("Passkey authentication failed", zap.Error(err))
		c.JSON(401, gin.H{"error": "authentication_failed", "error_description": "passkey verification failed"})
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Create a session for this login
	session, sessionErr := s.identityService.CreateSession(ctx, userID, oauthParams["client_id"], clientIP, userAgent, 24*time.Hour)
	if sessionErr != nil {
		s.logger.Warn("Failed to create session during passkey login", zap.Error(sessionErr))
	}
	if session != nil {
		oauthParams["session_id"] = session.ID
	}

	// Clean up Redis keys
	s.redis.Client.Del(ctx, "login_session:"+req.LoginSession)
	s.redis.Client.Del(ctx, "passkey_session:"+req.LoginSession)

	go s.logAuditEvent(context.Background(), "authentication", "security", "passkey_login", "success",
		userID, clientIP, userID, "user",
		map[string]interface{}{"method": "passkey"})

	s.issueAuthorizationCode(c, oauthParams, userID)
}

// handleOAuthMagicLink requests a magic link for passwordless login.
// POST /oauth/magic-link
func (s *Service) handleOAuthMagicLink(c *gin.Context) {
	var req struct {
		Email        string `json:"email"`
		LoginSession string `json:"login_session"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}

	if req.Email == "" || req.LoginSession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "email and login_session are required"})
		return
	}

	ctx := c.Request.Context()

	// Validate login_session exists
	_, err := s.redis.Client.Get(ctx, "login_session:"+req.LoginSession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired login session"})
		return
	}

	// Rate limiting: max 3 magic link requests per email per 10 minutes
	rateLimitKey := "ml_rate:" + req.Email
	count, _ := s.redis.Client.Incr(ctx, rateLimitKey).Result()
	if count == 1 {
		s.redis.Client.Expire(ctx, rateLimitKey, 10*time.Minute)
	}
	if count > 3 {
		// Always return success to prevent email enumeration
		c.JSON(200, gin.H{"message": "If an account exists with that email, a magic link has been sent."})
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Build the redirect URL that the magic link will point to
	redirectURL := s.issuer + "/oauth/magic-link-verify?login_session=" + url.QueryEscape(req.LoginSession)

	magicLink, err := s.identityService.CreateMagicLink(ctx, req.Email, "login", redirectURL, clientIP, userAgent)
	if err != nil {
		// Log the error but return success to prevent email enumeration
		s.logger.Debug("Magic link creation failed (may be expected for unknown email)", zap.Error(err))
		c.JSON(200, gin.H{"message": "If an account exists with that email, a magic link has been sent."})
		return
	}

	// CRITICAL: NEVER log magic link tokens in production
	// Magic link tokens must NEVER be logged in production environments
	// This check enforces production safety regardless of config flag
	if s.config.DebugOTPsEnabled() && s.config.IsDevelopment() && magicLink.Token != "" {
		verifyURL := s.issuer + "/oauth/magic-link-verify?token=" + url.QueryEscape(magicLink.Token) + "&login_session=" + url.QueryEscape(req.LoginSession)
		s.logger.Info("DEBUG: Magic link verify URL", zap.String("url", verifyURL))
	}

	go s.logAuditEvent(context.Background(), "authentication", "security", "magic_link_sent", "success",
		"", clientIP, req.Email, "email",
		map[string]interface{}{"purpose": "login"})

	// Always return the same response regardless of whether the email was found
	c.JSON(200, gin.H{"message": "If an account exists with that email, a magic link has been sent."})
}

// handleMagicLinkVerify handles the browser redirect when the user clicks a magic link.
// GET /oauth/magic-link-verify
func (s *Service) handleMagicLinkVerify(c *gin.Context) {
	token := c.Query("token")
	loginSession := c.Query("login_session")

	if token == "" || loginSession == "" {
		c.Redirect(302, "/login?error=invalid_magic_link")
		return
	}

	// CRITICAL: Validate login_session format to prevent Redis key injection
	if !isValidSessionID(loginSession) {
		s.logger.Warn("Invalid login_session format in magic link verify")
		c.Redirect(302, "/login?error=invalid_magic_link")
		return
	}

	ctx := c.Request.Context()

	// Retrieve oauth params from login_session
	paramsJSON, err := s.redis.Client.Get(ctx, "login_session:"+loginSession).Result()
	if err != nil {
		c.Redirect(302, "/login?error=session_expired")
		return
	}

	var oauthParams map[string]string
	if err := json.Unmarshal([]byte(paramsJSON), &oauthParams); err != nil {
		c.Redirect(302, "/login?error=invalid_magic_link")
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Verify the magic link token
	userID, _, err := s.identityService.VerifyMagicLink(ctx, token, clientIP, userAgent)
	if err != nil {
		s.logger.Warn("Magic link verification failed", zap.Error(err))
		c.Redirect(302, "/login?error=invalid_magic_link")
		return
	}

	// Create a session for this login
	session, sessionErr := s.identityService.CreateSession(ctx, userID, oauthParams["client_id"], clientIP, userAgent, 24*time.Hour)
	if sessionErr != nil {
		s.logger.Warn("Failed to create session during magic link login", zap.Error(sessionErr))
	}
	if session != nil {
		oauthParams["session_id"] = session.ID
	}

	// Build the authorization code manually (since this is a redirect, not a JSON response)
	code := GenerateRandomToken(32)
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            oauthParams["client_id"],
		UserID:              userID,
		RedirectURI:         oauthParams["redirect_uri"],
		Scope:               oauthParams["scope"],
		State:               oauthParams["state"],
		Nonce:               oauthParams["nonce"],
		CodeChallenge:       oauthParams["code_challenge"],
		CodeChallengeMethod: oauthParams["code_challenge_method"],
	}

	if err := s.CreateAuthorizationCode(ctx, authCode); err != nil {
		s.logger.Error("Failed to create authorization code for magic link", zap.Error(err))
		c.Redirect(302, "/login?error=server_error")
		return
	}

	// Store session_id alongside the auth code (same pattern as issueAuthorizationCode)
	if sessionID := oauthParams["session_id"]; sessionID != "" {
		s.redis.Client.Set(ctx, "authcode_session:"+code, sessionID, 5*time.Minute)
	}

	// Clean up login session
	s.redis.Client.Del(ctx, "login_session:"+loginSession)

	// Build redirect URL with the authorization code
	redirectURL, err := url.Parse(oauthParams["redirect_uri"])
	if err != nil {
		c.Redirect(302, "/login?error=invalid_magic_link")
		return
	}
	query := redirectURL.Query()
	query.Set("code", code)
	if oauthParams["state"] != "" {
		query.Set("state", oauthParams["state"])
	}
	redirectURL.RawQuery = query.Encode()

	go s.logAuditEvent(context.Background(), "authentication", "security", "magic_link_login", "success",
		userID, clientIP, userID, "user",
		map[string]interface{}{"method": "magic_link"})

	c.Redirect(302, redirectURL.String())
}

// handleQRLoginCreate creates a QR login session for mobile-to-desktop authentication.
// POST /oauth/qr-login/create
func (s *Service) handleQRLoginCreate(c *gin.Context) {
	var req struct {
		LoginSession string `json:"login_session"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}

	if req.LoginSession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "login_session is required"})
		return
	}

	// CRITICAL: Validate login_session format to prevent Redis key injection
	if !isValidSessionID(req.LoginSession) {
		s.logger.Warn("Invalid login_session format detected", zap.String("session", req.LoginSession))
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid login_session format"})
		return
	}

	ctx := c.Request.Context()

	// Validate login_session exists
	_, err := s.redis.Client.Get(ctx, "login_session:"+req.LoginSession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired login session"})
		return
	}

	clientIP := c.ClientIP()

	browserInfo := map[string]interface{}{
		"login_session": req.LoginSession,
		"ip_address":    clientIP,
		"user_agent":    c.GetHeader("User-Agent"),
	}

	qrSession, err := s.identityService.CreateQRLoginSession(ctx, clientIP, browserInfo)
	if err != nil {
		s.logger.Error("Failed to create QR login session", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": "failed to create QR login session"})
		return
	}

	// Store mapping from QR session token back to the OAuth login session
	s.redis.Client.Set(ctx, "qr_oauth:"+qrSession.SessionToken, req.LoginSession, 5*time.Minute)

	qrContent := fmt.Sprintf("openidx://qr-login?session=%s", qrSession.SessionToken)

	c.JSON(200, gin.H{
		"session_token": qrSession.SessionToken,
		"qr_content":    qrContent,
		"expires_at":    qrSession.ExpiresAt,
	})
}

// handleQRLoginPoll polls the QR login session status and completes the login if approved.
// GET /oauth/qr-login/poll
func (s *Service) handleQRLoginPoll(c *gin.Context) {
	sessionToken := c.Query("session_token")
	loginSession := c.Query("login_session")

	if sessionToken == "" || loginSession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "session_token and login_session are required"})
		return
	}

	// CRITICAL: Validate session_token and login_session format to prevent Redis key injection
	if !isValidSessionID(sessionToken) {
		s.logger.Warn("Invalid session_token format in QR login poll")
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid session_token format"})
		return
	}
	if !isValidSessionID(loginSession) {
		s.logger.Warn("Invalid login_session format in QR login poll")
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid login_session format"})
		return
	}

	ctx := c.Request.Context()

	qrSession, err := s.identityService.GetQRLoginSession(ctx, sessionToken)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found", "error_description": "QR login session not found or expired"})
		return
	}

	// If not yet approved, return the current status
	if qrSession.Status != "approved" || qrSession.UserID == nil {
		c.JSON(200, gin.H{"status": qrSession.Status})
		return
	}

	userID := *qrSession.UserID

	// Retrieve OAuth params from the login session
	paramsJSON, err := s.redis.Client.Get(ctx, "login_session:"+loginSession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "login session expired"})
		return
	}

	var oauthParams map[string]string
	if err := json.Unmarshal([]byte(paramsJSON), &oauthParams); err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": "failed to parse login session"})
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Create a session for this login
	session, sessionErr := s.identityService.CreateSession(ctx, userID, oauthParams["client_id"], clientIP, userAgent, 24*time.Hour)
	if sessionErr != nil {
		s.logger.Warn("Failed to create session during QR login", zap.Error(sessionErr))
	}
	if session != nil {
		oauthParams["session_id"] = session.ID
	}

	// Clean up Redis keys
	s.redis.Client.Del(ctx, "login_session:"+loginSession)
	s.redis.Client.Del(ctx, "qr_oauth:"+sessionToken)

	go s.logAuditEvent(context.Background(), "authentication", "security", "qr_login", "success",
		userID, clientIP, userID, "user",
		map[string]interface{}{"method": "qr_code"})

	s.issueAuthorizationCode(c, oauthParams, userID)
}

// generateSecureHex generates a cryptographically secure random hex string.
// This is used internally for authorization codes in redirect-based flows.
func generateSecureHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
