package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
	"github.com/openidx/openidx/internal/identity"
)

// INLINE ENROLMENT: A SIGN-IN THE POLICY REFUSES FOR WANT OF A FACTOR ADDS ONE.
//
// evaluateMFA answers EnrollmentRequired when a policy requires a method the
// person has not added and the time to add one is over, and for an external
// user with no strong factor. Both used to end the sign-in with a 403 the
// person could do nothing about: "ask an administrator for a bypass code",
// "ask your sponsor for a new invitation". The first factor has just been
// proven, though, so with MFA_INLINE_ENROLLMENT (default true) the login opens
// an ENROL session instead: the page sets up an authenticator app or a passkey
// against it, and the code is issued once that factor is stored, exactly as
// after a verified second factor.
//
// The enrol session lives under its own Redis prefix, so none of the
// challenge endpoints (/oauth/mfa-verify and friends) can consume it, and the
// challenge session cannot be fed to the enrol endpoints. It is pinned to the
// methods the evaluation allows, single use (claimed with GETDEL at finish),
// bounded in attempts, and five minutes long. Email and SMS codes are never
// offered here: the policy's own refusal is about those not being enough, and
// an external user is held to strong factors (externalid D4).

const (
	mfaEnrollSessionPrefix = "mfa_enroll_session:"
	mfaEnrollSessionTTL    = 5 * time.Minute
	// mfaEnrollMaxAttempts bounds wrong codes and restarted ceremonies.
	mfaEnrollMaxAttempts = 5

	// ctxEnrollBackupCodes carries the backup codes minted with an inline
	// enrolment to the response that issues the code.
	ctxEnrollBackupCodes = "mfa_enroll_backup_codes"
)

// inlineEnrollableMethods are the factors the login page can set up itself.
var inlineEnrollableMethods = []string{"totp", "webauthn"}

// mfaEnrollSessionInternal are the session fields that are not part of the
// pending authorization request.
var mfaEnrollSessionInternal = map[string]bool{
	"user_id": true, "mode": true, "allowed_methods": true, "auth_method": true,
	"attempts": true, "totp_secret": true, "user_type": true,
	"risk_score": true, "fingerprint": true, "location": true,
}

// inlineEnrollmentEnabled reads MFA_INLINE_ENROLLMENT.
func (s *Service) inlineEnrollmentEnabled() bool {
	return s.config != nil && s.config.MFAInlineEnrollment
}

// inlineEnrollMethods is the list an enrol session offers: what the policy
// requires (any strong-enough factor when it names none), held to what the
// page can enrol, and for an external user to externalid.FactorAllowed.
func inlineEnrollMethods(ev mfaEvaluation, userType string) []string {
	required := ev.RequiredMethods
	if len(required) == 0 {
		required = inlineEnrollableMethods
	}
	out := []string{}
	for _, m := range required {
		if !hasMethod(inlineEnrollableMethods, m) || hasMethod(out, m) {
			continue
		}
		if ev.External && !externalid.FactorAllowed(externalid.TypeExternal, m) {
			continue
		}
		if userType != "" && !externalid.FactorAllowed(userType, m) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// offerInlineEnrollment opens an enrol session for a sign-in evaluateMFA
// refused with EnrollmentRequired. ok is false when the flag is off, nothing
// the policy requires can be enrolled here, or the session could not be
// stored; the caller then refuses as before. authMethod is the first factor's
// amr value: "pwd" or "fed".
func (s *Service) offerInlineEnrollment(ctx context.Context, user *identity.User, oauthParams map[string]string, ev mfaEvaluation, authMethod string) (string, []string, bool) {
	if !ev.EnrollmentRequired || user == nil || oauthParams == nil || !s.inlineEnrollmentEnabled() {
		return "", nil, false
	}
	methods := inlineEnrollMethods(ev, user.UserType)
	if len(methods) == 0 {
		return "", nil, false
	}
	data := map[string]string{}
	for k, v := range oauthParams {
		data[k] = v
	}
	data["user_id"] = user.ID
	data["user_type"] = user.UserType
	data["mode"] = "enroll"
	data["allowed_methods"] = strings.Join(methods, ",")
	data["auth_method"] = authMethod
	data["attempts"] = "0"
	payload, err := json.Marshal(data)
	if err != nil {
		return "", nil, false
	}
	id := GenerateRandomToken(32)
	if err := s.redis.Client.Set(ctx, mfaEnrollSessionPrefix+id, string(payload), mfaEnrollSessionTTL).Err(); err != nil {
		s.logger.Error("could not open the MFA enrolment session", zap.Error(err))
		return "", nil, false
	}
	s.logAuditEvent(ctx, "authentication", "security", "mfa_inline_enrollment_offered", "success",
		user.ID, "", user.ID, "user", map[string]interface{}{"methods": methods, "via": authMethod})
	return id, methods, true
}

// loadEnrollSession reads (without claiming) an enrol session. It answers the
// request itself on failure.
func (s *Service) loadEnrollSession(c *gin.Context, id, method string) (map[string]string, bool) {
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "enroll_session is required"})
		return nil, false
	}
	raw, err := s.redis.Client.Get(c.Request.Context(), mfaEnrollSessionPrefix+id).Result()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid or expired enrolment session"})
		return nil, false
	}
	return s.checkEnrollSession(c, id, raw, method)
}

func (s *Service) checkEnrollSession(c *gin.Context, id, raw, method string) (map[string]string, bool) {
	var data map[string]string
	if err := json.Unmarshal([]byte(raw), &data); err != nil || data["mode"] != "enroll" || data["user_id"] == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid or expired enrolment session"})
		return nil, false
	}
	if !hasMethod(allowedMFAMethods(data), method) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "this sign-in cannot enrol " + method})
		return nil, false
	}
	if n, _ := strconv.Atoi(data["attempts"]); n >= mfaEnrollMaxAttempts {
		s.redis.Client.Del(c.Request.Context(), mfaEnrollSessionPrefix+id)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too_many_attempts", "error_description": "too many attempts; sign in again"})
		return nil, false
	}
	return data, true
}

// saveEnrollSession writes the session back with attempts bumped by bump,
// keeping what is left of its lifetime.
func (s *Service) saveEnrollSession(ctx context.Context, id string, data map[string]string, bump int) {
	n, _ := strconv.Atoi(data["attempts"])
	data["attempts"] = strconv.Itoa(n + bump)
	ttl, err := s.redis.Client.TTL(ctx, mfaEnrollSessionPrefix+id).Result()
	if err != nil || ttl <= 0 {
		ttl = mfaEnrollSessionTTL
	}
	if payload, err := json.Marshal(data); err == nil {
		s.redis.Client.Set(ctx, mfaEnrollSessionPrefix+id, string(payload), ttl)
	}
}

// claimEnrollSession takes the session out of Redis (GETDEL), so that only
// one finish can complete it. A failed finish puts it back with one more
// attempt counted.
func (s *Service) claimEnrollSession(c *gin.Context, id, method string) (map[string]string, bool) {
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "enroll_session is required"})
		return nil, false
	}
	ctx := c.Request.Context()
	ttl, _ := s.redis.Client.TTL(ctx, mfaEnrollSessionPrefix+id).Result()
	raw, err := s.redis.Client.GetDel(ctx, mfaEnrollSessionPrefix+id).Result()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid or expired enrolment session"})
		return nil, false
	}
	data, ok := s.checkEnrollSession(c, id, raw, method)
	if ok {
		if ttl <= 0 {
			ttl = mfaEnrollSessionTTL
		}
		data["__ttl"] = strconv.FormatInt(int64(ttl/time.Second), 10)
	}
	return data, ok
}

// releaseEnrollSession restores a claimed session after a failed finish.
func (s *Service) releaseEnrollSession(ctx context.Context, id string, data map[string]string) {
	secs, _ := strconv.Atoi(data["__ttl"])
	delete(data, "__ttl")
	n, _ := strconv.Atoi(data["attempts"])
	data["attempts"] = strconv.Itoa(n + 1)
	if n+1 >= mfaEnrollMaxAttempts || secs <= 0 {
		return
	}
	if payload, err := json.Marshal(data); err == nil {
		s.redis.Client.Set(ctx, mfaEnrollSessionPrefix+id, string(payload), time.Duration(secs)*time.Second)
	}
}

// handleMFAEnrollTOTPBegin: POST /oauth/mfa/enroll/totp/begin {enroll_session}.
// Mints a secret, pins it into the session, and returns the QR URL.
func (s *Service) handleMFAEnrollTOTPBegin(c *gin.Context) {
	var req struct {
		EnrollSession string `json:"enroll_session"`
	}
	_ = c.ShouldBindJSON(&req)
	data, ok := s.loadEnrollSession(c, req.EnrollSession, "totp")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	enr, err := s.identityService.GenerateTOTPSecret(ctx, data["user_id"])
	if err != nil {
		s.logger.Error("inline enrolment: could not mint a TOTP secret", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	data["totp_secret"] = enr.Secret
	s.saveEnrollSession(ctx, req.EnrollSession, data, 1)
	c.JSON(http.StatusOK, gin.H{"qr_code_url": enr.QRCodeURL, "manual_key": enr.ManualKey})
}

// handleMFAEnrollTOTPFinish: POST /oauth/mfa/enroll/totp/finish
// {enroll_session, code}. Stores the factor and completes the sign-in.
func (s *Service) handleMFAEnrollTOTPFinish(c *gin.Context) {
	var req struct {
		EnrollSession string `json:"enroll_session"`
		Code          string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "enroll_session and code are required"})
		return
	}
	data, ok := s.claimEnrollSession(c, req.EnrollSession, "totp")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := data["user_id"]
	if data["totp_secret"] == "" {
		s.releaseEnrollSession(ctx, req.EnrollSession, data)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "start the authenticator setup first"})
		return
	}
	if err := s.identityService.EnrollTOTP(identity.ContextWithActorID(ctx, userID), userID, data["totp_secret"], strings.TrimSpace(req.Code)); err != nil {
		s.releaseEnrollSession(ctx, req.EnrollSession, data)
		s.logAuditEvent(ctx, "authentication", "security", "mfa_inline_enrollment", "failure",
			userID, c.ClientIP(), userID, "user", map[string]interface{}{"method": "totp", "reason": "invalid_code"})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_mfa_code", "error_description": "The code does not match. Check the authenticator app's clock and try again."})
		return
	}
	s.completeInlineEnrollment(c, data, "totp")
}

// handleMFAEnrollWebAuthnBegin: POST /oauth/mfa/enroll/webauthn/begin
// {enroll_session}. Returns the credential creation options.
func (s *Service) handleMFAEnrollWebAuthnBegin(c *gin.Context) {
	var req struct {
		EnrollSession string `json:"enroll_session"`
	}
	_ = c.ShouldBindJSON(&req)
	data, ok := s.loadEnrollSession(c, req.EnrollSession, "webauthn")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	options, err := s.identityService.BeginWebAuthnRegistration(ctx, data["user_id"])
	if err != nil {
		s.logger.Error("inline enrolment: could not begin passkey registration", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "could not start the passkey setup"})
		return
	}
	s.saveEnrollSession(ctx, req.EnrollSession, data, 1)
	c.JSON(http.StatusOK, options)
}

// handleMFAEnrollWebAuthnFinish: POST /oauth/mfa/enroll/webauthn/finish
// {enroll_session, credential, name}. Stores the passkey and completes.
func (s *Service) handleMFAEnrollWebAuthnFinish(c *gin.Context) {
	var req struct {
		EnrollSession string          `json:"enroll_session"`
		Credential    json.RawMessage `json:"credential"`
		Name          string          `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Credential) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "enroll_session and credential are required"})
		return
	}
	data, ok := s.claimEnrollSession(c, req.EnrollSession, "webauthn")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := data["user_id"]
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(string(req.Credential)))
	if err == nil {
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = "Passkey"
		}
		_, err = s.identityService.FinishWebAuthnRegistration(identity.ContextWithActorID(ctx, userID), userID, name, parsed)
	}
	if err != nil {
		s.releaseEnrollSession(ctx, req.EnrollSession, data)
		s.logAuditEvent(ctx, "authentication", "security", "mfa_inline_enrollment", "failure",
			userID, c.ClientIP(), userID, "user", map[string]interface{}{"method": "webauthn", "reason": "invalid_credential"})
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "the passkey could not be registered"})
		return
	}
	s.completeInlineEnrollment(c, data, "webauthn")
}

// completeInlineEnrollment finishes the sign-in after the factor is stored:
// backup codes, an external account waiting for its factor activated, a
// session stamped with the first factor plus mfa, and the code issued.
func (s *Service) completeInlineEnrollment(c *gin.Context, data map[string]string, method string) {
	ctx := c.Request.Context()
	userID := data["user_id"]
	clientIP := c.ClientIP()
	actorCtx := identity.ContextWithActorID(ctx, userID)

	codes, err := s.identityService.GenerateBackupCodes(actorCtx, userID, 10)
	if err != nil {
		s.logger.Warn("inline enrolment: backup codes not generated", zap.Error(err))
	}
	if data["user_type"] == externalid.TypeExternal && s.db != nil {
		if org, oerr := orgctx.From(ctx); oerr == nil {
			tag, uerr := s.db.Pool.Exec(ctx, `
				UPDATE users SET account_status = 'active', enabled = true, status_changed_at = NOW(), updated_at = NOW()
				 WHERE id = $1::uuid AND org_id = $2 AND user_type = 'external' AND account_status = 'pending_mfa'`, userID, org.ID)
			if uerr != nil {
				s.logger.Error("inline enrolment: could not activate the external account", zap.Error(uerr))
			} else if tag.RowsAffected() > 0 {
				s.logAuditEvent(ctx, "identity", "external_access", "external.activated", "success",
					userID, clientIP, userID, "user", map[string]interface{}{"factor": method, "via": "inline_enrollment"})
			}
		}
	}
	s.logAuditEvent(ctx, "authentication", "security", "mfa_inline_enrollment", "success",
		userID, clientIP, userID, "user", map[string]interface{}{"method": method})

	oauthParams := map[string]string{}
	for k, v := range data {
		if !mfaEnrollSessionInternal[k] && !strings.HasPrefix(k, "__") {
			oauthParams[k] = v
		}
	}
	firstFactor := data["auth_method"]
	if firstFactor != "fed" {
		firstFactor = "pwd"
	}
	session, serr := s.identityService.CreateSession(ctx, userID, oauthParams["client_id"], clientIP, c.GetHeader("User-Agent"), 24*time.Hour)
	if serr != nil {
		s.logger.Warn("inline enrolment: session not created", zap.Error(serr))
	}
	if session != nil {
		oauthParams["session_id"] = session.ID
		s.recordSessionAuthMethods(ctx, session.ID, []string{firstFactor, "mfa"})
	}
	if len(codes) > 0 {
		c.Set(ctxEnrollBackupCodes, codes)
	}
	s.issueAuthorizationCode(c, oauthParams, userID)
}
