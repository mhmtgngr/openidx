package oauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// A SIGN-IN THROUGH AN EXTERNAL IDENTITY ASKS THE PASSWORD LOGIN'S QUESTION.
//
// A social provider (GET /oauth/social/callback) and an enterprise identity
// provider (GET /oauth/callback, reached from the console's SSO buttons through
// /oauth/authorize?idp_hint=) each prove who the person is at that provider,
// which is one factor. Neither asked evaluateMFA: a user with a second factor
// enrolled, a user an MFA policy covers, a user whose grace period to add a
// required method was over, and a sign-in the risk engine would deny were all
// issued a code, and the social callback without a pending request answered
// with tokens. So anyone who controlled the external account -- a phished
// Google login, a provider account registered to the victim's address and
// linked earlier -- had the whole account, second factor or not.
//
// Both now ask evaluateMFA, the password login's decision, as the sign-in link
// does (magicLinkNeedsMore). Unlike the link, an external sign-in can finish
// the challenge: it may be the person's only way in, so a user who must give a
// second factor is handed to the login page with an MFA session, the same one
// the password step opens, pinned to the methods the evaluation offered.
// POST /oauth/mfa-verify then completes the pending request exactly as after a
// password. Refusals go to the login page with the reason in ?error=.

// External sign-in refusals, as the login page reads them from ?error=.
const (
	externalErrEnrollmentRequired = "sso_mfa_enrollment_required"
	externalErrHighRisk           = "sso_high_risk_login"
	externalErrUnavailable        = "sso_sign_in_failed"
)

// externalSignInNeedsMore decides whether a sign-in through an external
// identity may issue a code for userID now. It returns true when it has
// answered the request itself: with a redirect to the login page's
// second-factor step, or with a refusal. oauthParams is the pending
// authorization request, which the MFA session carries to its completion; nil
// means there is none (the social callback's token fallback), and then a user
// who needs more is refused with 403. loginSession, when the request has one,
// goes back with a refusal so the login page can continue the same pending
// request, and is closed when the second-factor step takes over. via names the
// path in the audit trail.
func (s *Service) externalSignInNeedsMore(c *gin.Context, userID string, oauthParams map[string]string, loginSession, via string) bool {
	ctx := c.Request.Context()
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	refuse := func(reason string) bool {
		s.logAuditEvent(ctx, "authentication", "security", "external_sign_in", "failure",
			userID, clientIP, userID, "user", map[string]interface{}{"via": via, "reason": reason})
		if oauthParams == nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             reason,
				"error_description": "This account cannot finish this sign-in here. Sign in from the login page.",
			})
			return true
		}
		q := url.Values{"error": {reason}}
		if loginSession != "" {
			q.Set("login_session", loginSession)
		}
		c.Redirect(http.StatusFound, "/login?"+q.Encode())
		return true
	}

	user, err := s.identityService.GetUser(ctx, userID)
	if err != nil || user == nil {
		s.logger.Warn("External sign-in: the user could not be loaded; refusing", zap.Error(err))
		return refuse(externalErrUnavailable)
	}

	var fingerprint string
	var deviceTrusted bool
	if s.riskService != nil {
		fingerprint = s.riskService.ComputeDeviceFingerprint(clientIP, userAgent)
		deviceTrusted = s.riskService.IsDeviceTrusted(ctx, userID, fingerprint)
	}
	ev := s.evaluateMFA(ctx, user, clientIP, userAgent, fingerprint, "", deviceTrusted, 0, nil)
	if ev.GraceBegan {
		s.auditMFAGrace(ctx, userID, clientIP, "mfa_grace_started", "success", ev)
	}
	if ev.EnrollmentDue != nil && oauthParams != nil {
		if due, err := json.Marshal(ev.EnrollmentDue); err == nil {
			oauthParams[paramMFAEnrollmentDue] = string(due)
		}
	}

	switch {
	case ev.Challenge:
		if oauthParams == nil {
			return refuse("mfa_required")
		}
		mfaSession, err := s.createMFASession(ctx, userID, oauthParams, ev.RiskScore, fingerprint, "", ev.Methods)
		if err != nil {
			s.logger.Error("External sign-in: could not open the MFA session; refusing", zap.Error(err))
			return refuse(externalErrUnavailable)
		}
		if loginSession != "" {
			s.redis.Client.Del(ctx, "login_session:"+loginSession)
		}
		s.logAuditEvent(ctx, "authentication", "security", "external_sign_in", "mfa_required",
			userID, clientIP, userID, "user", map[string]interface{}{"via": via, "methods": ev.Methods})
		q := url.Values{
			"mfa_session": {mfaSession},
			"mfa_methods": {strings.Join(ev.Methods, ",")},
		}
		if !ev.BrowserTrusted {
			q.Set("can_trust_browser", "1")
		}
		c.Redirect(http.StatusFound, "/login?"+q.Encode())
		return true
	case ev.EnrollmentRequired:
		s.auditMFAGrace(ctx, userID, clientIP, "mfa_enrollment_required", "failure", ev)
		return refuse(externalErrEnrollmentRequired)
	case ev.DenyAccess:
		return refuse(externalErrHighRisk)
	}
	return false
}
