package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/identity"
)

// The server-rendered login page (renderLoginPage → POST /oauth/authorize/callback)
// is what every PUBLIC OIDC client gets in a browser: BrowZer, the mobile app,
// the desktop client. It used to authenticate a password and issue an
// authorization code with no second-factor step at all, so a user with TOTP or
// push enrolled could skip MFA entirely by signing in through it — while the
// JSON path the console SPA drives enforced MFA properly.
//
// This file completes that path: the same mfaEvaluation both flows share now
// gates it, and the challenge is finished on server-rendered pages that need no
// JavaScript (the login page's CSP is script-src 'self', and a push wait screen
// polls with a meta refresh).

// hostedMFAMethods narrows the offerable factors to the ones the server-rendered
// page can actually complete. WebAuthn needs a browser API call (no JS here),
// and anything else unknown is not completable — leaving them out matters,
// because a login that cannot finish its challenge must be refused rather than
// let through.
func hostedMFAMethods(methods []string) []string {
	out := []string{}
	for _, m := range methods {
		switch m {
		case "totp", "push", "sms", "email", "backup", "bypass":
			out = append(out, m)
		}
	}
	return out
}

// codeEntryMethod reports whether a factor is completed by typing a code.
func codeEntryMethod(m string) bool {
	switch m {
	case "totp", "sms", "email", "backup", "bypass":
		return true
	}
	return false
}

var hostedMFAMethodLabels = map[string]string{
	"totp":   "Authenticator app",
	"push":   "Push notification",
	"sms":    "Text message",
	"email":  "Email code",
	"backup": "Backup code",
	"bypass": "Bypass code",
}

// createMFASession stashes the partially-authenticated login in Redis exactly
// the way the JSON path does, so /oauth/mfa-verify, /oauth/mfa-send-otp and the
// hosted pages below all read the same session shape.
func (s *Service) createMFASession(ctx context.Context, userID string, oauthParams map[string]string, riskScore int, fingerprint, location string, methods []string) (string, error) {
	mfaSession := GenerateRandomToken(32)
	mfaData := map[string]string{
		"user_id":     userID,
		"risk_score":  fmt.Sprintf("%d", riskScore),
		"fingerprint": fingerprint,
		"location":    location,
		// The factors this challenge may be completed with, decided ONCE by the
		// risk evaluation. Without pinning them here, a later step could
		// re-derive them from enrollment alone and quietly drop a restriction
		// the risk policy imposed (e.g. "this login needs a phishing-resistant
		// factor"), letting the user finish with a weaker one instead.
		"allowed_methods": strings.Join(methods, ","),
	}
	for k, v := range oauthParams {
		mfaData[k] = v
	}
	payload, err := json.Marshal(mfaData)
	if err != nil {
		return "", err
	}
	if err := s.redis.Client.Set(ctx, "mfa_session:"+mfaSession, string(payload), 5*time.Minute).Err(); err != nil {
		return "", err
	}
	return mfaSession, nil
}

// loadMFASession reads a hosted-flow MFA session back out of Redis.
func (s *Service) loadMFASession(ctx context.Context, mfaSession string) (map[string]string, bool) {
	if mfaSession == "" {
		return nil, false
	}
	raw, err := s.redis.Client.Get(ctx, "mfa_session:"+mfaSession).Result()
	if err != nil {
		return nil, false
	}
	var data map[string]string
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, false
	}
	if data["user_id"] == "" {
		return nil, false
	}
	return data, true
}

// beginHostedMFA is the branch handleAuthorizeCallback takes when the shared
// evaluation says this login needs a second factor.
func (s *Service) beginHostedMFA(c *gin.Context, user *identity.User, oauthParams map[string]string, loginSession string, ev mfaEvaluation, fingerprint, location string) {
	methods := hostedMFAMethods(ev.Methods)
	if len(methods) == 0 {
		// Enrolled only in factors this page cannot complete (WebAuthn today).
		// Fail closed: never issue a code because the challenge is inconvenient.
		s.logger.Warn("hosted login blocked: MFA required but no completable factor",
			zap.String("user_id", user.ID),
			zap.Strings("enrolled_methods", ev.Methods))
		s.renderLoginPage(c, loginSession,
			"This account requires a second factor that cannot be completed here. Sign in through the OpenIDX console instead.")
		return
	}

	mfaSession, err := s.createMFASession(c.Request.Context(), user.ID, oauthParams, ev.RiskScore, fingerprint, location, ev.Methods)
	if err != nil {
		s.logger.Error("failed to create hosted MFA session", zap.Error(err))
		s.renderLoginPage(c, loginSession, "Could not start verification. Please try again.")
		return
	}
	// The password step is done — retire the login session.
	s.redis.Client.Del(c.Request.Context(), "login_session:"+loginSession)

	s.renderMFAPage(c, mfaSession, methods, methods[0], "", "")
}

// renderMFAPage draws the server-rendered second-factor step, branded like the
// login page it follows. No JavaScript: code factors submit a form, push starts
// a challenge and then waits on a meta-refresh page.
func (s *Service) renderMFAPage(c *gin.Context, mfaSession string, methods []string, selected, errorMsg, notice string) {
	if len(methods) == 0 {
		// Nothing left this challenge can be completed with (every offered
		// factor was removed mid-flow). Refuse rather than index into an empty
		// list — and never fall through to issuing a code.
		s.renderExpiredMFA(c)
		return
	}
	b := s.loadLoginBranding(c.Request.Context())

	if selected == "" || !containsString(methods, selected) {
		selected = methods[0]
	}

	msgHTML := ""
	if errorMsg != "" {
		msgHTML = `<div style="color:#ef4444;background:#fef2f2;border:1px solid #fecaca;padding:12px;border-radius:8px;margin-bottom:16px;font-size:14px">` + html.EscapeString(errorMsg) + `</div>`
	} else if notice != "" {
		msgHTML = `<div style="color:#166534;background:#f0fdf4;border:1px solid #bbf7d0;padding:12px;border-radius:8px;margin-bottom:16px;font-size:14px">` + html.EscapeString(notice) + `</div>`
	}

	var body strings.Builder
	if codeEntryMethod(selected) {
		hint := "Enter the 6-digit code from your authenticator app."
		switch selected {
		case "sms":
			hint = "Enter the code we sent to your phone."
		case "email":
			hint = "Enter the code we sent to your email."
		case "backup":
			hint = "Enter one of your backup codes."
		case "bypass":
			hint = "Enter the bypass code your administrator gave you."
		}
		body.WriteString(`<p class="sub">` + html.EscapeString(hint) + `</p>`)
		body.WriteString(`<form method="POST" action="/oauth/authorize/mfa">`)
		body.WriteString(`<input type="hidden" name="mfa_session" value="` + html.EscapeString(mfaSession) + `">`)
		body.WriteString(`<input type="hidden" name="method" value="` + html.EscapeString(selected) + `">`)
		body.WriteString(`<div class="field"><label>Verification code</label><input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus></div>`)
		body.WriteString(trustBrowserFieldHTML())
		body.WriteString(`<button type="submit">Verify</button></form>`)
		if selected == "sms" || selected == "email" {
			body.WriteString(`<form method="POST" action="/oauth/authorize/mfa/send" style="margin-top:10px">`)
			body.WriteString(`<input type="hidden" name="mfa_session" value="` + html.EscapeString(mfaSession) + `">`)
			body.WriteString(`<input type="hidden" name="method" value="` + html.EscapeString(selected) + `">`)
			body.WriteString(`<button type="submit" style="background:transparent;color:#94a3b8;border:1px solid #334155">Send a code</button></form>`)
		}
	} else { // push
		body.WriteString(`<p class="sub">Approve the sign-in on your enrolled device.</p>`)
		body.WriteString(`<form method="POST" action="/oauth/authorize/mfa/push">`)
		body.WriteString(`<input type="hidden" name="mfa_session" value="` + html.EscapeString(mfaSession) + `">`)
		body.WriteString(trustBrowserFieldHTML())
		body.WriteString(`<button type="submit">Send push notification</button></form>`)
	}

	// Other factors the user can switch to.
	var alt strings.Builder
	for _, m := range methods {
		if m == selected {
			continue
		}
		alt.WriteString(`<form method="POST" action="/oauth/authorize/mfa/method" style="display:inline">`)
		alt.WriteString(`<input type="hidden" name="mfa_session" value="` + html.EscapeString(mfaSession) + `">`)
		alt.WriteString(`<input type="hidden" name="method" value="` + html.EscapeString(m) + `">`)
		alt.WriteString(`<button type="submit" style="background:transparent;color:#94a3b8;border:none;padding:4px;width:auto;font-size:13px;text-decoration:underline">` +
			html.EscapeString(hostedMFAMethodLabels[m]) + `</button></form>`)
	}
	altHTML := ""
	if alt.Len() > 0 {
		altHTML = `<div style="margin-top:16px;font-size:13px;color:#64748b">Use another method: ` + alt.String() + `</div>`
	}

	s.renderBrandedPage(c, b, "Two-step verification", msgHTML+body.String()+altHTML, "")
}

func trustBrowserFieldHTML() string {
	return `<label style="display:flex;gap:8px;align-items:center;font-size:13px;margin-bottom:16px;color:#94a3b8">` +
		`<input type="checkbox" name="trust_browser" value="1" style="width:auto">` +
		`Trust this browser for 30 days</label>`
}

// handleAuthorizeMFAMethod re-renders the challenge with a different factor.
func (s *Service) handleAuthorizeMFAMethod(c *gin.Context) {
	mfaSession := c.PostForm("mfa_session")
	data, ok := s.loadMFASession(c.Request.Context(), mfaSession)
	if !ok {
		s.renderExpiredMFA(c)
		return
	}
	methods := s.sessionMethods(c.Request.Context(), data)
	if len(methods) == 0 {
		s.renderExpiredMFA(c)
		return
	}
	// renderMFAPage falls back to methods[0] for anything not in the list, so a
	// forged method here can only pick among the factors this challenge offers.
	s.renderMFAPage(c, mfaSession, methods, c.PostForm("method"), "", "")
}

// handleAuthorizeMFASend sends an SMS/email OTP for the hosted flow.
func (s *Service) handleAuthorizeMFASend(c *gin.Context) {
	mfaSession := c.PostForm("mfa_session")
	method := c.PostForm("method")
	data, ok := s.loadMFASession(c.Request.Context(), mfaSession)
	if !ok {
		s.renderExpiredMFA(c)
		return
	}
	userID := data["user_id"]
	ctx := c.Request.Context()

	if !s.methodAllowed(ctx, data, method) {
		s.renderMFAPage(c, mfaSession, s.sessionMethods(ctx, data), "",
			"That verification method is not available for this sign-in.", "")
		return
	}

	var err error
	switch method {
	case "sms":
		_, err = s.identityService.CreateSMSChallenge(ctx, userID, c.ClientIP(), c.GetHeader("User-Agent"))
	case "email":
		_, err = s.identityService.CreateEmailOTPChallenge(ctx, userID, c.ClientIP(), c.GetHeader("User-Agent"))
	default:
		err = fmt.Errorf("unsupported method")
	}

	methods := s.sessionMethods(ctx, data)
	if err != nil {
		s.logger.Error("hosted MFA: failed to send OTP", zap.String("method", sanitizeForLog(method)), zap.Error(err))
		s.renderMFAPage(c, mfaSession, methods, method, "Could not send the code. Try another method.", "")
		return
	}
	s.renderMFAPage(c, mfaSession, methods, method, "", "We sent you a code.")
}

// handleAuthorizeMFA verifies a typed second factor and finishes the login.
func (s *Service) handleAuthorizeMFA(c *gin.Context) {
	mfaSession := c.PostForm("mfa_session")
	method := c.PostForm("method")
	code := c.PostForm("code")
	trustBrowser := c.PostForm("trust_browser") != ""

	data, ok := s.loadMFASession(c.Request.Context(), mfaSession)
	if !ok {
		s.renderExpiredMFA(c)
		return
	}
	if method == "" {
		method = "totp"
	}
	// A session pinned to one method (passwordless phone sign-in) must not be
	// completable with a different, weaker factor.
	if pinned := requiredMFAMethodFromSession(data); pinned != "" && pinned != method {
		s.renderMFAPage(c, mfaSession, s.sessionMethods(c.Request.Context(), data), pinned,
			"This sign-in must be completed with "+pinned+".", "")
		return
	}
	if !codeEntryMethod(method) || !s.methodAllowed(c.Request.Context(), data, method) {
		// The challenge only accepts a factor it offered: the risk policy may
		// have narrowed the list, and a posted method must not widen it again.
		s.renderMFAPage(c, mfaSession, s.sessionMethods(c.Request.Context(), data), "",
			"That verification method is not available for this sign-in.", "")
		return
	}

	userID := data["user_id"]
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	valid, verifyErr := s.verifyStepUpFactor(c.Request.Context(), userID, method, code, clientIP, userAgent)
	if verifyErr != nil || !valid {
		s.auditMFAResult(userID, clientIP, method, false, trustBrowser)
		s.renderMFAPage(c, mfaSession, s.sessionMethods(c.Request.Context(), data), method,
			"Invalid verification code.", "")
		return
	}

	s.completeHostedMFA(c, mfaSession, data, method, trustBrowser)
}

// handleAuthorizeMFAPush starts a push challenge and shows the waiting screen.
func (s *Service) handleAuthorizeMFAPush(c *gin.Context) {
	mfaSession := c.PostForm("mfa_session")
	trustBrowser := c.PostForm("trust_browser") != ""

	data, ok := s.loadMFASession(c.Request.Context(), mfaSession)
	if !ok {
		s.renderExpiredMFA(c)
		return
	}
	userID := data["user_id"]

	if !s.methodAllowed(c.Request.Context(), data, "push") {
		s.renderMFAPage(c, mfaSession, s.sessionMethods(c.Request.Context(), data), "",
			"That verification method is not available for this sign-in.", "")
		return
	}

	appName := ""
	if cid := data["client_id"]; cid != "" {
		if cl, err := s.GetClient(c.Request.Context(), cid); err == nil && cl != nil {
			appName = cl.Name
		}
	}
	challenge, err := s.identityService.CreatePushMFAChallenge(c.Request.Context(), &identity.PushMFAChallengeRequest{
		UserID:    userID,
		IPAddress: c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		AppName:   appName,
	})
	if err != nil {
		s.logger.Error("hosted MFA: failed to create push challenge", zap.Error(err))
		s.renderMFAPage(c, mfaSession, s.sessionMethods(c.Request.Context(), data), "push",
			"Could not send a push notification. Try another method.", "")
		return
	}

	s.renderPushWaitPage(c, mfaSession, challenge.ID, challenge.ChallengeCode, trustBrowser, "")
}

// handleAuthorizeMFAWait is the meta-refresh landing point while a push
// challenge is outstanding: it completes the login as soon as the challenge is
// approved, and never issues anything while it is pending, denied or expired.
func (s *Service) handleAuthorizeMFAWait(c *gin.Context) {
	mfaSession := c.Query("mfa_session")
	challengeID := c.Query("challenge_id")
	trustBrowser := c.Query("trust_browser") == "1"

	data, ok := s.loadMFASession(c.Request.Context(), mfaSession)
	if !ok {
		s.renderExpiredMFA(c)
		return
	}
	userID := data["user_id"]

	challenge, err := s.identityService.GetPushMFAChallenge(c.Request.Context(), challengeID)
	if err != nil || challenge == nil || challenge.UserID != userID {
		s.renderMFAPage(c, mfaSession, s.sessionMethods(c.Request.Context(), data), "push",
			"That approval request is no longer valid.", "")
		return
	}

	switch {
	case challenge.Status == "approved" && time.Now().Before(challenge.ExpiresAt):
		if !s.methodAllowed(c.Request.Context(), data, "push") {
			s.renderMFAPage(c, mfaSession, s.sessionMethods(c.Request.Context(), data), "",
				"That verification method is not available for this sign-in.", "")
			return
		}
		s.completeHostedMFA(c, mfaSession, data, "push", trustBrowser)
	case challenge.Status == "denied":
		s.renderMFAPage(c, mfaSession, s.sessionMethods(c.Request.Context(), data), "push",
			"The sign-in was denied on your device.", "")
	case time.Now().After(challenge.ExpiresAt):
		s.renderMFAPage(c, mfaSession, s.sessionMethods(c.Request.Context(), data), "push",
			"The approval request expired. Try again.", "")
	default:
		s.renderPushWaitPage(c, mfaSession, challengeID, challenge.ChallengeCode, trustBrowser, "")
	}
}

// renderPushWaitPage shows the number-match code and refreshes itself until the
// challenge resolves. Meta refresh keeps this working under script-src 'self'.
func (s *Service) renderPushWaitPage(c *gin.Context, mfaSession, challengeID, challengeCode string, trustBrowser bool, errorMsg string) {
	b := s.loadLoginBranding(c.Request.Context())

	q := url.Values{}
	q.Set("mfa_session", mfaSession)
	q.Set("challenge_id", challengeID)
	if trustBrowser {
		q.Set("trust_browser", "1")
	}
	refresh := `<meta http-equiv="refresh" content="3;url=/oauth/authorize/mfa/wait?` + html.EscapeString(q.Encode()) + `">`

	body := `<p class="sub">Approve the sign-in on your device.</p>`
	if challengeCode != "" {
		body += `<div style="font-size:44px;font-weight:700;letter-spacing:8px;color:#f8fafc;margin:16px 0">` +
			html.EscapeString(challengeCode) + `</div><p class="sub">Match this number on your device.</p>`
	}
	body += `<p class="sub" style="margin-top:16px">Waiting for approval…</p>`
	if errorMsg != "" {
		body = `<div style="color:#ef4444;margin-bottom:16px;font-size:14px">` + html.EscapeString(errorMsg) + `</div>` + body
	}

	s.renderBrandedPage(c, b, "Check your device", body, refresh)
}

func (s *Service) renderExpiredMFA(c *gin.Context) {
	b := s.loadLoginBranding(c.Request.Context())
	s.renderBrandedPage(c, b, "Sign-in expired",
		`<p class="sub">This sign-in attempt expired. Return to the application and start again.</p>`, "")
}

// completeHostedMFA finishes a verified hosted login: it consumes the MFA
// session, optionally trusts the browser, creates the session with pwd+mfa, and
// redirects to the client with a real authorization code.
func (s *Service) completeHostedMFA(c *gin.Context, mfaSession string, data map[string]string, method string, trustBrowser bool) {
	ctx := c.Request.Context()
	userID := data["user_id"]
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	s.redis.Client.Del(ctx, "mfa_session:"+mfaSession)
	s.auditMFAResult(userID, clientIP, method, true, trustBrowser)

	if trustBrowser {
		fingerprint := data["fingerprint"]
		if fingerprint == "" && s.riskService != nil {
			fingerprint = s.riskService.ComputeDeviceFingerprint(clientIP, userAgent)
		}
		if _, err := s.identityService.TrustBrowser(ctx, userID, fingerprint,
			parseBrowserNameFromUA(userAgent), clientIP, userAgent); err != nil {
			s.logger.Warn("hosted MFA: failed to trust browser", zap.Error(err))
		}
	}

	oauthParams := map[string]string{}
	for k, v := range data {
		switch k {
		case "user_id", "risk_score", "fingerprint", "location":
			continue
		}
		oauthParams[k] = v
	}

	if session, err := s.identityService.CreateSession(ctx, userID, oauthParams["client_id"], clientIP, userAgent, 24*time.Hour); err != nil {
		s.logger.Warn("hosted MFA: failed to create session", zap.Error(err))
	} else if session != nil {
		oauthParams["session_id"] = session.ID
		s.recordSessionAuthMethods(ctx, session.ID, []string{"pwd", "mfa"})
	}

	s.issueHostedAuthorizationCode(c, oauthParams, userID)
}

// issueHostedAuthorizationCode persists a code through the same store the token
// endpoint consumes and 302s the browser back to the client.
func (s *Service) issueHostedAuthorizationCode(c *gin.Context, oauthParams map[string]string, userID string) {
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
	if err := s.CreateAuthorizationCode(c.Request.Context(), authCode); err != nil {
		writeServerOrUnavailable(c, err)
		return
	}
	if sessionID := oauthParams["session_id"]; sessionID != "" {
		s.redis.Client.Set(c.Request.Context(), "authcode_session:"+code, sessionID, 5*time.Minute)
	}
	c.Redirect(302, authorizationRedirectURL(oauthParams["redirect_uri"], code, oauthParams["state"]))
}

// sessionMethods returns the factors this challenge may still be completed
// with: the set pinned when the challenge was created (the risk policy's
// verdict), intersected with what the user still has enrolled and with what a
// server-rendered page can actually complete. Re-deriving from enrollment alone
// would drop the risk restriction, so the pinned list is authoritative when it
// is present; a session created before this field existed falls back to
// enrollment.
func (s *Service) sessionMethods(ctx context.Context, data map[string]string) []string {
	return s.filterSessionMethods(s.enrolledMethods(ctx, data["user_id"]), data["allowed_methods"])
}

// filterSessionMethods intersects the pinned list with current enrollment and
// with what a server-rendered page can complete.
func (s *Service) filterSessionMethods(enrolled []string, allowedMethods string) []string {
	pinned := []string{}
	for _, m := range strings.Split(allowedMethods, ",") {
		if m = strings.TrimSpace(m); m != "" {
			pinned = append(pinned, m)
		}
	}
	if len(pinned) == 0 {
		return hostedMFAMethods(enrolled)
	}
	out := []string{}
	for _, m := range pinned {
		if containsString(enrolled, m) {
			out = append(out, m)
		}
	}
	return hostedMFAMethods(out)
}

// methodAllowed reports whether a caller-supplied method may complete this
// challenge. Every hosted step gates on it, so switching method, asking for an
// OTP or submitting a code cannot reach a factor the challenge never offered.
func (s *Service) methodAllowed(ctx context.Context, data map[string]string, method string) bool {
	return containsString(s.sessionMethods(ctx, data), method)
}

// enrolledMethods lists the primary and supplemental factors a user currently has.
func (s *Service) enrolledMethods(ctx context.Context, userID string) []string {
	methods := []string{}
	if s.identityService == nil || userID == "" {
		return methods
	}
	if st, _ := s.identityService.GetTOTPStatus(ctx, userID); st != nil && st.Enabled {
		methods = append(methods, "totp")
	}
	if devices, _ := s.identityService.GetPushDevices(ctx, userID); len(devices) > 0 {
		methods = append(methods, "push")
	}
	if sms, _ := s.identityService.GetSMSEnrollment(ctx, userID); sms != nil && sms.Verified && sms.Enabled {
		methods = append(methods, "sms")
	}
	if em, _ := s.identityService.GetEmailOTPEnrollment(ctx, userID); em != nil && em.Enabled {
		methods = append(methods, "email")
	}
	if n, _ := s.identityService.GetBackupCodeCount(ctx, userID); n > 0 {
		methods = append(methods, "backup")
	}
	if ok, _ := s.identityService.HasActiveBypassCode(ctx, userID); ok {
		methods = append(methods, "bypass")
	}
	return methods
}

func (s *Service) auditMFAResult(userID, clientIP, method string, ok, trustBrowser bool) {
	action, result := "mfa_failed", "failure"
	if ok {
		action, result = "mfa_verified", "success"
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logAuditEvent(ctx, "authentication", "security", action, result,
			userID, clientIP, userID, "user",
			map[string]interface{}{"method": method, "trust_browser": trustBrowser, "surface": "hosted_login"})
	}()
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
