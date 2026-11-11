package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/accessdecision"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/stepup"
)

// AUTHENTICATION CONTEXT CLASS: acr_values IN, acr OUT (OIDC Core §3.1.2.1, §2).
//
// A relying party asks for how strongly the person must have authenticated
// with acr_values, and reads what it got from the ID token's acr claim. The
// classes are ordered, each one implying the ones below it:
//
//	urn:openidx:pwd                 a first factor only (the floor, never asked for)
//	urn:openidx:mfa                 a second factor during this session
//	urn:openidx:mfa:fresh           a second factor within the step-up window
//	                                (STEPUP_MAX_AGE, or the console's reauth interval)
//	urn:openidx:phishing-resistant  a passkey / security key (amr "hwk")
//
// What a session achieved is read from the server's own record of it
// (sessions.auth_methods, sessions.mfa_verified_at), never from the request.
// When a request asks for more than the session has, the code is not minted:
// the person is challenged for a second factor first, restricted to a passkey
// for the phishing-resistant class.
//
// An application whose resource conditions say require_step_up asks for
// urn:openidx:mfa:fresh on every sign-in, whatever the client sent.
const (
	ACRPassword           = "urn:openidx:pwd"
	ACRMFA                = "urn:openidx:mfa"
	ACRMFAFresh           = "urn:openidx:mfa:fresh"
	ACRPhishingResistant  = "urn:openidx:phishing-resistant"
	paramACRValues        = "acr_values"
	errUnmetAuthnRequired = "unmet_authentication_requirements"
)

// acrValuesSupported is what discovery advertises, weakest first.
var acrValuesSupported = []string{ACRPassword, ACRMFA, ACRMFAFresh, ACRPhishingResistant}

// acrRank orders the classes. Unknown values rank zero and are ignored.
func acrRank(v string) int {
	switch v {
	case ACRPassword:
		return 1
	case ACRMFA:
		return 2
	case ACRMFAFresh:
		return 3
	case ACRPhishingResistant:
		return 4
	}
	return 0
}

// parseACRValues keeps the known classes of a space-separated acr_values, in
// the client's order. A class this server does not define is dropped rather
// than refused: OIDC makes acr_values a voluntary claim request.
func parseACRValues(raw string) []string {
	var out []string
	for _, v := range strings.Fields(raw) {
		if acrRank(v) > 0 {
			out = append(out, v)
		}
	}
	return out
}

// normalizedACRValues is the value to carry in the pending request: the known
// classes only, or "" when none was asked for.
func normalizedACRValues(raw string) string {
	return strings.Join(parseACRValues(raw), " ")
}

// sessionAssurance is what one login session proved.
type sessionAssurance struct {
	Methods       []string
	MFAVerifiedAt *time.Time
	Found         bool
}

// satisfies reports whether the session meets class at now, given the
// step-up window.
func (a sessionAssurance) satisfies(class string, now time.Time, window time.Duration) bool {
	if !a.Found {
		return false
	}
	has := func(m string) bool {
		for _, x := range a.Methods {
			if x == m {
				return true
			}
		}
		return false
	}
	switch class {
	case ACRPassword:
		return true
	case ACRMFA:
		return has("mfa")
	case ACRMFAFresh:
		return has("mfa") && a.MFAVerifiedAt != nil && now.Sub(*a.MFAVerifiedAt) <= window
	case ACRPhishingResistant:
		return has("mfa") && has("hwk")
	}
	return false
}

// highest is the acr claim: the strongest class the session satisfies, with
// urn:openidx:pwd as the floor of any session at all.
func (a sessionAssurance) highest(now time.Time, window time.Duration) string {
	best := ""
	for _, v := range acrValuesSupported {
		if a.satisfies(v, now, window) {
			best = v
		}
	}
	return best
}

// requirementMet answers whether the session satisfies the request: any one
// of the requested classes is enough (they are the client's alternatives).
// No request is always met.
func (a sessionAssurance) requirementMet(requested []string, now time.Time, window time.Duration) bool {
	if len(requested) == 0 {
		return true
	}
	for _, v := range requested {
		if a.satisfies(v, now, window) {
			return true
		}
	}
	return false
}

// loadSessionAssurance reads a session's recorded methods and last second
// factor, org-scoped. A missing session is Found=false, and satisfies nothing.
func (s *Service) loadSessionAssurance(ctx context.Context, sessionID string) (sessionAssurance, error) {
	var a sessionAssurance
	if sessionID == "" || s.db == nil {
		return a, nil
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return a, nil
	}
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(auth_methods, '{}'), mfa_verified_at FROM sessions WHERE id = $1 AND org_id = $2`,
		sessionID, org.ID).Scan(&a.Methods, &a.MFAVerifiedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return a, nil
		}
		return a, err
	}
	a.Found = true
	return a, nil
}

// stepUpWindow is the freshness window urn:openidx:mfa:fresh is judged in:
// the one the step-up gate uses.
func (s *Service) stepUpWindow(ctx context.Context) time.Duration {
	var def time.Duration
	if s.config != nil {
		def = s.config.StepUpMaxAge
	}
	return stepup.MaxAge(ctx, s.db, def)
}

// sessionACR is the acr claim for a token minted from sessionID, or "".
func (s *Service) sessionACR(ctx context.Context, sessionID ...string) string {
	if len(sessionID) == 0 || sessionID[0] == "" {
		return ""
	}
	a, err := s.loadSessionAssurance(ctx, sessionID[0])
	if err != nil || !a.Found {
		return ""
	}
	return a.highest(time.Now(), s.stepUpWindow(ctx))
}

// requiredACR is what this pending request demands: the client's acr_values,
// plus urn:openidx:mfa:fresh when the application behind the client declares
// require_step_up. The application's demand is not an alternative the client
// can talk down: when it applies, it is the requirement.
func (s *Service) requiredACR(ctx context.Context, oauthParams map[string]string) []string {
	requested := parseACRValues(oauthParams[paramACRValues])
	if s.applicationRequiresStepUp(ctx, oauthParams["client_id"]) {
		// The client's stronger alternatives still count (phishing-resistant
		// is only ever stronger here if it is also fresh, so it is not kept).
		return []string{ACRMFAFresh}
	}
	return requested
}

// applicationRequiresStepUp reads resource_conditions.require_step_up for the
// application behind clientID. A lookup that fails reads as false: the
// assignment gate, which runs first, already refuses on a failed lookup when
// enforcement is on.
func (s *Service) applicationRequiresStepUp(ctx context.Context, clientID string) bool {
	if clientID == "" || s.db == nil {
		return false
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return false
	}
	var appID string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT id FROM applications WHERE client_id = $1 AND org_id = $2`, clientID, org.ID).Scan(&appID); err != nil {
		return false
	}
	res, err := accessdecision.LoadResource(ctx, s.db, appID, org.ID)
	if err != nil {
		return false
	}
	return res.Conditions.RequireStepUp
}

// acrGateAllows is the mint-time check. It returns true when the code may be
// minted. Otherwise it has answered the request: with an MFA challenge the
// login page completes (the same body POST /oauth/login answers with), or,
// when the person has no factor that could satisfy the request, with
// unmet_authentication_requirements.
//
// redirect is for the endpoints the browser navigates to (the SSO callback,
// a magic link): those answer with a redirect to the login page's MFA step,
// or to the client with the OIDC error, instead of a JSON body.
func (s *Service) acrGateAllows(c *gin.Context, oauthParams map[string]string, userID string, redirect bool) bool {
	ctx := c.Request.Context()
	required := s.requiredACR(ctx, oauthParams)
	if len(required) == 0 {
		return true
	}
	a, err := s.loadSessionAssurance(ctx, oauthParams["session_id"])
	if err != nil {
		writeServerOrUnavailable(c, err)
		return false
	}
	now := time.Now()
	if a.requirementMet(required, now, s.stepUpWindow(ctx)) {
		return true
	}

	methods := s.acrChallengeMethods(ctx, userID, required)
	if len(methods) == 0 {
		s.logAuditEvent(ctx, "authentication", "security", "acr_unmet", "failure",
			userID, c.ClientIP(), oauthParams["client_id"], "client",
			map[string]interface{}{"acr_values": strings.Join(required, " ")})
		if redirect {
			s.redirectAuthorizeError(c, oauthParams["redirect_uri"], oauthParams["state"], errUnmetAuthnRequired,
				"no factor on this account satisfies the requested acr_values")
			return false
		}
		c.JSON(403, gin.H{
			"error":             errUnmetAuthnRequired,
			"error_description": "This application asks for a stronger sign-in than any factor on this account can give. Add an authenticator app or a passkey and try again.",
			"acr_values":        required,
		})
		return false
	}
	mfaSession, err := s.createMFASession(ctx, userID, oauthParams, 0, "", "", methods)
	if err != nil {
		s.logger.Error("acr: MFA session not created", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return false
	}
	s.logAuditEvent(ctx, "authentication", "security", "acr_step_up", "challenge",
		userID, c.ClientIP(), oauthParams["client_id"], "client",
		map[string]interface{}{"acr_values": strings.Join(required, " "), "methods": methods})
	if redirect {
		q := url.Values{"mfa_session": {mfaSession}, "mfa_methods": {strings.Join(methods, ",")}}
		c.Redirect(http.StatusFound, "/login?"+q.Encode())
		return false
	}
	c.JSON(200, gin.H{
		"mfa_required":      true,
		"mfa_session":       mfaSession,
		"mfa_methods":       methods,
		"acr_values":        required,
		"can_trust_browser": false,
	})
	return false
}

// acrOnlyPhishingResistant reports whether the request can only be satisfied
// by a passkey.
func acrOnlyPhishingResistant(required []string) bool {
	if len(required) == 0 {
		return false
	}
	for _, v := range required {
		if v != ACRPhishingResistant {
			return false
		}
	}
	return true
}

// acrChallengeMethods is the factor list for an acr step-up: the person's
// enrolled strong factors, a passkey only when nothing weaker is acceptable.
// Backup and bypass codes are not offered: they prove possession of a printout,
// not of a device, and an application that asked for a fresh factor asked for
// a device.
func (s *Service) acrChallengeMethods(ctx context.Context, userID string, required []string) []string {
	if s.identityService == nil {
		return nil
	}
	var methods []string
	onlyPasskey := acrOnlyPhishingResistant(required)
	if !onlyPasskey {
		if st, _ := s.identityService.GetTOTPStatus(ctx, userID); st != nil && st.Enabled {
			methods = append(methods, "totp")
		}
	}
	if creds, _ := s.identityService.GetWebAuthnCredentials(ctx, userID); len(creds) > 0 {
		methods = append(methods, "webauthn")
	}
	if !onlyPasskey {
		devices, _ := s.identityService.GetPushDevices(ctx, userID)
		if identity.AssessPushLiveness(devices, time.Now(), s.identityService.PushDeviceStaleAfter()).Offerable() {
			methods = append(methods, "push")
		}
	}
	return methods
}

// narrowMFAMethodsForACR restricts a login challenge's factor list to a
// passkey when the pending request asks for nothing weaker, so the person is
// not asked for a code first and a passkey second. A list with no passkey is
// returned unchanged: the mint-time gate then refuses with
// unmet_authentication_requirements after the first factor, which says what
// is missing instead of a challenge nobody can answer.
func narrowMFAMethodsForACR(oauthParams map[string]string, methods []string) []string {
	if !acrOnlyPhishingResistant(parseACRValues(oauthParams[paramACRValues])) {
		return methods
	}
	for _, m := range methods {
		if m == "webauthn" {
			return []string{"webauthn"}
		}
	}
	return methods
}

// mfaAuthMethods is the amr recorded after a verified second factor: a
// passkey adds "hwk" (RFC 8176), which is what urn:openidx:phishing-resistant
// keys on.
func mfaAuthMethods(firstFactor, method string) []string {
	if method == "webauthn" {
		return []string{firstFactor, "hwk", "mfa"}
	}
	return []string{firstFactor, "mfa"}
}
