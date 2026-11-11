package oauth

// OpenIDX as a Microsoft Entra ID external authentication method (EAM).
//
// Entra's Conditional Access can hand the second factor of a sign-in to an
// external OpenID provider. Entra redirects the browser to the provider's
// authorization endpoint with an id_token_hint naming the person (signed by
// Entra, already expired by design), the provider runs its own second factor,
// and posts an id_token back to Entra (response_mode=form_post) whose acr and
// amr say what was done. OpenIDX is that provider here:
//
//   GET  /eam/.well-known/openid-configuration   the provider document
//   GET  /eam/jwks                                its keys, with x5c (eam_keys.go)
//   GET|POST /eam/authorize                       Entra's request
//   POST /eam/verify                              the sign-in page completes the factor
//
// The issuer is <OAUTH_ISSUER>/eam, separate from the platform issuer, so an
// Entra-bound id_token can never be mistaken for a platform token and vice
// versa. Everything is off unless EAM_ENABLED=true: the endpoints answer 404.
//
// The person is resolved install-wide (an Entra application is one per
// install, not per organization) from the hint's oid, by the identity link an
// Entra sign-in or a directory sync recorded, then by preferred_username as a
// verified email. Nobody found is access_denied: OpenIDX does not provision a
// person because Entra asked for their second factor.

import (
	"context"
	"crypto/sha1" // #nosec G505 -- x5t is defined as the SHA-1 thumbprint (RFC 7517 §4.8); not a security use
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
	"github.com/openidx/openidx/internal/federation/oidcrp"
)

const (
	// eamDefaultAuthority is Entra's sign-in host; tests point eamAuthority
	// at an httptest server.
	eamDefaultAuthority = "https://login.microsoftonline.com"
	// eamACR is the only acr Entra accepts from an external method.
	eamACR = "possessionorinherence"
	// eamTokenLifetime is the id_token's lifetime; Entra wants it short.
	eamTokenLifetime = 5 * time.Minute

	eamErrDenied      = "access_denied"
	eamErrUnavailable = "temporarily_unavailable"
)

// eamState is the per-Service lazily built relying-party machinery for
// verifying Entra's id_token_hint.
type eamState struct {
	once       sync.Once
	discoverer *oidcrp.Discoverer
}

var eamStates sync.Map // *Service -> *eamState

func (s *Service) eamDiscoverer() *oidcrp.Discoverer {
	v, _ := eamStates.LoadOrStore(s, &eamState{})
	st := v.(*eamState)
	st.once.Do(func() { st.discoverer = oidcrp.NewDiscoverer(nil) })
	return st.discoverer
}

func (s *Service) eamEnabled() bool { return s.config != nil && s.config.EAMEnabled }

func (s *Service) eamIssuer() string { return strings.TrimSuffix(s.issuer, "/") + "/eam" }

func (s *Service) eamAuthorityBase() string {
	if s.eamAuthority != "" {
		return strings.TrimSuffix(s.eamAuthority, "/")
	}
	return eamDefaultAuthority
}

func (s *Service) eamClientID() string {
	if s.config == nil {
		return ""
	}
	return strings.TrimSpace(s.config.EAMClientID)
}

func (s *Service) eamTenantAllowed(tid string) bool {
	if s.config == nil || tid == "" {
		return false
	}
	for _, t := range strings.Split(s.config.EAMTenantIDs, ",") {
		if strings.EqualFold(strings.TrimSpace(t), tid) {
			return true
		}
	}
	return false
}

// eamRedirectURI is the one reply address Entra uses for an external method.
func (s *Service) eamRedirectURI() string {
	return s.eamAuthorityBase() + "/common/federation/externalauthprovider"
}

func (s *Service) eamGate(c *gin.Context) bool {
	if !s.eamEnabled() {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return false
	}
	return true
}

// registerEAMRoutes wires the public EAM endpoints and the platform key API.
func (s *Service) registerEAMRoutes(router *gin.Engine, adminChain ...gin.HandlerFunc) {
	eam := router.Group("/eam")
	eam.GET("/.well-known/openid-configuration", s.handleEAMDiscovery)
	eam.GET("/jwks", s.handleEAMJWKS)
	eam.GET("/authorize", s.handleEAMAuthorize)
	eam.POST("/authorize", s.handleEAMAuthorize)
	eam.POST("/verify", s.handleEAMVerify)

	keys := router.Group("/api/v1/oauth/eam/keys")
	keys.Use(adminChain...)
	keys.GET("", s.handleListEAMKeys)
	keys.POST("/rotate", s.handleRotateEAMKey)

	status := router.Group("/api/v1/oauth/eam/status")
	status.Use(adminChain...)
	status.GET("", s.handleEAMStatus)
}

// handleEAMDiscovery: GET /eam/.well-known/openid-configuration.
func (s *Service) handleEAMDiscovery(c *gin.Context) {
	if !s.eamGate(c) {
		return
	}
	iss := s.eamIssuer()
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"jwks_uri":                              iss + "/jwks",
		"response_types_supported":              []string{"id_token"},
		"response_modes_supported":              []string{"form_post"},
		"scopes_supported":                      []string{"openid"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported":                      []string{"sub", "acr", "amr"},
		"acr_values_supported":                  []string{eamACR},
	})
}

// handleEAMJWKS: GET /eam/jwks. Every published key, including one rotated
// in that does not sign yet.
func (s *Service) handleEAMJWKS(c *gin.Context) {
	if !s.eamGate(c) {
		return
	}
	keys, err := s.ensureEAMKeys(c.Request.Context(), time.Now())
	if err != nil {
		s.logger.Error("eam: load keys", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": eamErrUnavailable})
		return
	}
	out := make([]eamJWK, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.jwk())
	}
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, gin.H{"keys": out})
}

func sha1Thumbprint(der []byte) string {
	sum := sha1.Sum(der) // #nosec G401 -- x5t is SHA-1 by definition
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// eamParam reads a parameter from the query or, on POST, the form.
func eamParam(c *gin.Context, name string) string {
	if v := c.Query(name); v != "" {
		return v
	}
	if c.Request.Method == http.MethodPost {
		return c.PostForm(name)
	}
	return ""
}

var eamFormPost = template.Must(template.New("eam").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Continuing to Microsoft</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="{{.Action}}">
{{range $k, $v := .Fields}}<input type="hidden" name="{{$k}}" value="{{$v}}">
{{end}}<noscript><button type="submit">Continue</button></noscript>
</form></body></html>`))

// eamRespond posts fields to Entra's reply address as an auto-submitting form.
func (s *Service) eamRespond(c *gin.Context, fields map[string]string) {
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_ = eamFormPost.Execute(c.Writer, struct {
		Action string
		Fields map[string]string
	}{s.eamRedirectURI(), fields})
}

func (s *Service) eamAudit(ctx context.Context, action, outcome, userID, ip string, meta map[string]interface{}) {
	s.logAuditEvent(ctx, "authentication", "security", action, outcome, userID, ip, userID, "user", meta)
}

// eamRequest is a validated /eam/authorize request.
type eamRequest struct {
	State           string
	Nonce           string
	ClientRequestID string
	Hint            *oidcrp.Claims
}

// eamAuthorizeError is a refusal, and whether Entra's reply address may
// receive it (only once redirect_uri was checked).
type eamAuthorizeError struct {
	code       string
	reason     string
	replyable  bool
	statusCode int
}

func (e *eamAuthorizeError) Error() string { return e.code + ": " + e.reason }

func eamRefuse(code, reason string, replyable bool) *eamAuthorizeError {
	return &eamAuthorizeError{code: code, reason: reason, replyable: replyable, statusCode: http.StatusBadRequest}
}

// validateEAMRequest checks Entra's request and verifies its id_token_hint.
func (s *Service) validateEAMRequest(c *gin.Context) (*eamRequest, *eamAuthorizeError) {
	clientID := eamParam(c, "client_id")
	if s.eamClientID() == "" || clientID != s.eamClientID() {
		return nil, eamRefuse("unauthorized_client", "client_id is not the configured EAM application", false)
	}
	if eamParam(c, "redirect_uri") != s.eamRedirectURI() {
		return nil, eamRefuse("invalid_request", "redirect_uri is not Entra's external method reply address", false)
	}
	req := &eamRequest{
		State:           eamParam(c, "state"),
		Nonce:           eamParam(c, "nonce"),
		ClientRequestID: eamParam(c, "client-request-id"),
	}
	if eamParam(c, "response_type") != "id_token" {
		return req, eamRefuse("unsupported_response_type", "response_type must be id_token", true)
	}
	if eamParam(c, "response_mode") != "form_post" {
		return req, eamRefuse("invalid_request", "response_mode must be form_post", true)
	}
	if !containsWord(eamParam(c, "scope"), "openid") {
		return req, eamRefuse("invalid_scope", "scope must include openid", true)
	}
	if req.Nonce == "" {
		return req, eamRefuse("invalid_request", "nonce is required", true)
	}
	if raw := eamParam(c, "claims"); raw != "" && !eamClaimsAcceptable(raw) {
		return req, eamRefuse(eamErrDenied, "claims requests an acr this provider does not assert", true)
	}
	hint := eamParam(c, "id_token_hint")
	if hint == "" {
		return req, eamRefuse("invalid_request", "id_token_hint is required", true)
	}

	// The tenant decides which Entra issuer must have signed the hint, so it
	// is read before verification and checked against the allowlist; the
	// verification below then proves it.
	tid := unverifiedClaim(hint, "tid")
	if !s.eamTenantAllowed(tid) {
		return req, eamRefuse(eamErrDenied, "the hint's tenant is not an allowed Entra tenant", true)
	}
	ctx := c.Request.Context()
	issuer := s.eamAuthorityBase() + "/" + tid + "/v2.0"
	d := s.eamDiscoverer()
	md, err := d.Discover(ctx, issuer, "")
	if err != nil {
		s.logger.Warn("eam: Entra discovery failed", zap.String("issuer", issuer), zap.Error(err))
		e := eamRefuse(eamErrUnavailable, "Entra's provider document could not be read", true)
		return req, e
	}
	claims, err := d.VerifyIDToken(ctx, md, hint, oidcrp.VerifyOptions{ClientID: s.eamClientID(), AllowExpired: true})
	if err != nil {
		return req, eamRefuse(eamErrDenied, "id_token_hint did not verify: "+err.Error(), true)
	}
	if !strings.EqualFold(claims.TID, tid) {
		return req, eamRefuse(eamErrDenied, "id_token_hint tenant mismatch", true)
	}
	req.Hint = claims
	return req, nil
}

func containsWord(list, w string) bool {
	for _, f := range strings.Fields(list) {
		if f == w {
			return true
		}
	}
	return false
}

// eamClaimsAcceptable reads the claims request parameter: an acr request
// whose values do not include possessionorinherence is one OpenIDX cannot
// satisfy.
func eamClaimsAcceptable(raw string) bool {
	var req struct {
		IDToken map[string]struct {
			Values []string `json:"values"`
			Value  string   `json:"value"`
		} `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return false
	}
	acr, ok := req.IDToken["acr"]
	if !ok || (len(acr.Values) == 0 && acr.Value == "") {
		return true
	}
	if acr.Value == eamACR {
		return true
	}
	for _, v := range acr.Values {
		if v == eamACR {
			return true
		}
	}
	return false
}

// unverifiedClaim reads one string claim from a JWT without verifying it.
func unverifiedClaim(raw, name string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var m map[string]interface{}
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	v, _ := m[name].(string)
	return v
}

var errEAMAmbiguous = errors.New("eam: more than one person matches")

// resolveEAMUser finds the OpenIDX person the hint names. Install-wide: an
// Entra application serves one install, whichever organization the person
// is in.
func (s *Service) resolveEAMUser(ctx context.Context, hint *oidcrp.Claims) (string, error) {
	ctx = orgctx.WithBypassRLS(ctx)
	if hint.OID != "" {
		// 1. The identity link an Entra sign-in recorded (B1: external_id_claim=oid).
		ids, err := s.eamUserIDs(ctx, `
			SELECT DISTINCT l.user_id::text FROM user_identity_links l
			  JOIN identity_providers p ON p.id = l.provider_id
			 WHERE l.external_id = $1 AND p.issuer_url ILIKE '%' || $2 || '%'
			   --orgscope:ignore EAM is install-wide: one Entra app, people in any organization; the tenant id pins the provider
			`, hint.OID, hint.TID)
		if err != nil || len(ids) > 0 {
			return eamOne(ids, err)
		}
		// 2. A directory sync from Entra (directory/azure_ad.go stores the
		// Graph object id as users.external_id, source azure_ad).
		ids, err = s.eamUserIDs(ctx, `
			SELECT id::text FROM users WHERE source = 'azure_ad' AND external_id = $1
			   --orgscope:ignore EAM is install-wide: one Entra app, people in any organization
			`, hint.OID)
		if err != nil || len(ids) > 0 {
			return eamOne(ids, err)
		}
	}
	// 3. preferred_username as a verified email address.
	if email := strings.TrimSpace(hint.PreferredUsername); strings.Contains(email, "@") {
		ids, err := s.eamUserIDs(ctx, `
			SELECT id::text FROM users WHERE lower(email) = lower($1) AND email_verified = true
			   --orgscope:ignore EAM is install-wide: one Entra app, people in any organization
			`, email)
		return eamOne(ids, err)
	}
	return "", pgx.ErrNoRows
}

func (s *Service) eamUserIDs(ctx context.Context, q string, args ...interface{}) ([]string, error) {
	rows, err := s.db.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func eamOne(ids []string, err error) (string, error) {
	switch {
	case err != nil:
		return "", err
	case len(ids) == 0:
		return "", pgx.ErrNoRows
	case len(ids) > 1:
		return "", errEAMAmbiguous
	}
	return ids[0], nil
}

// eamAllowedMethods narrows the evaluated methods to what may stand behind
// Entra's possession-or-inherence claim.
func (s *Service) eamAllowedMethods(methods []string) []string {
	strongOnly := s.config == nil || s.config.EAMRequireStrongFactors
	var out []string
	for _, m := range methods {
		switch {
		case externalid.FactorAllowed(externalid.TypeExternal, m):
			out = append(out, m)
		case !strongOnly && (m == "sms" || m == "email"):
			out = append(out, m)
		}
	}
	return out
}

// eamAMR is the amr value Entra reads for an OpenIDX factor.
func eamAMR(method string) string {
	switch method {
	case "totp", "email":
		return "otp"
	case "webauthn":
		return "fido"
	case "push":
		return "pop"
	case "sms":
		return "sms"
	}
	return ""
}

// handleEAMAuthorize: GET|POST /eam/authorize, Entra's request.
func (s *Service) handleEAMAuthorize(c *gin.Context) {
	if !s.eamGate(c) {
		return
	}
	ctx := c.Request.Context()
	ip := c.ClientIP()
	req, rerr := s.validateEAMRequest(c)
	refuse := func(e *eamAuthorizeError, userID string) {
		meta := map[string]interface{}{"reason": e.reason, "error": e.code}
		if req != nil {
			meta["client_request_id"] = req.ClientRequestID
		}
		s.eamAudit(ctx, "eam.mfa_refused", "failure", userID, ip, meta)
		if !e.replyable {
			c.JSON(e.statusCode, gin.H{"error": e.code, "error_description": e.reason})
			return
		}
		fields := map[string]string{"error": e.code, "error_description": e.reason}
		if req != nil && req.State != "" {
			fields["state"] = req.State
		}
		s.eamRespond(c, fields)
	}
	if rerr != nil {
		refuse(rerr, "")
		return
	}

	userID, err := s.resolveEAMUser(ctx, req.Hint)
	if err != nil {
		code, reason := eamErrDenied, "no OpenIDX account matches this Entra user"
		if !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, errEAMAmbiguous) {
			s.logger.Error("eam: resolve user", zap.Error(err))
			code, reason = eamErrUnavailable, "the account could not be looked up"
		} else if errors.Is(err, errEAMAmbiguous) {
			reason = "more than one OpenIDX account matches this Entra user"
		}
		refuse(eamRefuse(code, reason, true), "")
		return
	}
	if s.identityService == nil {
		refuse(eamRefuse(eamErrUnavailable, "identity service unavailable", true), userID)
		return
	}
	user, err := s.identityService.GetUser(ctx, userID)
	if err != nil || user == nil || !user.Enabled {
		refuse(eamRefuse(eamErrDenied, "the account is not active", true), userID)
		return
	}

	ev := s.evaluateMFA(ctx, user, ip, c.GetHeader("User-Agent"), "", "", false, 0, nil)
	if ev.Undecidable {
		refuse(eamRefuse(eamErrUnavailable, "the MFA policy could not be evaluated", true), userID)
		return
	}
	if ev.DenyAccess {
		refuse(eamRefuse(eamErrDenied, "the sign-in was refused by risk policy", true), userID)
		return
	}
	allowed := s.eamAllowedMethods(ev.Methods)
	if len(allowed) == 0 {
		// Inline enrolment (B3.2) is not wired to this flow yet: a person
		// with no acceptable factor cannot satisfy Entra here.
		refuse(eamRefuse(eamErrDenied, "the account has no acceptable second factor enrolled", true), userID)
		return
	}

	session, err := s.createMFASession(ctx, userID, map[string]string{
		"eam_session":           "1",
		"eam_state":             req.State,
		"eam_nonce":             req.Nonce,
		"eam_sub":               req.Hint.Sub,
		"eam_tid":               req.Hint.TID,
		"eam_client_request_id": req.ClientRequestID,
	}, 0, "", "", allowed)
	if err != nil {
		s.logger.Error("eam: open MFA session", zap.Error(err))
		refuse(eamRefuse(eamErrUnavailable, "the MFA session could not be opened", true), userID)
		return
	}
	q := url.Values{"eam_session": {session}, "mfa_methods": {strings.Join(allowed, ",")}}
	c.Redirect(http.StatusFound, "/login?"+q.Encode())
}

// handleEAMVerify: POST /eam/verify. The sign-in page posts the factor for an
// EAM session; the answer is the form Entra's reply address receives.
func (s *Service) handleEAMVerify(c *gin.Context) {
	if !s.eamGate(c) {
		return
	}
	var body struct {
		MFASession string `json:"mfa_session"`
		Code       string `json:"code"`
		Method     string `json:"method"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.MFASession == "" || body.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "mfa_session and code are required"})
		return
	}
	ctx := c.Request.Context()
	ip := c.ClientIP()
	raw, err := s.redis.Client.Get(ctx, "mfa_session:"+body.MFASession).Result()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid or expired MFA session"})
		return
	}
	var data map[string]string
	if err := json.Unmarshal([]byte(raw), &data); err != nil || data["eam_session"] != "1" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "not an external authentication session"})
		return
	}
	userID := data["user_id"]
	if body.Method == "" {
		body.Method = "totp"
	}
	// The session pins the factors eamAllowedMethods left; nothing else
	// (backup, bypass) completes it.
	if allowedMFAMethods(data) == nil || !mfaMethodPermitted(data, body.Method) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "this sign-in cannot be completed with " + body.Method})
		return
	}
	ok, verr := s.verifyStepUpFactor(ctx, userID, body.Method, body.Code, ip, c.GetHeader("User-Agent"))
	if verr != nil || !ok {
		s.eamAudit(ctx, "eam.mfa_failed", "failure", userID, ip, map[string]interface{}{
			"method": body.Method, "client_request_id": data["eam_client_request_id"]})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_mfa_code", "error_description": "Invalid verification code"})
		return
	}
	s.redis.Client.Del(ctx, "mfa_session:"+body.MFASession)

	fields := map[string]string{}
	if st := data["eam_state"]; st != "" {
		fields["state"] = st
	}
	idToken, err := s.signEAMIDToken(ctx, data["eam_sub"], data["eam_nonce"], eamAMR(body.Method), time.Now())
	if err != nil {
		s.logger.Error("eam: sign id_token", zap.Error(err))
		fields["error"] = eamErrUnavailable
	} else {
		fields["id_token"] = idToken
		s.eamAudit(ctx, "eam.mfa_satisfied", "success", userID, ip, map[string]interface{}{
			"method": body.Method, "tid": data["eam_tid"], "client_request_id": data["eam_client_request_id"]})
	}
	c.JSON(http.StatusOK, gin.H{"form_post": gin.H{"action": s.eamRedirectURI(), "fields": fields}})
}

// signEAMIDToken mints the id_token Entra reads: iss <issuer>/eam, aud the
// EAM application, sub copied from the hint, the request's nonce, five
// minutes, acr possessionorinherence, amr the factor used.
func (s *Service) signEAMIDToken(ctx context.Context, sub, nonce, amr string, now time.Time) (string, error) {
	key, err := s.eamSigningKey(ctx, now)
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{
		"iss":   s.eamIssuer(),
		"aud":   s.eamClientID(),
		"sub":   sub,
		"nonce": nonce,
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   now.Add(eamTokenLifetime).Unix(),
		"acr":   eamACR,
		"amr":   []string{amr},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = key.KID
	return tok.SignedString(key.Private)
}
