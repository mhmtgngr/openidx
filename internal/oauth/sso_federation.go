package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
	"github.com/openidx/openidx/internal/federation/oidcrp"
	"github.com/openidx/openidx/internal/identity"
)

// ENTERPRISE SSO IS AN OPENID CONNECT RELYING PARTY.
//
// GET /oauth/authorize?idp_hint=<id> sends the browser to an upstream
// provider (Entra ID, ADFS, Keycloak, a partner's issuer) and GET
// /oauth/callback finishes the sign-in. Both used to build Keycloak's
// endpoint paths from the issuer URL by hand, sent no nonce and no PKCE,
// verified only the ID token's signature, and found the user by a substring
// match on email (ListUsers' search), JIT-creating anyone the provider
// vouched for. They now go through internal/federation/oidcrp: endpoints
// from the provider's discovery document, state + nonce + PKCE, every
// OpenID Connect Core ID token check, the IdP's claims mapping, and a user
// resolution that links by the configured stable claim, links by email only
// when that email is proven, and provisions only when the IdP says so.

// SSO refusals, as the login page reads them from ?error=.
const (
	ssoErrIdP                  = "sso_idp_error"
	ssoErrNonceMismatch        = "sso_nonce_mismatch"
	ssoErrUserNotFound         = "sso_user_not_found"
	ssoErrPartnerNotRegistered = "sso_partner_not_registered"
)

// ssoStateTTL is how long a started upstream sign-in may take.
const ssoStateTTL = 10 * time.Minute

// paramFirstFactor rides the pending request into the MFA session so the
// second-factor step records the session's methods as fed+mfa, not pwd+mfa.
const paramFirstFactor = "first_factor"

// upstreamMFAMethods are the RFC 8176 amr values that mean the provider
// itself asked for more than one factor.
var upstreamMFAMethods = map[string]bool{
	"mfa": true, "otp": true, "fido": true, "hwk": true, "swk": true, "pop": true, "sms": true, "tel": true,
}

// federationDiscoverer is the process-wide relying-party Discoverer.
func (s *Service) federationDiscoverer() *oidcrp.Discoverer {
	s.federationOnce.Do(func() {
		if s.federation == nil {
			s.federation = oidcrp.NewDiscoverer(nil)
		}
	})
	return s.federation
}

// pkceChallengeS256 is the RFC 7636 S256 transform of verifier.
func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ssoRefuse sends the browser back to the login page with reason.
func ssoRefuse(c *gin.Context, reason, loginSession string) {
	q := url.Values{"error": {reason}}
	if loginSession != "" {
		q.Set("login_session", loginSession)
	}
	c.Redirect(http.StatusFound, "/login?"+q.Encode())
}

func (s *Service) handleSSOAuthorize(c *gin.Context, q authorizeParams, idpID string) {
	ctx := c.Request.Context()
	idp, err := s.identityService.GetIdentityProvider(ctx, idpID)
	if err != nil || idp == nil || !idp.Enabled {
		c.JSON(400, gin.H{"error": "invalid_idp"})
		return
	}
	idp.NormalizeFederationProfile()

	// The request being completed. A login page that already holds a pending
	// third-party request (login_session) sends only idp_hint and the handle:
	// the client_id, redirect_uri, state, nonce and PKCE challenge are the
	// ones /oauth/authorize stashed under login_session:<id>, never values
	// the browser supplies now. Without a handle the request carries them.
	loginSession := q.Query("login_session")
	orig, ok := s.ssoOriginalParams(ctx, q, loginSession)
	if !ok {
		s.logAuditEvent(ctx, "authentication", "sso", "sso_login", "failure",
			"", c.ClientIP(), "", "user", map[string]interface{}{"reason": "invalid_login_session", "idp_id": idp.ID.String()})
		ssoRefuse(c, externalErrUnavailable, "")
		return
	}

	// PKCE, before the flow leaves for the external IdP. This path is reached
	// from handleAuthorize with an idp_hint, BEFORE that handler fetches the
	// client, so the rule is applied here against the client this request
	// names. The refusal is a 400 and not a redirect: this handler has not
	// validated redirect_uri against the client, and reporting an error to an
	// unvalidated redirect_uri is an open redirect.
	if ssoClient, cerr := s.GetClient(ctx, orig["client_id"]); cerr == nil {
		if perr := validatePKCERequest(ssoClient, orig["code_challenge"], orig["code_challenge_method"], s.isProduction()); perr != nil {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": perr.Error()})
			return
		}
	}

	md, err := s.federationDiscoverer().Discover(ctx, idp.IssuerURL, idp.DiscoveryURL)
	if err != nil {
		s.logger.Warn("SSO: provider discovery failed", zap.String("idp_id", idp.ID.String()), zap.Error(err))
		s.logAuditEvent(ctx, "authentication", "sso", "sso_login", "failure",
			"", c.ClientIP(), "", "user", map[string]interface{}{"reason": "discovery_failed", "idp_id": idp.ID.String()})
		ssoRefuse(c, externalErrUnavailable, loginSession)
		return
	}

	// The state entry carries the pending OpenIDX request, the IdP the flow
	// belongs to (the callback resolves the provider from it and nothing
	// else), and this sign-in's nonce and PKCE verifier.
	state := GenerateRandomToken(32)
	nonce := GenerateRandomToken(32)
	pending := make(map[string]string, len(orig)+4)
	for k, v := range orig {
		pending[k] = v
	}
	pending["idp_id"] = idp.ID.String()
	pending["upstream_nonce"] = nonce
	if loginSession != "" {
		pending["login_session"] = loginSession
	}

	authURL, err := url.Parse(md.AuthorizationEndpoint)
	if err != nil || md.AuthorizationEndpoint == "" {
		ssoRefuse(c, externalErrUnavailable, loginSession)
		return
	}
	query := authURL.Query()
	query.Set("client_id", idp.ClientID)
	query.Set("redirect_uri", s.issuer+"/oauth/callback")
	query.Set("response_type", "code")
	scopes := []string(idp.Scopes)
	if !containsString(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", state)
	query.Set("nonce", nonce)
	if idp.UsePKCE != nil && *idp.UsePKCE {
		verifier := GenerateRandomToken(48)
		pending["upstream_code_verifier"] = verifier
		query.Set("code_challenge", pkceChallengeS256(verifier))
		query.Set("code_challenge_method", "S256")
	}
	// Only the parameters the IdP profile allows travel upstream.
	for _, p := range idp.PassThroughParams {
		if v := q.Query(p); v != "" {
			query.Set(p, v)
		}
	}
	authURL.RawQuery = query.Encode()

	raw, _ := json.Marshal(pending)
	if err := s.redis.Client.Set(ctx, "sso_state:"+state, string(raw), ssoStateTTL).Err(); err != nil {
		writeServerOrUnavailable(c, err)
		return
	}
	c.Redirect(302, authURL.String())
}

// ssoOriginalParams is the authorization request an SSO sign-in completes:
// the pending one stored at login_session:<id> when the login page names it,
// else the request's own parameters. ok is false for a handle that names
// nothing (expired, already used, or forged).
func (s *Service) ssoOriginalParams(ctx context.Context, q authorizeParams, loginSession string) (map[string]string, bool) {
	keys := []string{"client_id", "redirect_uri", "response_type", "scope", "state",
		"nonce", "code_challenge", "code_challenge_method", "prompt", "max_age"}
	out := make(map[string]string, len(keys))
	if loginSession == "" {
		for _, k := range keys {
			if v := q.Query(k); v != "" {
				out[k] = v
			}
		}
		return out, true
	}
	raw, err := s.redis.Client.Get(ctx, "login_session:"+loginSession).Result()
	if err != nil {
		return nil, false
	}
	var stored map[string]string
	if json.Unmarshal([]byte(raw), &stored) != nil || stored["client_id"] == "" || stored["redirect_uri"] == "" {
		return nil, false
	}
	for _, k := range keys {
		if v := stored[k]; v != "" {
			out[k] = v
		}
	}
	return out, true
}

func containsString(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// ssoTokenResponse is the part of the provider's token response the callback reads.
type ssoTokenResponse struct {
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// exchangeSSOCode redeems code at the provider's token endpoint.
func (s *Service) exchangeSSOCode(ctx context.Context, md *oidcrp.Metadata, idp *identity.IdentityProvider, code, verifier string) (string, error) {
	if md.TokenEndpoint == "" {
		return "", errors.New("provider publishes no token endpoint")
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {s.issuer + "/oauth/callback"},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, md.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(idp.ClientID), url.QueryEscape(idp.ClientSecret))
	client, _ := oidcrp.GuardedClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tr ssoTokenResponse
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", fmt.Errorf("token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || tr.Error != "" {
		return "", fmt.Errorf("token endpoint: %d %s", resp.StatusCode, tr.Error)
	}
	if tr.IDToken == "" {
		return "", errors.New("token response carries no id_token")
	}
	return tr.IDToken, nil
}

// externalIDFrom reads the claim the IdP names as its stable user key. A
// claims mapping for external_id wins over the profile's external_id_claim.
func externalIDFrom(idp *identity.IdentityProvider, cl *oidcrp.Claims, mapped oidcrp.Mapped) string {
	if _, ok := idp.ClaimsMapping[oidcrp.FieldExternalID]; ok {
		return mapped.ExternalID
	}
	switch idp.ExternalIDClaim {
	case "oid":
		return cl.OID
	case "upn":
		return cl.UPN
	case "email":
		return cl.Email
	case "preferred_username":
		return cl.PreferredUsername
	default:
		return cl.Sub
	}
}

func (s *Service) handleCallback(c *gin.Context) {
	ctx := c.Request.Context()
	clientIP := c.ClientIP()
	state := c.Query("state")
	code := c.Query("code")

	audit := func(action, status, userID string, details map[string]interface{}) {
		s.logAuditEvent(ctx, "authentication", "sso", action, status, userID, clientIP, userID, "user", details)
	}

	paramsJSON, err := s.redis.Client.Get(ctx, "sso_state:"+state).Result()
	if state == "" || err != nil {
		audit("sso_login", "failure", "", map[string]interface{}{"reason": "invalid_state"})
		c.JSON(400, gin.H{"error": "invalid_state"})
		return
	}
	// One use: a replayed callback finds nothing.
	s.redis.Client.Del(ctx, "sso_state:"+state)
	var originalParams map[string]string
	_ = json.Unmarshal([]byte(paramsJSON), &originalParams)
	loginSession := originalParams["login_session"]

	idpID := originalParams["idp_id"]
	if idpID == "" {
		audit("sso_login", "failure", "", map[string]interface{}{"reason": "state_missing_idp"})
		c.JSON(400, gin.H{"error": "invalid_state"})
		return
	}
	idp, err := s.identityService.GetIdentityProvider(ctx, idpID)
	if err != nil || idp == nil {
		audit("sso_login", "failure", "", map[string]interface{}{"reason": "idp_not_found", "idp_id": idpID})
		c.JSON(400, gin.H{"error": "invalid_idp"})
		return
	}
	idp.NormalizeFederationProfile()
	idpDetails := func(extra map[string]interface{}) map[string]interface{} {
		m := map[string]interface{}{"idp_id": idp.ID.String()}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// The provider refused (the user cancelled, consent was denied, a
	// conditional access policy blocked the sign-in).
	if upErr := c.Query("error"); upErr != "" {
		audit("sso_login", "failure", "", idpDetails(map[string]interface{}{"reason": "upstream_error", "upstream_error": upErr}))
		ssoRefuse(c, ssoErrIdP, loginSession)
		return
	}
	if code == "" {
		audit("sso_login", "failure", "", idpDetails(map[string]interface{}{"reason": "missing_code"}))
		ssoRefuse(c, ssoErrIdP, loginSession)
		return
	}

	disc := s.federationDiscoverer()
	md, err := disc.Discover(ctx, idp.IssuerURL, idp.DiscoveryURL)
	if err != nil {
		s.logger.Warn("SSO: provider discovery failed", zap.Error(err))
		audit("sso_login", "failure", "", idpDetails(map[string]interface{}{"reason": "discovery_failed"}))
		ssoRefuse(c, externalErrUnavailable, loginSession)
		return
	}
	rawIDToken, err := s.exchangeSSOCode(ctx, md, idp, code, originalParams["upstream_code_verifier"])
	if err != nil {
		s.logger.Warn("SSO: code exchange failed", zap.Error(err))
		audit("sso_login", "failure", "", idpDetails(map[string]interface{}{"reason": "token_exchange_failed"}))
		ssoRefuse(c, externalErrUnavailable, loginSession)
		return
	}
	claims, err := disc.VerifyIDToken(ctx, md, rawIDToken, oidcrp.VerifyOptions{
		ClientID: idp.ClientID,
		Nonce:    originalParams["upstream_nonce"],
	})
	if err != nil {
		if errors.Is(err, oidcrp.ErrNonce) {
			audit(ssoErrNonceMismatch, "failure", "", idpDetails(nil))
			ssoRefuse(c, ssoErrNonceMismatch, loginSession)
			return
		}
		s.logger.Warn("SSO: ID token refused", zap.Error(err))
		audit("sso_login", "failure", "", idpDetails(map[string]interface{}{"reason": "id_token_verification_failed", "error": err.Error()}))
		ssoRefuse(c, externalErrUnavailable, loginSession)
		return
	}

	mapped := oidcrp.ApplyClaimsMapping(claims.Raw, idp.ClaimsMapping)
	externalID := externalIDFrom(idp, claims, mapped)
	if externalID == "" {
		audit("sso_login", "failure", "", idpDetails(map[string]interface{}{"reason": "missing_external_id", "claim": idp.ExternalIDClaim}))
		ssoRefuse(c, externalErrUnavailable, loginSession)
		return
	}

	user, reason := s.resolveFederatedUser(ctx, c, idp, claims, mapped, externalID)
	if user == nil {
		audit("sso_login", "failure", "", idpDetails(map[string]interface{}{"reason": reason, "external_user_id": externalID}))
		ssoRefuse(c, reason, loginSession)
		return
	}

	if err := s.checkCountryBlock(ctx, clientIP, user.ID, user.UserName); err != nil {
		audit("sso_login", "failure", user.ID, idpDetails(map[string]interface{}{"reason": "country_blocked"}))
		ssoRefuse(c, "sso_location_blocked", loginSession)
		return
	}

	external := false
	if org, oerr := orgctx.From(ctx); oerr == nil {
		external, _ = externalid.IsExternal(ctx, s.db.Pool, org.ID, user.ID)
		if external {
			s.slideFederatedExpiry(ctx, org.ID, user.ID)
		}
	}
	s.syncFederatedGroups(ctx, idp, user.ID, external, mapped.Groups)

	upstreamMFA := false
	if idp.TrustUpstreamMFA {
		for _, m := range claims.AMR {
			if upstreamMFAMethods[strings.ToLower(m)] {
				upstreamMFA = true
				break
			}
		}
	}

	audit("sso_login", "success", user.ID, idpDetails(map[string]interface{}{
		"external_user_id": externalID, "upstream_amr": claims.AMR, "upstream_mfa_trusted": upstreamMFA && !external,
	}))

	pending := make(map[string]string, len(originalParams))
	for k, v := range originalParams {
		switch k {
		case "idp_id", "upstream_nonce", "upstream_code_verifier", "login_session":
		default:
			pending[k] = v
		}
	}
	pending[paramFirstFactor] = "fed"
	pending["idp"] = idp.ID.String()

	// The upstream second factor counts only for an internal user: an
	// external (vendor) identity always proves an OpenIDX factor here.
	methods := []string{"fed"}
	if upstreamMFA && !external {
		methods = []string{"fed", "mfa"}
	} else if s.externalSignInNeedsMore(c, user.ID, pending, loginSession, "sso") {
		return
	}

	if !s.assignmentGateAllows(c, originalParams["client_id"], user.ID, originalParams["redirect_uri"]) {
		return
	}

	session, serr := s.identityService.CreateSession(ctx, user.ID, originalParams["client_id"], clientIP, c.GetHeader("User-Agent"), 24*time.Hour)
	if serr != nil {
		s.logger.Warn("SSO: could not create the session", zap.Error(serr))
	}

	// The PKCE challenge travels with the code: a public client's code
	// without it is refused at the token endpoint.
	authCode := &AuthorizationCode{
		Code:                GenerateRandomToken(32),
		ClientID:            originalParams["client_id"],
		UserID:              user.ID,
		RedirectURI:         originalParams["redirect_uri"],
		Scope:               originalParams["scope"],
		State:               originalParams["state"],
		Nonce:               originalParams["nonce"],
		CodeChallenge:       originalParams["code_challenge"],
		CodeChallengeMethod: originalParams["code_challenge_method"],
	}
	if err := s.CreateAuthorizationCode(ctx, authCode); err != nil {
		writeServerOrUnavailable(c, err)
		return
	}
	if session != nil {
		s.recordSessionAuthMethods(ctx, session.ID, methods)
		s.recordSessionIdP(ctx, session.ID, idp.ID.String())
		s.redis.Client.Set(ctx, "authcode_session:"+authCode.Code, session.ID, 5*time.Minute)
		s.setBrowserSessionCookie(c, session.ID)
	}
	if loginSession != "" {
		s.redis.Client.Del(ctx, "login_session:"+loginSession)
	}

	c.Redirect(302, authorizationRedirectURL(originalParams["redirect_uri"], authCode.Code, authCode.State))
}

// resolveFederatedUser finds the OpenIDX user the provider vouched for, in
// order: the stable link (idp_id + external_user_id), an exact email match
// when that email is proven (email_verified, or the IdP's jit_policy says the
// provider's emails may be trusted for linking) and then the link is
// written, and JIT provisioning when the IdP's policy allows it. It returns
// the refusal reason when no user may sign in.
func (s *Service) resolveFederatedUser(ctx context.Context, c *gin.Context, idp *identity.IdentityProvider,
	claims *oidcrp.Claims, mapped oidcrp.Mapped, externalID string) (*identity.User, string) {
	clientIP := c.ClientIP()
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, externalErrUnavailable
	}
	audit := func(action, uid string, details map[string]interface{}) {
		details["idp_id"] = idp.ID.String()
		details["external_user_id"] = externalID
		s.logAuditEvent(ctx, "authentication", "sso", action, "success", uid, clientIP, uid, "user", details)
	}

	// (1) The stable federated link.
	var uid string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT id FROM users WHERE org_id = $1 AND idp_id = $2 AND external_user_id = $3 LIMIT 1`,
		org.ID, idp.ID, externalID).Scan(&uid); err == nil && uid != "" {
		if u, gerr := s.identityService.GetUser(ctx, uid); gerr == nil && u != nil {
			audit("sso_identity_matched", uid, map[string]interface{}{})
			return u, ""
		}
		return nil, externalErrUnavailable
	}

	// (2) Exact email, only when the email is proven.
	email := strings.TrimSpace(mapped.Email)
	if email != "" && (claims.EmailVerified || idp.JITPolicy.LinkByEmail) {
		if u, gerr := s.identityService.GetUserByEmail(ctx, email); gerr == nil && u != nil && strings.EqualFold(u.GetEmail(), email) {
			tag, uerr := s.db.Pool.Exec(ctx,
				`UPDATE users SET idp_id = $1, external_user_id = $2 WHERE id = $3 AND org_id = $4 AND external_user_id IS NULL`,
				idp.ID, externalID, u.ID, org.ID)
			if uerr != nil {
				s.logger.Warn("SSO: could not write the federated link", zap.String("user_id", u.ID), zap.Error(uerr))
			} else if tag.RowsAffected() == 0 {
				// Already linked to another provider identity: an email
				// match must not take over somebody's existing link.
				return nil, ssoErrUserNotFound
			}
			audit("sso_identity_backfilled", u.ID, map[string]interface{}{"via": "email"})
			return u, ""
		}
	}

	// (3) Just-in-time provisioning, when the IdP's policy allows it.
	if !idp.JITPolicy.Provision {
		return nil, ssoErrUserNotFound
	}
	if email == "" {
		return nil, ssoErrUserNotFound
	}
	if federatedPopulation(idp.JITPolicy, claims.Raw, claims.PreferredUsername, claims.UPN) == identity.PopulationExternal {
		// An external (vendor) person: the vendor supplies sponsor, expiry
		// and groups (federated_provisioning.go).
		v, verr := s.resolveVendorForClaims(ctx, org.ID, idp.ID.String(), idp.JITPolicy, email)
		var newID string
		if verr == nil {
			newID, verr = s.provisionFederatedExternal(ctx, org.ID, v, federatedPerson{
				Email: email, Username: mapped.Username, FirstName: mapped.FirstName, LastName: mapped.LastName,
				EmailVerified: claims.EmailVerified, IdPID: idp.ID.String(), ExternalID: externalID,
			})
		}
		if verr != nil {
			reason, detail := federatedExternalRefusal(verr)
			if reason == externalErrUnavailable {
				s.logger.Error("SSO: external provisioning failed", zap.Error(verr))
			}
			details := map[string]interface{}{"email": email, "reason": detail}
			if v != nil {
				details["vendor_org_id"] = v.ID
			}
			s.logAuditEvent(ctx, "authentication", "sso", "sso_user_provisioned", "failure", "", clientIP, "", "user", details)
			return nil, reason
		}
		u, gerr := s.identityService.GetUser(ctx, newID)
		if gerr != nil || u == nil {
			return nil, externalErrUnavailable
		}
		audit("sso_user_provisioned", newID, map[string]interface{}{"email": email, "population": "external", "vendor_org_id": v.ID})
		return u, ""
	}
	username := mapped.Username
	if username == "" {
		username = email
	}
	u := &identity.User{UserName: username, Enabled: true, EmailVerified: claims.EmailVerified}
	u.SetEmail(email)
	u.SetFirstName(mapped.FirstName)
	u.SetLastName(mapped.LastName)
	if err := s.identityService.CreateUser(ctx, u); err != nil {
		s.logger.Error("SSO: provisioning failed", zap.Error(err))
		return nil, externalErrUnavailable
	}
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE users SET idp_id = $1, external_user_id = $2 WHERE id = $3 AND org_id = $4`,
		idp.ID, externalID, u.ID, org.ID); err != nil {
		s.logger.Warn("SSO: could not write the federated link for a provisioned user", zap.Error(err))
	}
	audit("sso_user_provisioned", u.ID, map[string]interface{}{"email": email})
	return u, ""
}

// syncFederatedGroups applies idp.GroupMapping: for every mapped group the
// user is added when the provider's groups claim carries the mapped value
// and removed when it does not. Groups the mapping does not name are never
// touched. An external user joins only an external_allowed group.
func (s *Service) syncFederatedGroups(ctx context.Context, idp *identity.IdentityProvider, userID string, external bool, upstream []string) {
	if len(idp.GroupMapping) == 0 {
		return
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return
	}
	have := map[string]bool{}
	for _, g := range upstream {
		have[g] = true
	}
	want := map[string]bool{}
	mapped := map[string]bool{}
	for _, e := range idp.GroupMapping {
		mapped[e.GroupID] = true
		if have[e.ClaimValue] {
			want[e.GroupID] = true
		}
	}
	for gid := range mapped {
		if want[gid] {
			if external {
				var allowed bool
				if err := s.db.Pool.QueryRow(ctx,
					`SELECT external_allowed FROM groups WHERE id = $1::uuid AND org_id = $2`, gid, org.ID).Scan(&allowed); err != nil || !allowed {
					s.logger.Info("SSO: group mapping skipped for an external user", zap.String("group_id", gid), zap.Error(externalid.ErrGroupNotExternal))
					continue
				}
			}
			if _, err := s.db.Pool.Exec(ctx,
				`INSERT INTO group_memberships (group_id, user_id, joined_at, org_id)
				 SELECT $1::uuid, $2::uuid, NOW(), $3
				  WHERE EXISTS (SELECT 1 FROM groups WHERE id = $1::uuid AND org_id = $3)
				    AND NOT EXISTS (SELECT 1 FROM group_memberships WHERE group_id = $1::uuid AND user_id = $2::uuid AND org_id = $3)`,
				gid, userID, org.ID); err != nil {
				s.logger.Warn("SSO: group mapping add failed", zap.String("group_id", gid), zap.Error(err))
			}
			continue
		}
		if _, err := s.db.Pool.Exec(ctx,
			`DELETE FROM group_memberships WHERE group_id = $1::uuid AND user_id = $2::uuid AND org_id = $3`,
			gid, userID, org.ID); err != nil {
			s.logger.Warn("SSO: group mapping remove failed", zap.String("group_id", gid), zap.Error(err))
		}
	}
}

// recordSessionIdP stamps which identity provider established a session, so
// the OpenIDX ID token can carry an idp claim. Stored in Redis beside the
// session: sessions has no column for it, and it lives as long as the session
// could.
func (s *Service) recordSessionIdP(ctx context.Context, sessionID, idpID string) {
	if sessionID == "" || idpID == "" || s.redis == nil {
		return
	}
	s.redis.Client.Set(ctx, "session_idp:"+sessionID, idpID, 30*24*time.Hour)
}

// sessionIdP is the identity provider that established sessionID, or "".
func (s *Service) sessionIdP(ctx context.Context, sessionID []string) string {
	if len(sessionID) == 0 || sessionID[0] == "" || s.redis == nil || s.redis.Client == nil {
		return ""
	}
	v, _ := s.redis.Client.Get(ctx, "session_idp:"+sessionID[0]).Result()
	return v
}
