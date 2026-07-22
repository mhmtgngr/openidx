// Package oauth - OAuth 2.0 authorization consent enforcement.
//
// application_sso_settings.require_consent has long been an admin-settable flag
// that nothing enforced: the authorization endpoint issued codes without ever
// asking the user to approve the client and scopes. This wires that flag into
// the code-issuance choke points. When an application requires consent and the
// user has not already granted the requested scopes, the flow pauses and returns
// a consent challenge; the browser renders an approval screen and posts the
// decision to /oauth/consent, which records the grant (so future logins skip the
// prompt unless the requested scopes widen) and then issues the code.
package oauth

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// consentSessionTTL bounds how long a pending consent decision is valid.
const consentSessionTTL = 5 * time.Minute

// consentRequired reports whether the given client requires user consent for the
// requested scopes and the user has not already granted them. It fails open to
// "not required" only when consent cannot be configured for this request (no org
// context / no SSO settings row), matching the platform's prior behavior; any
// such case is logged.
func (s *Service) consentRequired(ctx context.Context, clientID, userID, scope string) (bool, error) {
	if clientID == "" || userID == "" {
		return false, nil
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		// No tenant context: cannot resolve application_sso_settings; preserve
		// existing behavior (no consent) but make it visible.
		s.logger.Debug("consent check skipped: no org context", zap.String("client_id", clientID))
		return false, nil
	}

	var requireConsent bool
	err = s.db.Pool.QueryRow(ctx, `
		SELECT ass.require_consent
		FROM application_sso_settings ass
		JOIN applications a ON a.id = ass.application_id
		WHERE a.client_id = $1 AND a.org_id = $2
	`, clientID, org.ID).Scan(&requireConsent)
	if err != nil {
		// No SSO settings row for this client → consent not configured.
		return false, nil
	}
	if !requireConsent {
		return false, nil
	}

	// Consent is required for the app. Has the user already granted a superset of
	// the requested scopes to this client?
	var grantedScopes string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT scopes FROM oauth_user_consents
		WHERE org_id = $1 AND user_id = $2 AND client_id = $3
	`, org.ID, userID, clientID).Scan(&grantedScopes)
	if err != nil {
		// No prior consent on record → must prompt.
		return true, nil
	}

	if scopesCovered(grantedScopes, scope) {
		return false, nil
	}
	return true, nil
}

// scopesCovered reports whether every scope in requested appears in granted.
func scopesCovered(granted, requested string) bool {
	grantedSet := make(map[string]struct{})
	for _, g := range strings.Fields(granted) {
		grantedSet[g] = struct{}{}
	}
	for _, r := range strings.Fields(requested) {
		if _, ok := grantedSet[r]; !ok {
			return false
		}
	}
	return true
}

// recordConsent upserts the user's grant of the given scopes to the client,
// merging with any previously granted scopes so consent is cumulative.
func (s *Service) recordConsent(ctx context.Context, clientID, userID, scope string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Merge with any existing grant so a narrower later request doesn't shrink it.
	var existing string
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT scopes FROM oauth_user_consents
		WHERE org_id = $1 AND user_id = $2 AND client_id = $3
	`, org.ID, userID, clientID).Scan(&existing)

	merged := mergeScopes(existing, scope)

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_user_consents (org_id, user_id, client_id, scopes, granted_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (org_id, user_id, client_id)
		DO UPDATE SET scopes = $4, updated_at = NOW()
	`, org.ID, userID, clientID, merged)
	return err
}

// mergeScopes returns the union of two space-delimited scope strings, preserving
// first-seen order.
func mergeScopes(a, b string) string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range append(strings.Fields(a), strings.Fields(b)...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

// beginConsent stashes the pending authorization parameters and returns a consent
// challenge for the browser to render. The subject (userID) is captured
// server-side here, so the later decision cannot be redirected to another user.
func (s *Service) beginConsent(c *gin.Context, oauthParams map[string]string, userID string) {
	token := GenerateRandomToken(32)

	stash := map[string]string{"user_id": userID}
	for k, v := range oauthParams {
		stash[k] = v
	}
	payload, err := json.Marshal(stash)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	if err := s.redis.Client.Set(c.Request.Context(), "oauth_consent:"+token, string(payload), consentSessionTTL).Err(); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	clientName := oauthParams["client_id"]
	if client, cerr := s.GetClient(c.Request.Context(), oauthParams["client_id"]); cerr == nil && client.Name != "" {
		clientName = client.Name
	}

	c.JSON(200, gin.H{
		"consent_required": true,
		"consent_session":  token,
		"client_id":        oauthParams["client_id"],
		"client_name":      clientName,
		"scopes":           strings.Fields(oauthParams["scope"]),
	})
}

// handleConsentDecision records or rejects a user's consent and, on approval,
// issues the authorization code. POST /oauth/consent.
func (s *Service) handleConsentDecision(c *gin.Context) {
	var req struct {
		ConsentSession string `json:"consent_session"`
		Approve        bool   `json:"approve"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.ConsentSession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "consent_session is required"})
		return
	}
	if !isValidSessionID(req.ConsentSession) {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid consent_session"})
		return
	}

	ctx := c.Request.Context()
	stashJSON, err := s.redis.Client.Get(ctx, "oauth_consent:"+req.ConsentSession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired consent session"})
		return
	}
	// One-time use.
	s.redis.Client.Del(ctx, "oauth_consent:"+req.ConsentSession)

	var stash map[string]string
	if err := json.Unmarshal([]byte(stashJSON), &stash); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	userID := stash["user_id"]
	if userID == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "consent session missing subject"})
		return
	}

	// Denied: bounce back to the client with an OAuth error.
	if !req.Approve {
		redirectURL, perr := url.Parse(stash["redirect_uri"])
		if perr != nil {
			c.JSON(200, gin.H{"error": "access_denied"})
			return
		}
		query := redirectURL.Query()
		query.Set("error", "access_denied")
		query.Set("error_description", "user denied consent")
		if stash["state"] != "" {
			query.Set("state", stash["state"])
		}
		redirectURL.RawQuery = query.Encode()
		s.logAuditEvent(ctx, "authentication", "oauth", "consent", "denied",
			userID, c.ClientIP(), stash["client_id"], "client",
			map[string]interface{}{"client_id": stash["client_id"]})
		c.JSON(200, gin.H{"redirect_url": redirectURL.String()})
		return
	}

	// Approved: persist the grant, then issue the code (bypassing the re-check).
	if err := s.recordConsent(ctx, stash["client_id"], userID, stash["scope"]); err != nil {
		s.logger.Error("failed to record consent", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	s.logAuditEvent(ctx, "authentication", "oauth", "consent", "granted",
		userID, c.ClientIP(), stash["client_id"], "client",
		map[string]interface{}{"client_id": stash["client_id"], "scope": stash["scope"]})

	stash["consent_granted"] = "true"
	s.issueAuthorizationCode(c, stash, userID)
}
