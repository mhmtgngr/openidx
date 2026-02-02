// Package access - Multi-IDP routing for zero-trust proxy authentication
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// IDPConfig represents an identity provider configuration loaded from the database
type IDPConfig struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	ProviderType string   `json:"provider_type"` // "oidc" or "saml"
	IssuerURL    string   `json:"issuer_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"-"`
	Scopes       []string `json:"scopes"`
	Enabled      bool     `json:"enabled"`
}

// getRouteIDP loads the IDP configuration for a route. Returns nil if the route uses the default IDP.
func (s *Service) getRouteIDP(ctx context.Context, route *ProxyRoute) (*IDPConfig, error) {
	if route.IDPId == "" {
		return nil, nil
	}

	var idp IDPConfig
	var scopesJSON []byte

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, provider_type, issuer_url, client_id, client_secret, scopes, enabled
		 FROM identity_providers WHERE id=$1`, route.IDPId).
		Scan(&idp.ID, &idp.Name, &idp.ProviderType, &idp.IssuerURL,
			&idp.ClientID, &idp.ClientSecret, &scopesJSON, &idp.Enabled)
	if err != nil {
		return nil, fmt.Errorf("failed to load IDP %s: %w", route.IDPId, err)
	}

	if scopesJSON != nil {
		if err := json.Unmarshal(scopesJSON, &idp.Scopes); err != nil {
			s.logger.Warn("Failed to unmarshal IDP scopes", zap.String("idp_id", idp.ID), zap.Error(err))
		}
	}
	if len(idp.Scopes) == 0 {
		idp.Scopes = []string{"openid", "profile", "email"}
	}

	return &idp, nil
}

// listEnabledIDPs returns all enabled identity providers
func (s *Service) listEnabledIDPs(ctx context.Context) ([]IDPConfig, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, name, provider_type, issuer_url, client_id, scopes, enabled
		 FROM identity_providers WHERE enabled=true ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("failed to query IDPs: %w", err)
	}
	defer rows.Close()

	var idps []IDPConfig
	for rows.Next() {
		var idp IDPConfig
		var scopesJSON []byte
		err := rows.Scan(&idp.ID, &idp.Name, &idp.ProviderType, &idp.IssuerURL,
			&idp.ClientID, &scopesJSON, &idp.Enabled)
		if err != nil {
			s.logger.Warn("Failed to scan IDP row", zap.Error(err))
			continue
		}
		if scopesJSON != nil {
			json.Unmarshal(scopesJSON, &idp.Scopes)
		}
		idps = append(idps, idp)
	}

	if idps == nil {
		idps = []IDPConfig{}
	}
	return idps, nil
}

// handleIDPDiscovery lists available IDPs, optionally filtered by route_id
func (s *Service) handleIDPDiscovery(c *gin.Context) {
	routeID := c.Query("route_id")

	if routeID != "" {
		// Return the specific IDP for this route
		route, err := s.getRouteByID(c.Request.Context(), routeID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}

		idp, err := s.getRouteIDP(c.Request.Context(), route)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if idp != nil {
			c.JSON(http.StatusOK, gin.H{
				"idps":    []IDPConfig{*idp},
				"default": false,
			})
			return
		}

		// No specific IDP, return default info
		c.JSON(http.StatusOK, gin.H{
			"idps": []gin.H{{
				"id":            "default",
				"name":          "OpenIDX OAuth",
				"provider_type": "oidc",
				"issuer_url":    s.oauthIssuer,
				"enabled":       true,
			}},
			"default": true,
		})
		return
	}

	// List all enabled IDPs
	idps, err := s.listEnabledIDPs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Prepend default OpenIDX OAuth
	allIDPs := []gin.H{{
		"id":            "default",
		"name":          "OpenIDX OAuth",
		"provider_type": "oidc",
		"issuer_url":    s.oauthIssuer,
		"enabled":       true,
	}}
	for _, idp := range idps {
		allIDPs = append(allIDPs, gin.H{
			"id":            idp.ID,
			"name":          idp.Name,
			"provider_type": idp.ProviderType,
			"issuer_url":    idp.IssuerURL,
			"enabled":       idp.Enabled,
		})
	}

	c.JSON(http.StatusOK, gin.H{"idps": allIDPs})
}

// handleLoginWithIDP handles the OAuth login flow for a specific external IDP
func (s *Service) handleLoginWithIDP(c *gin.Context, idpID string) {
	ctx := c.Request.Context()

	// Load the IDP
	var idp IDPConfig
	var scopesJSON []byte
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, provider_type, issuer_url, client_id, client_secret, scopes
		 FROM identity_providers WHERE id=$1 AND enabled=true`, idpID).
		Scan(&idp.ID, &idp.Name, &idp.ProviderType, &idp.IssuerURL,
			&idp.ClientID, &idp.ClientSecret, &scopesJSON)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IDP not found or not enabled"})
		return
	}
	if scopesJSON != nil {
		if err := json.Unmarshal(scopesJSON, &idp.Scopes); err != nil {
			s.logger.Warn("Failed to unmarshal IDP scopes", zap.String("idp_id", idp.ID), zap.Error(err))
		}
	}
	if len(idp.Scopes) == 0 {
		idp.Scopes = []string{"openid", "profile", "email"}
	}

	// Generate PKCE
	verifier := generateCodeVerifier()
	challenge := generateCodeChallenge(verifier)
	state := generateState()

	redirectURL := c.Query("redirect_url")
	if redirectURL == "" {
		redirectURL = "/"
	}

	// Store state with IDP info
	sessionData, _ := json.Marshal(map[string]string{
		"verifier":     verifier,
		"redirect_url": redirectURL,
		"idp_id":       idp.ID,
		"idp_issuer":   idp.IssuerURL,
	})
	s.redis.Client.Set(ctx, "access_oauth_state:"+state, sessionData, 10*time.Minute)

	// Build callback URL
	callbackURL := fmt.Sprintf("http://%s:%d/access/.auth/callback",
		s.config.AccessProxyDomain, s.config.Port)

	// Build auth URL using the external IDP
	scopeStr := url.QueryEscape(joinScopes(idp.Scopes))
	authURL := fmt.Sprintf("%s/authorize?client_id=%s&response_type=code&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=%s&scope=%s",
		idp.IssuerURL,
		url.QueryEscape(idp.ClientID),
		url.QueryEscape(callbackURL),
		url.QueryEscape(challenge),
		url.QueryEscape(state),
		scopeStr)

	c.Redirect(http.StatusFound, authURL)
}

// handleCallbackWithIDP handles the OAuth callback for an external IDP
func (s *Service) handleCallbackWithIDP(c *gin.Context, idpID, idpIssuer, verifier, redirectURL string) {
	code := c.Query("code")

	// Load the IDP to get client_secret
	var clientID, clientSecret string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT client_id, client_secret FROM identity_providers WHERE id=$1",
		idpID).Scan(&clientID, &clientSecret)
	if err != nil {
		s.logger.Error("Failed to load IDP for callback", zap.String("idp_id", idpID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
		return
	}

	callbackURL := fmt.Sprintf("http://%s:%d/access/.auth/callback",
		s.config.AccessProxyDomain, s.config.Port)

	// Exchange code with the external IDP
	tokenResp, err := s.exchangeCodeWithIDP(c.Request.Context(), idpIssuer, clientID, clientSecret, code, verifier, callbackURL)
	if err != nil {
		s.logger.Error("Failed to exchange code with external IDP", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
		return
	}

	// Parse the access token (or ID token) claims
	tokenToParse := tokenResp.AccessToken
	if tokenResp.IDToken != "" {
		tokenToParse = tokenResp.IDToken
	}

	claims, err := s.parseTokenClaims(tokenToParse)
	if err != nil {
		s.logger.Error("Failed to parse token from external IDP", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse token"})
		return
	}

	// Create proxy session
	session, err := s.createSession(c, claims, tokenResp.AccessToken)
	if err != nil {
		s.logger.Error("Failed to create session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	// Store IDP ID on the session
	s.db.Pool.Exec(c.Request.Context(),
		"UPDATE proxy_sessions SET idp_id=$1 WHERE id=$2", idpID, session.ID)

	// Set session cookie
	c.SetCookie(
		"_openidx_proxy_session",
		session.SessionToken,
		session.AbsoluteTimeout(),
		"/", "", false, true,
	)

	s.logAuditEvent(c, "proxy_session_created", session.UserID, "session", map[string]interface{}{
		"session_id": session.ID,
		"email":      session.Email,
		"idp_id":     idpID,
	})

	if redirectURL == "" {
		redirectURL = "/"
	}
	c.Redirect(http.StatusFound, redirectURL)
}

// exchangeCodeWithIDP exchanges an authorization code with an external IDP's token endpoint
func (s *Service) exchangeCodeWithIDP(ctx context.Context, issuerURL, clientID, clientSecret, code, verifier, redirectURI string) (*tokenResponse, error) {
	tokenURL := issuerURL + "/token"

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}

	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange with IDP failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("IDP token exchange returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode IDP token response: %w", err)
	}

	return &tokenResp, nil
}

func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}
