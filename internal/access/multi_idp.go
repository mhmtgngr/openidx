// Package access - Multi-IDP routing for zero-trust proxy authentication
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
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

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var idp IDPConfig
	var scopesJSON []byte

	err = s.db.Pool.QueryRow(ctx,
		`SELECT id, name, provider_type, issuer_url, client_id, client_secret, scopes, enabled
		 FROM identity_providers WHERE id=$1 AND org_id=$2`, route.IDPId, org.ID).
		Scan(&idp.ID, &idp.Name, &idp.ProviderType, &idp.IssuerURL,
			&idp.ClientID, &idp.ClientSecret, &scopesJSON, &idp.Enabled)
	if err != nil {
		return nil, fmt.Errorf("failed to load IDP %s: %w", route.IDPId, err)
	}
	if idp.ClientSecret, err = s.idpCipher.Decrypt(idp.ClientSecret); err != nil {
		return nil, fmt.Errorf("decrypt IDP client_secret: %w", err)
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
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, name, provider_type, issuer_url, client_id, scopes, enabled
		 FROM identity_providers WHERE enabled=true AND org_id=$1 ORDER BY name`, org.ID)
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
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("i d p discovery", err), s.logger)
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
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("i d p discovery", err), s.logger)
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

// idpEnabledInOrg reports whether idpID is an enabled identity provider of the
// request's organization. The proxy no longer talks to it (B1.5); it only
// refuses a hint that OpenIDX's /oauth/authorize would refuse anyway, with an
// answer the person can read.
func (s *Service) idpEnabledInOrg(ctx context.Context, idpID string) (bool, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}
	var ok bool
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM identity_providers WHERE id::text=$1 AND enabled=true AND org_id=$2)`,
		idpID, org.ID).Scan(&ok); err != nil {
		return false, nil
	}
	return ok, nil
}

// federatedIdP returns the idp claim of the id_token OpenIDX returned from the
// proxy's own back-channel code exchange: empty for a local sign-in.
func federatedIdP(s *Service, tok *tokenResponse) string {
	if tok == nil || tok.IDToken == "" {
		return ""
	}
	claims, err := s.parseTokenClaims(tok.IDToken)
	if err != nil {
		return ""
	}
	idp, _ := claims["idp"].(string)
	return idp
}
