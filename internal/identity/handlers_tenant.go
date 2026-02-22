package identity

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// handleGetLoginBranding returns tenant branding for the login page based on domain or org slug.
// This is a PUBLIC endpoint (no auth required).
func (s *Service) handleGetLoginBranding(c *gin.Context) {
	domain := c.Query("domain")
	org := c.Query("org")

	defaults := gin.H{
		"logo_url":           "",
		"favicon_url":        "",
		"primary_color":      "#1e40af",
		"secondary_color":    "#3b82f6",
		"background_color":   "#f8fafc",
		"background_image_url": "",
		"login_page_title":   "Sign In",
		"login_page_message": "",
		"portal_title":       "OpenIDX Portal",
		"custom_css":         "",
		"custom_footer":      "",
		"powered_by_visible": true,
	}

	var query string
	var arg interface{}

	if domain != "" {
		// Look up by tenant domain mapping
		query = `SELECT tb.logo_url, tb.favicon_url, tb.primary_color, tb.secondary_color,
			tb.background_color, tb.background_image_url, tb.login_page_title,
			tb.login_page_message, tb.portal_title, tb.custom_css, tb.custom_footer, tb.powered_by_visible
			FROM tenant_branding tb
			JOIN tenant_domains td ON tb.org_id = td.org_id
			WHERE td.domain = $1 AND td.verified = true`
		arg = domain
	} else if org != "" {
		// Look up by org slug
		query = `SELECT tb.logo_url, tb.favicon_url, tb.primary_color, tb.secondary_color,
			tb.background_color, tb.background_image_url, tb.login_page_title,
			tb.login_page_message, tb.portal_title, tb.custom_css, tb.custom_footer, tb.powered_by_visible
			FROM tenant_branding tb
			JOIN organizations o ON tb.org_id = o.id
			WHERE o.slug = $1`
		arg = org
	} else {
		c.JSON(http.StatusOK, defaults)
		return
	}

	var logoURL, faviconURL, primaryColor, secondaryColor, bgColor, bgImageURL string
	var loginTitle, loginMsg, portalTitle, customCSS, customFooter string
	var poweredBy bool

	err := s.db.Pool.QueryRow(c.Request.Context(), query, arg).Scan(
		&logoURL, &faviconURL, &primaryColor, &secondaryColor,
		&bgColor, &bgImageURL, &loginTitle,
		&loginMsg, &portalTitle, &customCSS, &customFooter, &poweredBy,
	)
	if err != nil {
		s.logger.Debug("No tenant branding found", zap.String("domain", domain), zap.String("org", org))
		c.JSON(http.StatusOK, defaults)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logo_url":             logoURL,
		"favicon_url":          faviconURL,
		"primary_color":        primaryColor,
		"secondary_color":      secondaryColor,
		"background_color":     bgColor,
		"background_image_url": bgImageURL,
		"login_page_title":     loginTitle,
		"login_page_message":   loginMsg,
		"portal_title":         portalTitle,
		"custom_css":           customCSS,
		"custom_footer":        customFooter,
		"powered_by_visible":   poweredBy,
	})
}
