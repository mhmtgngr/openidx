package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// oauthProtocolPaths are the endpoints a browser-based OAuth client on ANY
// origin must be able to call: the token, introspection, revocation, userinfo,
// device-authorization and dynamic-registration endpoints, plus discovery and
// the JWKS. A single-page app registered as a public client (PKCE) lives on the
// relying party's origin, not ours, and there is no list of relying-party
// origins that an identity provider could maintain — that is what client
// registration is for. Every mainstream IdP answers these with
// Access-Control-Allow-Origin: * for the same reason.
//
// This is safe because "*" is never combined with Allow-Credentials: the
// browser will not attach cookies to such a request, so a cross-origin page
// cannot ride a user's session. Credentials on these endpoints are explicit
// (client secret, bearer token, code + PKCE verifier), carried in the body or
// the Authorization header by the calling script, which is exactly what CORS
// exists to permit.
//
// Everything else the oauth-service serves — the login and MFA pages, consent,
// the step-up and passwordless flows — is session-carrying UI and follows the
// configured origin list like every other service.
var oauthProtocolPaths = []string{
	"/oauth/token",
	"/oauth/introspect",
	"/oauth/revoke",
	"/oauth/userinfo",
	"/oauth/device_authorization",
	"/oauth/register",
	"/oauth/jwks",
	"/.well-known/",
}

// IsOAuthProtocolPath reports whether path is one of the cross-origin-by-design
// OAuth/OIDC protocol endpoints.
func IsOAuthProtocolPath(path string) bool {
	for _, p := range oauthProtocolPaths {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(path, p) {
				return true
			}
			continue
		}
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// OAuthCORS is the oauth-service's CORS policy (global-scale plan task 0.6).
//
// It replaces an unconditional `Access-Control-Allow-Origin: *` on every
// response, which contradicted the production gate that refuses a wildcard
// CORS_ALLOWED_ORIGINS: the gate held for seven services and the eighth wrote
// the wildcard by hand. The two halves are now explicit. Protocol endpoints
// (see oauthProtocolPaths) answer "*" while protocolWildcard is true — the
// deliberate, credential-free exception the standard needs. Every other path
// goes through the shared CORS middleware with the configured origin list, so
// a disallowed origin is refused rather than reflected.
func OAuthCORS(protocolWildcard bool, allowedOrigins ...string) gin.HandlerFunc {
	uiCORS := CORS(allowedOrigins...)
	return func(c *gin.Context) {
		if protocolWildcard && IsOAuthProtocolPath(c.Request.URL.Path) {
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
			c.Header("Access-Control-Max-Age", "86400")
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
			return
		}
		uiCORS(c)
	}
}
