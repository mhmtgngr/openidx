package oauth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// authorizeParams is where an authorization request's parameters are read
// from. OpenID Connect Core §3.1.2.1: the authorization endpoint MUST support
// GET and POST; with GET the parameters are in the query string, with POST they
// are the form-encoded body.
//
// The accessor is named Query on purpose. Two source censuses key on
// `.Query("<name>")` calls: internal/common/middleware/query_param_census_test.go
// (every query parameter must be redacted in the request log or declared
// public) and pkce_policy_test.go (every function that reads code_challenge
// from a request enforces PKCE). A GET still carries these names in the query
// string the request logger writes, so both censuses must keep seeing them.
type authorizeParams struct{ values url.Values }

// Query returns the named authorization request parameter, from the query
// string of a GET or the body of a form POST.
func (p authorizeParams) Query(key string) string { return p.values.Get(key) }

// authorizeRequestParams returns the parameters of the authorization request c
// carries. A POST contributes its form body only (OIDC Core §3.1.2.1, Form
// Serialization), not its query string: a request whose parameters are split
// across the two is not one the specification describes. A body that does not
// parse yields no parameters, which the handler refuses as a request without a
// client_id.
func authorizeRequestParams(c *gin.Context) authorizeParams {
	if c.Request.Method == http.MethodPost {
		if err := c.Request.ParseForm(); err != nil {
			return authorizeParams{values: url.Values{}}
		}
		return authorizeParams{values: c.Request.PostForm}
	}
	return authorizeParams{values: c.Request.URL.Query()}
}

// isFormPost reports whether the request body is application/x-www-form-urlencoded,
// the only serialization OIDC Core §3.1.2.1 allows for a POSTed authorization
// request.
func isFormPost(c *gin.Context) bool {
	ct := c.GetHeader("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}

// handleAuthorizePost is the first handler on POST /oauth/authorize. That path
// is two endpoints:
//
//   - the OIDC authorization endpoint, which a relying party may POST to with a
//     form-encoded authorization request instead of a GET (§3.1.2.1). The
//     conformance suite's oidcc-ensure-post-request-succeeds does exactly
//     that, and got 401: the path was only the consent endpoint;
//   - the older consent endpoint, handleAuthorizeConsent, which takes a JSON
//     body and an authenticated session.
//
// The Content-Type tells them apart, and nothing else is needed. A form body
// could never have reached the consent handler with any effect: it binds JSON
// only (ShouldBindJSON), so a form-encoded consent submission was already a
// 400. Diverting form posts therefore changes no request that worked before,
// and a JSON post goes on, unchanged, through flowAuth to the consent handler.
//
// The authorization request is served by handleAuthorize itself, so a POST is
// validated, redirected and stashed exactly as the same parameters would be on
// a GET, and it runs WITHOUT flowAuth: the authorization endpoint is public,
// and a relying party's browser has no bearer token to present. One difference
// is the browser's, not the server's: a cross-site POST does not carry the
// SameSite=Lax openidx_sso cookie, so a POSTed request from another site goes
// to the login page rather than completing single sign-on.
func (s *Service) handleAuthorizePost(c *gin.Context) {
	if !isFormPost(c) {
		return // not an authorization request: the consent chain runs next
	}
	s.handleAuthorize(c)
	c.Abort()
}

// requestObjectRefusal answers an authorization request that carries a request
// object, by value (`request`) or by reference (`request_uri`).
//
// This server does not process request objects, and discovery says so
// (request_parameter_supported and request_uri_parameter_supported are both
// false). Before this, the parameters were ignored: the request went on with
// whatever sat outside the object, so a `state` or `nonce` the client put only
// inside it was silently lost -- the client got back a response it could not
// correlate, and an ID token without the nonce it asked for. OIDC Core §6.1
// and §6.2 let a server that does not support them say so with
// request_not_supported / request_uri_not_supported (§3.1.2.6), reported at the
// redirect_uri like every other request error, which is what this returns.
//
// The object is not opened: `state` is echoed from outside it when present,
// and one that exists only inside it is not returned (the conformance suite
// expects exactly that for a server that refuses request objects).
func requestObjectRefusal(p authorizeParams) (code, description string, refused bool) {
	switch {
	case p.Query("request") != "":
		return ErrorRequestNotSupported, "request objects (the request parameter) are not supported", true
	case p.Query("request_uri") != "":
		return ErrorRequestURINotSupported, "the request_uri parameter is not supported", true
	}
	return "", "", false
}
