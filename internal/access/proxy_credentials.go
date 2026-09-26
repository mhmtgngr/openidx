package access

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// proxySessionCookie carries a proxy session. It is the proxy's credential and
// nobody else's: the applications behind the proxy are never sent it.
const proxySessionCookie = "_openidx_proxy_session"

// proxyIdentityHeaders tell an upstream who the caller is. The proxy writes
// them from the verified session and from nothing else: a caller's own copies
// are deleted before anything is written, and a route's custom_headers cannot
// set them. The list is the X-Forwarded-* identity names the proxy and
// forward-auth write, the ones oauth2-proxy writes in the same namespace, and
// the overlay's X-Ziti-Identity; proxyIdentityHeaderPrefix adds oauth2-proxy's
// X-Auth-Request-* family, which an application moved from behind oauth2-proxy
// still believes.
var proxyIdentityHeaders = []string{
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Name",
	"X-Forwarded-Roles",
	"X-Forwarded-Groups",
	"X-Forwarded-Preferred-Username",
	"X-Forwarded-Access-Token",
	"X-Forwarded-Route",
	"X-Risk-Score",
	"X-Ziti-Identity",
}

const proxyIdentityHeaderPrefix = "X-Auth-Request-"

// isProxyIdentityHeader reports whether name, in any case, is one of the
// headers only the proxy may write.
func isProxyIdentityHeader(name string) bool {
	canon := http.CanonicalHeaderKey(strings.TrimSpace(name))
	for _, h := range proxyIdentityHeaders {
		if canon == h {
			return true
		}
	}
	return strings.HasPrefix(canon, proxyIdentityHeaderPrefix)
}

// identityCustomHeader returns the first of a route's custom_headers that only
// the proxy may write, or "" when there is none. The route API refuses such a
// route rather than store a header proxyRewrite would then skip in silence.
func identityCustomHeader(headers map[string]string) string {
	var names []string
	for name := range headers {
		if isProxyIdentityHeader(name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[0]
}

// deleteProxyOwnedHeaders removes from an outbound request every header the
// proxy asserts about the caller: the identity headers and X-Real-IP.
func deleteProxyOwnedHeaders(h http.Header) {
	for _, name := range proxyOwnedHeaders {
		h.Del(name)
	}
	for name := range h {
		if isProxyIdentityHeader(name) {
			delete(h, name)
		}
	}
}

// stripProxySessionCookie removes the proxy's session cookie from h's Cookie
// header and leaves every other cookie as the browser sent it. It reports
// whether there was one to remove.
func stripProxySessionCookie(h http.Header) bool {
	lines := h.Values("Cookie")
	kept := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		if !strings.Contains(line, proxySessionCookie) {
			kept = append(kept, line)
			continue
		}
		var parts []string
		for _, part := range strings.Split(line, ";") {
			p := strings.TrimSpace(part)
			if name, _, _ := strings.Cut(p, "="); strings.TrimSpace(name) == proxySessionCookie {
				removed = true
				continue
			}
			if p != "" {
				parts = append(parts, p)
			}
		}
		if len(parts) > 0 {
			kept = append(kept, strings.Join(parts, "; "))
		}
	}
	if !removed {
		return false
	}
	h.Del("Cookie")
	for _, line := range kept {
		h.Add("Cookie", line)
	}
	return true
}

// removeHeaderValue deletes the values of h[name] equal to value and keeps the
// rest.
func removeHeaderValue(h http.Header, name, value string) {
	vals := h.Values(name)
	if len(vals) == 0 {
		return
	}
	h.Del(name)
	for _, v := range vals {
		if v != value {
			h.Add(name, v)
		}
	}
}

// sessionHost is the name a proxy session is bound to: the host the browser
// addressed, without a port, in lower case. The session cookie is host-only
// (it names no Domain), and a browser sends a cookie to its host on any port,
// so this is exactly the set of requests the cookie was issued for.
func sessionHost(host string) string {
	h := strings.TrimSpace(host)
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"))
}

// browserHost is the host the browser addressed: the request's own Host,
// unless an edge that rewrote it to the service's internal name passed the
// original on in X-Forwarded-Host, which is also where the callback takes the
// host of its redirect_uri from.
func (s *Service) browserHost(c *gin.Context) string {
	host := c.Request.Host
	internal := s.config != nil && host == fmt.Sprintf("access-service:%d", s.config.Port)
	if host == "" || internal {
		if fwd, _, _ := strings.Cut(c.GetHeader("X-Forwarded-Host"), ","); strings.TrimSpace(fwd) != "" {
			host = strings.TrimSpace(fwd)
		}
	}
	return host
}

// writeForwardAuthHeaders puts on an allowing forward-auth answer the request
// headers the edge is to give the upstream in place of the caller's.
//
// The edge's forward-auth plugin copies the headers it lists as upstream
// headers from this answer onto the upstream request, and passes the caller's
// own copy of any header the answer leaves out. So every identity header is
// answered, empty where the route needs no sign-in or the session lacks the
// value, rather than left to the caller. A Cookie header that carried the
// proxy's session cookie is answered without it, and an Authorization header
// the access service authenticated this request with is answered empty.
// Written with Header().Set, because gin's c.Header deletes a header whose
// value is empty, which here would hand the caller's copy through.
func writeForwardAuthHeaders(c *gin.Context, session *ProxySession, routeName string, riskScore string, consumedAuthorization bool) {
	h := c.Writer.Header()
	var user, email, name, roles string
	if session != nil {
		user, email, name, roles = session.UserID, session.Email, session.Name, strings.Join(session.Roles, ",")
	}
	h.Set("X-Forwarded-User", user)
	h.Set("X-Forwarded-Email", email)
	h.Set("X-Forwarded-Name", name)
	h.Set("X-Forwarded-Roles", roles)
	h.Set("X-Forwarded-Route", routeName)
	h.Set("X-Risk-Score", riskScore)

	cookies := http.Header{"Cookie": c.Request.Header.Values("Cookie")}
	if stripProxySessionCookie(cookies) {
		h.Set("Cookie", strings.Join(cookies.Values("Cookie"), "; "))
	}
	if consumedAuthorization {
		h.Set("Authorization", "")
	}
}
