package access

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// redirectTarget returns raw when it names a place the proxy may send a
// browser after sign-in or sign-out, and fallback otherwise. Every redirect_url
// the proxy follows goes through it: the one /access/.auth/login stores for
// after sign-in (both the OpenIDX and the external identity provider flows,
// checked again when the callback follows it) and the one
// /access/.auth/logout follows straight away.
//
// Those links are public, and redirect_url used to be followed as given, so a
// link on a proxied application's own host could send the browser anywhere its
// author chose, right after a genuine OpenIDX sign-in or sign-out.
//
// A target passes when it is
//
//   - a path on the same host: one leading slash, not two, and no backslash,
//     which browsers read as a slash; or
//   - an absolute http(s) URL with no user information, whose host is the
//     access service's own (ACCESS_PROXY_DOMAIN, with or without the service's
//     port) or the host of one of the organization's enabled proxy routes.
//
// Hosts are compared exactly, so a case or trailing-dot variant of an allowed
// host does not pass, and neither does anything carrying a control character,
// a space or a byte outside ASCII, which browsers strip or rewrite before they
// parse.
func (s *Service) redirectTarget(c *gin.Context, raw, fallback string) string {
	if raw == "" {
		return fallback
	}
	for i := 0; i < len(raw); i++ {
		if b := raw[i]; b <= ' ' || b >= 0x7f || b == '\\' {
			return fallback
		}
	}
	if strings.HasPrefix(raw, "/") {
		if strings.HasPrefix(raw, "//") {
			return fallback
		}
		return raw
	}
	u, err := url.Parse(raw)
	// No user information: https://other.example@host/ goes to host, but it
	// reads as the other site to whoever is asked to follow it.
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Host == "" {
		return fallback
	}
	if !s.redirectHostAllowed(c, u.Host) {
		return fallback
	}
	return raw
}

// redirectHostAllowed reports whether host, exactly as a target URL carries
// it, is the access service's own or one of the organization's route hosts.
func (s *Service) redirectHostAllowed(c *gin.Context, host string) bool {
	if s.config != nil {
		if own := strings.ToLower(strings.TrimSpace(s.config.AccessProxyDomain)); own != "" {
			if host == own || (s.config.Port != 0 && host == own+":"+strconv.Itoa(s.config.Port)) {
				return true
			}
		}
	}
	orgID := s.redirectOrgID(c)
	if orgID == "" || s.db == nil {
		return false
	}
	ctx := c.Request.Context()
	rows, err := s.db.Pool.Query(orgctx.WithBypassRLS(ctx),
		// The organization comes from the route serving this host, which can
		// differ from the one the tenant resolver attached, so the belt is
		// lifted and the query names it instead.
		`SELECT from_url FROM proxy_routes WHERE org_id = $1::uuid AND enabled = true`, orgID)
	if err != nil {
		s.logger.Warn("could not read the organization's route hosts; refusing the redirect target",
			zap.Error(err))
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var fromURL string
		if err := rows.Scan(&fromURL); err != nil {
			continue
		}
		if u, perr := url.Parse(strings.TrimSpace(fromURL)); perr == nil && u.Host != "" &&
			strings.ToLower(u.Host) == host {
			return true
		}
	}
	return false
}

// redirectOrgID is the organization whose route hosts a redirect may name: the
// one that owns the route serving the request's host, which is the
// application the browser is signing in to, or, on a host no route serves
// (the access service's own), the organization the tenant resolver attached.
func (s *Service) redirectOrgID(c *gin.Context) string {
	ctx := c.Request.Context()
	if host := c.Request.Host; host != "" && s.db != nil {
		if route, err := s.findRouteByHost(ctx, host); err == nil && route != nil && route.OrgID != "" {
			return route.OrgID
		}
	}
	if org, err := orgctx.From(ctx); err == nil {
		return org.ID
	}
	return ""
}
