package access

import "regexp"

// A BrowZer route's host, path, landing path and upstream are written into the
// nginx configuration the access service generates for the public vhosts, the
// hop and the shared router, and into the router's landing page, which nginx
// serves from a quoted string. Those files serve every organization, and the
// values come from a route an organization's administrator writes, which the
// route API does not check. A quote, a semicolon, a brace, a dollar sign or a
// line break in one of them ends the directive it sits in and starts another --
// a server block for another organization's host, a location that proxies
// somewhere else, a page with script on it -- or leaves a file nginx refuses to
// load, which takes BrowZer down for every organization.
//
// So a route whose values fall outside these shapes is left out of everything
// generated from queryBrowZerRoutes, and the reason is logged.
var (
	browzerHostPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	browzerPathPattern    = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	browzerLandingPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/?=&%+,:@!-]*$`)
	// An http(s) URL with a plain host or an IPv6 literal, an optional port
	// and a plain path: no user information, query or fragment.
	browzerUpstreamPattern = regexp.MustCompile(
		`^(?i:https?)://([A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?(/[A-Za-z0-9._~/%-]*)?$`)
)

// browzerRouteUnsafe returns why a BrowZer route's values cannot be written
// into generated configuration, or "" when they can.
func browzerRouteUnsafe(r browzerRouteInfo) string {
	switch {
	case !browzerHostPattern.MatchString(r.hostname):
		return "its from_url does not name a plain host"
	case !browzerPathPattern.MatchString(r.pathPrefix):
		return "its from_url path has characters nginx would read as syntax"
	case r.landingPath != "" && !browzerLandingPattern.MatchString(r.landingPath):
		return "its landing_path has characters nginx would read as syntax"
	case !browzerUpstreamPattern.MatchString(r.toURL):
		return "its to_url is not a plain http(s) URL"
	}
	return ""
}
