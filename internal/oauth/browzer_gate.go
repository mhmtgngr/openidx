package oauth

import (
	"context"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// THE CLIENTLESS SIGN-IN IS JUDGED PER APPLICATION, NOT PER CLIENT.
//
// Every BrowZer (clientless) route signs in through one OAuth client, the
// one ziti_browzer_config names. The assignment gate looked the application
// up by client_id, so for every clientless route it found the same shared
// client and never the application behind the route: assignment was never
// judged at sign-in for clientless access, and the data path cannot judge
// it either (the browser dials the overlay router directly; the dial policy
// is the floor there). The redirect_uri names the route's host, and the
// route names its application; that is the one the sign-in is for.

// browzerRedirectHost is the host a BrowZer redirect_uri returns to, lower
// case and without a port, or "" when there is none.
func browzerRedirectHost(redirectURI string) string {
	u, err := url.Parse(strings.TrimSpace(redirectURI))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// browzerRouteApp is the enabled application behind the clientless route
// whose host the redirect names, or "" when the route has none.
func (s *Service) browzerRouteApp(ctx context.Context, orgID, redirectURI string) string {
	host := browzerRedirectHost(redirectURI)
	if host == "" || s.db == nil || s.db.Pool == nil {
		return ""
	}
	var appID string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT a.id::text FROM proxy_routes r
		  JOIN applications a ON a.route_id = r.id AND a.enabled = true
		 WHERE LOWER(r.host) = $1 AND r.org_id = $2 AND r.enabled = true
		   AND COALESCE(r.browzer_enabled, false) = true
		 ORDER BY a.id LIMIT 1`, host, orgID).Scan(&appID)
	if err != nil {
		if err != pgx.ErrNoRows {
			s.logger.Warn("browzer gate: route application lookup failed",
				zap.String("host", host), zap.Error(err))
		}
		return ""
	}
	return appID
}

// isBrowZerClient reports whether clientID is the shared clientless client.
func (s *Service) isBrowZerClient(clientID string) bool {
	return s.config != nil && clientID != "" && clientID == s.config.BrowZerClientID
}
