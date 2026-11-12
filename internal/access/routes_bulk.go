package access

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// bulkRoute is one resource to expose via the proxy / overlay.
type bulkRoute struct {
	Name    string `json:"name"`
	FromURL string `json:"from_url"`
	ToURL   string `json:"to_url"`
	Ziti    bool   `json:"ziti"`
}

// subnetSpec expands a CIDR + port into one route per host — the "onboard a
// whole site/subnet" shortcut.
type subnetSpec struct {
	CIDR       string `json:"cidr"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"` // tcp (default) | http | https
	NamePrefix string `json:"name_prefix"`
	Ziti       bool   `json:"ziti"`
}

// expandSubnet turns a CIDR + port into per-host bulkRoutes. Capped at a /24
// (256 hosts) to prevent runaway provisioning; the network + broadcast
// addresses of prefixes /30 or shorter are skipped.
func expandSubnet(spec subnetSpec) ([]bulkRoute, error) {
	proto := strings.ToLower(strings.TrimSpace(spec.Protocol))
	if proto == "" {
		proto = "tcp"
	}
	if spec.Port <= 0 || spec.Port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}
	prefix := strings.TrimSpace(spec.NamePrefix)
	if prefix == "" {
		prefix = "subnet"
	}
	ip, ipnet, err := net.ParseCIDR(spec.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr: %w", err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 subnets are supported")
	}
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 8 {
		return nil, fmt.Errorf("subnet too large (max /24 = 256 hosts)")
	}

	var hosts []net.IP
	for cur := ipnet.IP.Mask(ipnet.Mask).To4(); cur != nil && ipnet.Contains(cur); cur = nextIP(cur) {
		hosts = append(hosts, cloneIP(cur))
	}
	skipEnds := (bits - ones) >= 2 // /30 or shorter has a network + broadcast address

	var routes []bulkRoute
	for i, h := range hosts {
		if skipEnds && (i == 0 || i == len(hosts)-1) {
			continue
		}
		routes = append(routes, bulkRoute{
			Name:  fmt.Sprintf("%s-%s", prefix, h.String()),
			ToURL: fmt.Sprintf("%s://%s:%d", proto, h.String(), spec.Port),
			Ziti:  spec.Ziti,
		})
	}
	return routes, nil
}

func cloneIP(ip net.IP) net.IP { c := make(net.IP, len(ip)); copy(c, ip); return c }

func nextIP(ip net.IP) net.IP {
	c := cloneIP(ip)
	for i := len(c) - 1; i >= 0; i-- {
		c[i]++
		if c[i] != 0 {
			return c
		}
	}
	return nil // overflowed the whole address space
}

// sanitizeZitiName reduces a display name to the Ziti-safe charset.
func sanitizeZitiName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

func routeTypeForURL(toURL string) string {
	l := strings.ToLower(toURL)
	if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
		return "http"
	}
	return "tcp"
}

// handleBulkRoutes creates many proxy_routes at once (an explicit list and/or a
// CIDR expansion), then asks the reconciler to converge — the "expand the
// network easily" endpoint. The reconciler creates all Ziti services/policies
// for the ziti-enabled rows on its next pass (routers already carry every
// service via the #all bootstrap, so no per-route policy edits are needed).
func (s *Service) handleBulkRoutes(c *gin.Context) {
	var req struct {
		Routes []bulkRoute `json:"routes"`
		Subnet *subnetSpec `json:"subnet"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	list := req.Routes
	if req.Subnet != nil {
		expanded, err := expandSubnet(*req.Subnet)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		list = append(list, expanded...)
	}
	if len(list) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no routes to create"})
		return
	}
	if len(list) > 512 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many routes in one request (max 512)"})
		return
	}
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// A host is served by one enabled route in the whole installation, and
	// every route here is created enabled: a list naming a host another route
	// already serves, or naming one host twice, is refused as a whole before
	// anything is created.
	conflicts, err := s.bulkRouteHostConflicts(c.Request.Context(), org.ID, list)
	if err != nil {
		s.logger.Error("bulk routes: could not check the hosts", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create routes"})
		return
	}
	if len(conflicts) > 0 {
		c.JSON(http.StatusConflict, gin.H{
			"error":     "some hosts are already served by an enabled route, or listed twice; nothing was created",
			"conflicts": conflicts,
		})
		return
	}

	created := 0
	var nameConflicts []string
	for _, r := range list {
		name := strings.TrimSpace(r.Name)
		toURL := strings.TrimSpace(r.ToURL)
		if name == "" || toURL == "" {
			continue
		}
		svcName := ""
		if r.Ziti {
			svcName = "openidx-" + sanitizeZitiName(name)
			// The reconciler adopts and converges whatever service this name
			// already names, so it must not be another organization's or the
			// install's (ziti_scope.go).
			claimed, err := zitiServiceNameClaimed(c.Request.Context(), s.db, org.ID, svcName)
			if err != nil {
				s.logger.Warn("bulk route: could not check the ziti service name", zap.String("name", name), zap.Error(err))
				continue
			}
			if claimed {
				nameConflicts = append(nameConflicts, name)
				continue
			}
		}
		if _, err := s.db.Pool.Exec(c.Request.Context(),
			`INSERT INTO proxy_routes (id, name, from_url, to_url, require_auth, enabled, priority,
			   route_type, ziti_enabled, ziti_service_name, hosting_mode, org_id)
			 VALUES ($1, $2, $3, $4, true, true, 10, $5, $6, $7, 'identity', $8)`,
			uuid.New().String(), name, strings.TrimSpace(r.FromURL), toURL,
			routeTypeForURL(toURL), r.Ziti, svcName, org.ID); err != nil {
			s.logger.Warn("bulk route insert failed", zap.String("name", name), zap.Error(err))
			continue
		}
		created++
	}
	if created > 0 {
		s.enqueueReconcile()
	}
	resp := gin.H{"created": created, "requested": len(list)}
	if len(nameConflicts) > 0 {
		// The routes left out because their Ziti service name is taken.
		resp["name_conflicts"] = nameConflicts
	}
	c.JSON(http.StatusOK, resp)
}

// routerImageTagPattern is a docker tag: what may follow "openziti/ziti-router:".
var routerImageTagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// routerNamePattern keeps a router name safe to put in a shell command.
var routerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// defaultRouterImageTag is used when ZITI_ROUTER_IMAGE_TAG is unset: the
// version the bundled controller runs (deployments/docker, ZITI_VERSION).
const defaultRouterImageTag = "1.6.12"

// routerOnboardRequest is the body of POST /ziti/fabric/routers/enroll-token.
type routerOnboardRequest struct {
	Name              string `json:"name"`
	SiteSlug          string `json:"site_slug"`
	AdvertisedAddress string `json:"advertised_address"`
	ImageTag          string `json:"image_tag"`
}

// splitCtrlAddress splits ZITI_CTRL_PUBLIC_ADDRESS (host or host:port) into
// what the router image takes as ZITI_CTRL_ADVERTISED_ADDRESS and _PORT.
func splitCtrlAddress(addr string) (string, string) {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(strings.TrimPrefix(addr, "https://"), "tls:")
	addr = strings.TrimSuffix(addr, "/")
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return addr, "1280"
}

// routerOnboardCommand is the docker one-liner a router host runs. The env
// names are the ones the openziti/ziti-router image's /bootstrap.bash reads:
// ZITI_ENROLL_TOKEN holds the JWT itself (not a path) and is enrolled on the
// first start; ZITI_ROUTER_MODE=host makes it a hosting (Bind) router without
// tproxy. The volume keeps the enrolled identity across restarts.
func routerOnboardCommand(name, jwt, ctrlHost, ctrlPort, advertised, tag string) string {
	return fmt.Sprintf("docker run -d --name %s --restart=unless-stopped "+
		"-p 3022:3022 -v %s-data:/ziti-router "+
		"-e ZITI_ENROLL_TOKEN='%s' "+
		"-e ZITI_CTRL_ADVERTISED_ADDRESS=%s -e ZITI_CTRL_ADVERTISED_PORT=%s "+
		"-e ZITI_ROUTER_ADVERTISED_ADDRESS=%s -e ZITI_ROUTER_PORT=3022 "+
		"-e ZITI_ROUTER_MODE=host "+
		"openziti/ziti-router:%s",
		name, name, jwt, ctrlHost, ctrlPort, advertised, tag)
}

// handleRouterEnrollToken onboards an edge router into a site: it creates the
// router on the controller tagged site-<slug> and ziti-routers, records it in
// site_routers (the table the reconciler reads to decide which routers host
// which site), and returns a copy-paste docker command that enrolls and runs
// it. The router joins the mesh via the #all bootstrap with zero policy
// changes; services of its site Bind to it on the next reconcile.
func (s *Service) handleRouterEnrollToken(c *gin.Context) {
	zm := s.ziti()
	if zm == nil || !zm.IsInitialized() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ziti controller not connected"})
		return
	}
	var req routerOnboardRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "router-" + uuid.New().String()[:8]
	}
	if !routerNamePattern.MatchString(name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name must be 1-64 letters, digits, dots, hyphens or underscores"})
		return
	}
	advertised := strings.TrimSpace(req.AdvertisedAddress)
	if advertised == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "advertised_address is required: the host name or IP other routers and clients reach this router at"})
		return
	}
	if net.ParseIP(advertised) == nil && !validHostName(advertised) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "advertised_address must be a host name or an IP address (no port)"})
		return
	}
	tag := strings.TrimSpace(req.ImageTag)
	if tag == "" && s.config != nil {
		tag = strings.TrimSpace(s.config.ZitiRouterImageTag)
	}
	if tag == "" {
		tag = defaultRouterImageTag
	}
	if !routerImageTagPattern.MatchString(tag) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "image_tag is not a valid image tag"})
		return
	}
	slug := strings.TrimSpace(req.SiteSlug)
	if slug == "" {
		slug = DefaultSiteSlug
	}
	ctx := c.Request.Context()
	var siteID string
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore install-wide platform table; sites has no org
		`SELECT id::text FROM sites WHERE slug = $1`, slug).Scan(&siteID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unknown site %q; create it first", slug)})
		return
	}
	if err != nil {
		s.logger.Error("router enroll-token: site lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read sites"})
		return
	}

	id, jwt, err := zm.CreateEdgeRouter(ctx, name, []string{"site-" + slug, "ziti-routers"})
	if err != nil {
		s.logger.Error("router enroll-token: create failed", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to create edge router"})
		return
	}
	if jwt == "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": "router created but no enrollment token returned"})
		return
	}
	if _, err := s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore install-wide platform table; site_routers has no org
		`INSERT INTO site_routers (ziti_router_id, site_id, name, advertised_host, image_tag)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (ziti_router_id) DO UPDATE SET site_id = EXCLUDED.site_id, name = EXCLUDED.name,
		   advertised_host = EXCLUDED.advertised_host, image_tag = EXCLUDED.image_tag`,
		id, siteID, name, advertised, tag); err != nil {
		// Without the row the reconciler would retag the router into the
		// default site. Remove it rather than leave a router in the wrong site.
		s.logger.Error("router enroll-token: site_routers insert failed; deleting the router", zap.String("router_id", id), zap.Error(err))
		if _, _, derr := zm.mgmtRequest("DELETE", "/edge/management/v1/edge-routers/"+id, nil); derr != nil {
			s.logger.Error("router enroll-token: cleanup delete failed", zap.String("router_id", id), zap.Error(derr))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record the router's site"})
		return
	}

	ctrl := ""
	if zm.cfg != nil {
		ctrl = zm.cfg.ZitiCtrlPublicAddress
	}
	if ctrl == "" && s.config != nil {
		ctrl = s.config.ZitiCtrlPublicAddress
	}
	ctrlHost, ctrlPort := splitCtrlAddress(ctrl)
	resp := gin.H{
		"router_id":       id,
		"name":            name,
		"site_slug":       slug,
		"image_tag":       tag,
		"enrollment_jwt":  jwt,
		"controller":      ctrl,
		"onboard_command": routerOnboardCommand(name, jwt, ctrlHost, ctrlPort, advertised, tag),
	}
	if ctrlHost == "" {
		resp["warning"] = "ZITI_CTRL_PUBLIC_ADDRESS is not set; fill in ZITI_CTRL_ADVERTISED_ADDRESS with the controller address this router reaches"
	}
	s.logAuditEvent(c, "ziti_router.onboard", id, "edge_router", map[string]interface{}{"name": name, "site": slug, "advertised_address": advertised})
	s.enqueueReconcile()
	c.JSON(http.StatusOK, resp)
}

// bulkHostConflict is one host a bulk request cannot have.
type bulkHostConflict struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
	// Route is the caller's own organization's route that serves the host;
	// another organization's route is not named.
	Route string `json:"route,omitempty"`
}

// bulkRouteHostConflicts returns the hosts, among the routes handleBulkRoutes
// would create, that an enabled route already serves or that the list names
// more than once.
func (s *Service) bulkRouteHostConflicts(ctx context.Context, orgID string, list []bulkRoute) ([]bulkHostConflict, error) {
	var fromURLs []string
	for _, r := range list {
		if strings.TrimSpace(r.Name) == "" || strings.TrimSpace(r.ToURL) == "" {
			continue
		}
		fromURLs = append(fromURLs, strings.TrimSpace(r.FromURL))
	}
	if len(fromURLs) == 0 {
		return nil, nil
	}
	rows, err := s.db.Pool.Query(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore a host is held across organizations (migration v211); the holder's organization decides what the 409 may say about it
		`SELECT COALESCE(proxy_route_host(i.u), ''), COALESCE(r.org_id::text, ''), COALESCE(r.name, '')
		   FROM unnest($1::text[]) WITH ORDINALITY AS i(u, n)
		   LEFT JOIN proxy_routes r ON r.enabled = true AND r.host = proxy_route_host(i.u)
		  ORDER BY i.n`, fromURLs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []bulkHostConflict
	seen := map[string]bool{}
	for rows.Next() {
		var host, holderOrg, holderName string
		if err := rows.Scan(&host, &holderOrg, &holderName); err != nil {
			return nil, err
		}
		switch {
		case host == "":
			continue
		case holderOrg == orgID:
			out = append(out, bulkHostConflict{Host: host, Reason: "served by a route in this organization", Route: holderName})
		case holderOrg != "":
			out = append(out, bulkHostConflict{Host: host, Reason: "routed by another organization"})
		case seen[host]:
			out = append(out, bulkHostConflict{Host: host, Reason: "listed more than once"})
		}
		seen[host] = true
	}
	return out, rows.Err()
}
