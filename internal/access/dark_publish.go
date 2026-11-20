package access

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// DARK PUBLISH: an administrator publishes an internal web application in one
// step and the result is reachable only through the agent's tunnel.
//
// Until now that took three calls to three services: the network resource
// (access), who may use it (portal) and whether the device must be trusted
// (admin conditions). The result of getting any one wrong was an application
// nobody could open, or one everybody could. This file turns what a person
// types (an address, who may use it) into the three rows, written together or
// not at all.

// errPublishAddress is what parsePublishAddress and publishDarkApp answer for an
// address that cannot be published: the cause is wrapped, the sentinel is what
// the handler maps to a 400.
var errPublishAddress = errors.New("invalid address")

func publishAddressErr(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", errPublishAddress, fmt.Sprintf(format, args...))
}

// parsePublishAddress reads the address an administrator types ("the address
// people type today") as a network target and the URL a person opens it with.
//
// A value without a scheme is read as https. Only http and https are accepted;
// the default port follows the scheme. A name goes to DNSNames and an IP
// literal to Hosts, tcp only, one port: a published web application is one name
// and one port, which is also what lets the server pin it (network_pins.go).
// The launch URL keeps the path and query, drops the fragment and omits a
// default port. The target is NOT yet normalized or guarded: the caller passes
// it through normalizeNetworkTarget, which refuses the platform's own
// addresses.
func parsePublishAddress(raw string) (NetworkTarget, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return NetworkTarget{}, "", publishAddressErr("the address is empty")
	}
	s := raw
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return NetworkTarget{}, "", publishAddressErr("%q is not an address", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return NetworkTarget{}, "", publishAddressErr("only http and https addresses can be published, not %q", u.Scheme)
	}
	if u.User != nil {
		return NetworkTarget{}, "", publishAddressErr("an address cannot carry a user name or password")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return NetworkTarget{}, "", publishAddressErr("the address has no host")
	}
	if strings.Contains(host, "*") {
		return NetworkTarget{}, "", publishAddressErr("a wildcard cannot be published here; publish one application at a time")
	}

	defaultPort := 443
	if scheme == "http" {
		defaultPort = 80
	}
	port := defaultPort
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return NetworkTarget{}, "", publishAddressErr("the port %q is not between 1 and 65535", p)
		}
		port = n
	}

	target := NetworkTarget{
		PortRanges: []PortRange{{Low: port, High: port}},
		Protocols:  []string{"tcp"},
	}
	hostForURL := host
	if ip := net.ParseIP(host); ip != nil {
		target.Hosts = []string{ip.String()}
		hostForURL = ip.String()
		if ip.To4() == nil {
			hostForURL = "[" + hostForURL + "]"
		}
	} else if validHostName(host) {
		target.DNSNames = []string{host}
	} else {
		return NetworkTarget{}, "", publishAddressErr("%q is neither a host name nor an IP address", host)
	}

	launch := scheme + "://" + hostForURL
	if port != defaultPort {
		launch += ":" + strconv.Itoa(port)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	launch += path
	if u.RawQuery != "" {
		launch += "?" + u.RawQuery
	}
	return target, launch, nil
}

// The reasons a publish is refused. Each maps to one status and one code in the
// handler; none of them leaves a row behind.
var (
	errPublishName             = errors.New("the name must be 1 to 255 characters")
	errPublishNoAssignee       = errors.New("at least one group or user must be given: an assignment is the grant")
	errPublishUnknownPrincipal = errors.New("unknown group or user")
	errPublishUnknownGroup     = fmt.Errorf("%w: group", errPublishUnknownPrincipal)
	errPublishUnknownUser      = fmt.Errorf("%w: user", errPublishUnknownPrincipal)
	errPublishDuplicate        = errors.New("an application with this name and port is already published")
	errPublishTarget           = errors.New("the address cannot be published")
)

// publishRequest is what the "Publish an app" dialog sends. A pointer for
// RequireTrustedDevice: absent means required, which is the safe default.
type publishRequest struct {
	Name                 string   `json:"name"`
	Description          string   `json:"description"`
	Address              string   `json:"address"`
	Site                 string   `json:"site"`
	GroupIDs             []string `json:"group_ids"`
	UserIDs              []string `json:"user_ids"`
	RequireTrustedDevice *bool    `json:"require_trusted_device"`
}

// publishEnforcement says what this installation actually enforces, so the
// console never claims "only these people" where a gate is off (display equals
// enforcement).
type publishEnforcement struct {
	Assignment  bool   `json:"assignment"`
	DeviceTrust string `json:"device_trust"`
}

type publishResult struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	ServiceName          string             `json:"service_name"`
	URL                  string             `json:"url"`
	Target               NetworkTarget      `json:"target"`
	Groups               int                `json:"groups"`
	Users                int                `json:"users"`
	RequireTrustedDevice bool               `json:"require_trusted_device"`
	Enforcement          publishEnforcement `json:"enforcement"`
}

// uniqueUUIDs trims, drops empties and repeats and checks that every value is a
// UUID; bad is true when one is not.
func uniqueUUIDs(in []string) (out []string, bad bool) {
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, true
		}
		k := id.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out, false
}

// publishDarkApp writes a dark application: the network resource, its
// assignments and its device-trust condition, in one transaction. Nothing is
// opened to the internet: no proxy route, no BrowZer flag, no public host.
func (s *Service) publishDarkApp(ctx context.Context, orgID, actorID string, req publishRequest) (*publishResult, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 255 {
		return nil, errPublishName
	}
	target, launchURL, err := parsePublishAddress(req.Address)
	if err != nil {
		return nil, err
	}
	target.Site = strings.TrimSpace(req.Site)
	norm, verr := normalizeNetworkTarget(target)
	if verr != nil {
		return nil, fmt.Errorf("%w: %v", errPublishTarget, verr)
	}
	groups, bad := uniqueUUIDs(req.GroupIDs)
	if bad {
		return nil, errPublishUnknownGroup
	}
	users, bad := uniqueUUIDs(req.UserIDs)
	if bad {
		return nil, errPublishUnknownUser
	}
	if len(groups)+len(users) == 0 {
		return nil, errPublishNoAssignee
	}
	trusted := req.RequireTrustedDevice == nil || *req.RequireTrustedDevice

	var actor interface{}
	if id, perr := uuid.Parse(actorID); perr == nil {
		actor = id.String()
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Every group and user must belong to THIS organization: the assignment
	// tables carry no foreign key to them, so this check is the only thing that
	// keeps another tenant's id out.
	if len(groups) > 0 {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id = $1 AND id = ANY($2::uuid[])`, orgID, groups).Scan(&n); err != nil {
			return nil, err
		}
		if n != len(groups) {
			return nil, errPublishUnknownGroup
		}
	}
	if len(users) > 0 {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE org_id = $1 AND id = ANY($2::uuid[])`, orgID, users).Scan(&n); err != nil {
			return nil, err
		}
		if n != len(users) {
			return nil, errPublishUnknownUser
		}
	}

	// One name and port is one service: two services intercepting the same
	// address would split a device's traffic between them.
	port := norm.PortRanges[0].Low
	var dup bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM network_targets nt JOIN applications a ON a.id = nt.application_id
		   WHERE nt.org_id = $1 AND a.kind = 'network' AND COALESCE(a.enabled, true)
		     AND ($2::text[] && nt.dns_names OR $3::text[] && nt.hosts)
		     AND EXISTS (SELECT 1 FROM jsonb_array_elements(nt.port_ranges) pr
		                  WHERE (pr->>'low')::int <= $4 AND (pr->>'high')::int >= $4))`,
		orgID, norm.DNSNames, norm.Hosts, port).Scan(&dup); err != nil {
		return nil, err
	}
	if dup {
		return nil, errPublishDuplicate
	}

	id, err := s.createNetworkResourceTx(ctx, tx, orgID, name, strings.TrimSpace(req.Description), &norm)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE applications SET base_url = $2, require_assignment = true WHERE id = $1::uuid AND org_id = $3::uuid`,
		id, launchURL, orgID); err != nil {
		return nil, err
	}
	if len(groups) > 0 {
		if _, err := tx.Exec(ctx,
			`INSERT INTO group_application_assignments (group_id, application_id, org_id, assigned_by)
			 SELECT g, $2::uuid, $3::uuid, $4::uuid FROM unnest($1::uuid[]) g
			 ON CONFLICT (group_id, application_id) DO NOTHING`, groups, id, orgID, actor); err != nil {
			return nil, err
		}
	}
	if len(users) > 0 {
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_application_assignments (user_id, application_id, org_id)
			 SELECT u, $2::uuid, $3::uuid FROM unnest($1::uuid[]) u
			 ON CONFLICT (user_id, application_id) DO NOTHING`, users, id, orgID); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO resource_conditions (application_id, org_id, require_device_trust, updated_by)
		 VALUES ($1::uuid, $2::uuid, $3, $4::uuid)
		 ON CONFLICT (application_id) DO UPDATE SET
		   require_device_trust = EXCLUDED.require_device_trust, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		id, orgID, trusted, actor); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	res := &publishResult{
		ID: id, Name: name, ServiceName: networkServiceName(id), URL: launchURL, Target: norm,
		Groups: len(groups), Users: len(users), RequireTrustedDevice: trusted,
		Enforcement: publishEnforcement{DeviceTrust: "off"},
	}
	if s.config != nil {
		res.Enforcement.Assignment = s.config.AccessAssignmentEnforce
		if g := strings.ToLower(strings.TrimSpace(s.config.PostureDeviceTrustGate)); g != "" {
			res.Enforcement.DeviceTrust = g
		}
	}
	return res, nil
}

// handlePublishDarkApp is POST /network-resources/publish (admin only).
func (s *Service) handlePublishDarkApp(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var req publishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "invalid_request"})
		return
	}
	if !s.networkGuardReady(c) {
		return
	}
	res, err := s.publishDarkApp(ctx, org.ID, c.GetString("user_id"), req)
	switch {
	case err == nil:
	case errors.Is(err, errPublishName):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "invalid_name"})
		return
	case errors.Is(err, errPublishAddress):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "invalid_address"})
		return
	case errors.Is(err, errPublishTarget):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "target_refused"})
		return
	case errors.Is(err, errPublishNoAssignee):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "assignee_required"})
		return
	case errors.Is(err, errPublishUnknownGroup):
		c.JSON(http.StatusBadRequest, gin.H{"error": "one of the groups does not exist in this organization", "code": "unknown_group"})
		return
	case errors.Is(err, errPublishUnknownUser):
		c.JSON(http.StatusBadRequest, gin.H{"error": "one of the users does not exist in this organization", "code": "unknown_user"})
		return
	case errors.Is(err, errUnknownSite):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "unknown_site"})
		return
	case errors.Is(err, errPublishDuplicate):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "code": "already_published"})
		return
	default:
		s.logger.Error("publish dark app", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to publish the application"})
		return
	}
	s.logAuditEvent(c, "network_resource.publish", res.ID, "application", map[string]interface{}{
		"name": res.Name, "url": res.URL, "groups": res.Groups, "users": res.Users,
		"require_trusted_device": res.RequireTrustedDevice,
		"enforce_assignment":     res.Enforcement.Assignment, "device_trust_gate": res.Enforcement.DeviceTrust,
	})
	s.enqueueReconcile()
	c.JSON(http.StatusCreated, res)
}
