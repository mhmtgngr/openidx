package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	apperrors "github.com/openidx/openidx/internal/common/errors"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// WHICH ROLES AND ATTRIBUTES AN ORGANIZATION MAY USE ON THE SHARED CONTROLLER.
//
// The controller grants access by role: a service policy joins the services
// its serviceRoles match to the identities its identityRoles match, and a
// "#attr" role matches every object carrying that attribute, whichever
// organization it belongs to. The attribute namespace is one for the whole
// install. So without these rules an organization's admin could write a Dial
// policy naming #all or another organization's service and reach it, or a
// Bind policy for one and host its traffic; could give one of their
// identities an attribute that another organization's policy, or one of the
// install's own (#access-proxy-clients, #browzer-users, #enrolled-users, an
// org-<id> or app-<id> marker), grants; and could give a new service another
// organization's intercept address, capturing its users' traffic.
//
// For anyone but an install administrator, then:
//
//   - a service policy's serviceRoles name only the organization's own
//     services -- @id or @name of one, or #attr carried by its services and
//     no one else's; its identityRoles name only the organization's own
//     identities, or identities the install runs (routers, the access
//     proxy), and never an attribute OpenIDX assigns to users of every
//     organization. #all is refused on both sides. Add Service's dial roles
//     are identity roles under the same rule;
//   - an identity may not be given, or lose, an attribute OpenIDX manages,
//     nor be given one that a policy the organization does not own grants;
//   - a new service's attributes may not be one OpenIDX manages, another
//     organization's or the install's service name, or one a policy the
//     organization does not own names; and its intercept address may not be
//     one another organization's or the install's service intercepts.
//
// Roles are checked against what the controller and the mirror say when they
// are written. What this does not cover -- the attributes user sync derives
// from group names, which are shared between organizations unless
// ZITI_PER_ORG_ATTRIBUTES is on, and the reconciler's route Dial policies,
// which grant attributes every organization's users hold -- is stated in
// docs/THREAT-MODEL.md.

// zitiHostingAttrs are carried only by identities the install runs: the edge
// routers, the access proxy, the PAM broker's dialers. An organization may name
// them in its own service's policies -- that is how its service is hosted --
// but may not give them to an identity.
var zitiHostingAttrs = map[string]bool{
	"access-proxy-clients": true,
	"ziti-routers":         true,
	"pam-broker-dialers":   true,
}

// zitiUserAttrs are assigned by OpenIDX to identities of every organization, or
// mark one: no organization may name them in a policy or set them.
var zitiUserAttrs = map[string]bool{
	"all":            true,
	"browzer-users":  true,
	"enrolled-users": true,
	"device-trusted": true,
	"quarantined":    true,
	"openidx-agent":  true,
}

// zitiManagedAttr reports whether OpenIDX manages an identity attribute: an
// organization's admin may neither add nor remove it. jit-<request-id> is a
// network_service request's own attribute, which the request's Dial policy
// names: added and removed with the request's window, by nobody else.
func zitiManagedAttr(a string) bool {
	return zitiHostingAttrs[a] || zitiUserAttrs[a] || strings.HasPrefix(a, "org-") || strings.HasPrefix(a, "app-") ||
		strings.HasPrefix(a, "jit-")
}

// zitiManagedServiceAttrs are service attributes OpenIDX sets itself:
// browzer-enabled publishes a service to every BrowZer user and has its own
// route, which checks the organization owns the service.
var zitiManagedServiceAttrs = map[string]bool{
	"all":             true,
	"openidx-managed": true,
	"openidx-pam":     true,
	"browzer-enabled": true,
}

// zitiRoleRefusal is a request the rules above refuse, with its answer.
type zitiRoleRefusal struct {
	status int
	msg    string
}

func (e *zitiRoleRefusal) Error() string { return e.msg }

func refuseRole(status int, format string, args ...any) error {
	return &zitiRoleRefusal{status: status, msg: fmt.Sprintf(format, args...)}
}

// writeZitiRoleError answers a request whose roles or attributes were refused,
// or whose check could not run.
func (s *Service) writeZitiRoleError(c *gin.Context, what string, err error) {
	if r, ok := err.(*zitiRoleRefusal); ok {
		c.JSON(r.status, gin.H{"error": r.msg})
		return
	}
	apperrors.HandleErrorWithLogger(c, apperrors.Internal(what, err), s.logger)
}

// zitiFabric is what the checks read: the controller's services, identities
// and service policies, and which organization the mirror gives each of them
// ("" for none: the install's).
type zitiFabric struct {
	orgID       string
	services    []ZitiServiceInfo
	identities  []ZitiIdentityInfo
	policies    []ZitiServicePolicyInfo
	serviceOrg  map[string]string
	identityOrg map[string]string
	policyOrg   map[string]string
}

func (s *Service) loadZitiFabric(ctx context.Context, orgID string, withIdentities bool) (*zitiFabric, error) {
	f := &zitiFabric{orgID: orgID, serviceOrg: map[string]string{}, identityOrg: map[string]string{}, policyOrg: map[string]string{}}
	var err error
	if f.services, err = s.ziti().ListServices(ctx); err != nil {
		return nil, err
	}
	if withIdentities {
		if f.identities, err = s.ziti().ListIdentities(ctx); err != nil {
			return nil, err
		}
	}
	if f.policies, err = s.ziti().ListServicePolicies(ctx); err != nil {
		return nil, err
	}
	all := orgctx.WithBypassRLS(ctx)
	for _, q := range []struct {
		sql string
		dst map[string]string
	}{
		//orgscope:ignore who owns each controller service: what the role check looks for is another organization's
		{`SELECT ziti_id, org_id::text FROM ziti_services WHERE ziti_id IS NOT NULL`, f.serviceOrg},
		//orgscope:ignore who owns each controller identity: what the role check looks for is another organization's
		{`SELECT ziti_id, org_id::text FROM ziti_identities WHERE ziti_id IS NOT NULL`, f.identityOrg},
		//orgscope:ignore who owns each controller policy: what the attribute check looks for is another organization's
		{`SELECT ziti_id, org_id::text FROM ziti_service_policies WHERE ziti_id IS NOT NULL`, f.policyOrg},
	} {
		rows, err := s.db.Pool.Query(all, q.sql)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, org string
			if err := rows.Scan(&id, &org); err != nil {
				rows.Close()
				return nil, err
			}
			q.dst[id] = org
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// splitZitiRole parses a role: "#attr" or "@id-or-name".
func splitZitiRole(role string) (kind byte, value string, err error) {
	role = strings.TrimSpace(role)
	if len(role) < 2 || (role[0] != '#' && role[0] != '@') {
		return 0, "", refuseRole(http.StatusBadRequest, "role %q must be #attribute or @id", role)
	}
	return role[0], role[1:], nil
}

func holdsAttr(attrs []string, a string) bool {
	for _, x := range attrs {
		if x == a {
			return true
		}
	}
	return false
}

// checkServiceRoles refuses a serviceRoles list that names anything but the
// organization's own services.
func (f *zitiFabric) checkServiceRoles(roles []string) error {
	for _, role := range roles {
		kind, v, err := splitZitiRole(role)
		if err != nil {
			return err
		}
		if kind == '@' {
			found := false
			for _, svc := range f.services {
				if svc.ID == v || svc.Name == v {
					found = true
					if f.serviceOrg[svc.ID] != f.orgID {
						return refuseRole(http.StatusForbidden, "service role %q names a service that is not the organization's", role)
					}
				}
			}
			if !found {
				return refuseRole(http.StatusForbidden, "service role %q names no service of the organization's", role)
			}
			continue
		}
		if zitiManagedServiceAttrs[v] {
			return refuseRole(http.StatusForbidden, "service role %q is managed by OpenIDX", role)
		}
		carried := false
		for _, svc := range f.services {
			if holdsAttr(svc.Attributes, v) {
				carried = true
				if f.serviceOrg[svc.ID] != f.orgID {
					return refuseRole(http.StatusForbidden, "service role %q matches a service that is not the organization's", role)
				}
			}
		}
		if !carried {
			return refuseRole(http.StatusForbidden, "service role %q matches no service of the organization's", role)
		}
	}
	return nil
}

// checkIdentityRoles refuses an identityRoles list that names another
// organization's identities or an attribute OpenIDX gives users of every
// organization. The install's own identities may be named: a Bind policy for
// the organization's own service names its routers.
func (f *zitiFabric) checkIdentityRoles(roles []string) error {
	for _, role := range roles {
		kind, v, err := splitZitiRole(role)
		if err != nil {
			return err
		}
		if kind == '@' {
			found := false
			for _, id := range f.identities {
				if id.ID == v || id.Name == v {
					found = true
					if owner := f.identityOrg[id.ID]; owner != "" && owner != f.orgID {
						return refuseRole(http.StatusForbidden, "identity role %q names another organization's identity", role)
					}
				}
			}
			if !found {
				return refuseRole(http.StatusForbidden, "identity role %q names no identity", role)
			}
			continue
		}
		if zitiUserAttrs[v] || strings.HasPrefix(v, "app-") || strings.HasPrefix(v, "jit-") ||
			(strings.HasPrefix(v, "org-") && v != orgMarkerAttr(f.orgID) && !strings.HasPrefix(v, orgMarkerAttr(f.orgID)+"-")) {
			return refuseRole(http.StatusForbidden, "identity role %q matches identities of other organizations", role)
		}
		for _, id := range f.identities {
			if holdsAttr(id.Attributes, v) {
				if owner := f.identityOrg[id.ID]; owner != "" && owner != f.orgID {
					return refuseRole(http.StatusForbidden, "identity role %q matches another organization's identity", role)
				}
			}
		}
	}
	return nil
}

// grantedElsewhere reports whether a policy the organization does not own names
// "#attr" among the roles pick returns.
func (f *zitiFabric) grantedElsewhere(attr string, pick func(ZitiServicePolicyInfo) []string) bool {
	for _, p := range f.policies {
		if f.policyOrg[p.ID] == f.orgID {
			continue
		}
		if holdsAttr(pick(p), "#"+attr) {
			return true
		}
	}
	return false
}

// checkIdentityAttributes refuses a change from current to next that adds or
// removes an attribute OpenIDX manages, or adds one a policy the organization
// does not own grants.
func (f *zitiFabric) checkIdentityAttributes(current, next []string) error {
	for _, a := range next {
		if holdsAttr(current, a) {
			continue
		}
		if zitiManagedAttr(a) {
			return refuseRole(http.StatusForbidden, "attribute %q is managed by OpenIDX", a)
		}
		if f.grantedElsewhere(a, func(p ZitiServicePolicyInfo) []string { return p.IdentityRoles }) {
			return refuseRole(http.StatusForbidden, "attribute %q is granted by a policy that is not the organization's", a)
		}
	}
	for _, a := range current {
		if zitiManagedAttr(a) && !holdsAttr(next, a) {
			return refuseRole(http.StatusForbidden, "attribute %q is managed by OpenIDX", a)
		}
	}
	return nil
}

// checkServiceAttributes refuses attributes for a new service that OpenIDX
// manages, that name another organization's or the install's service, or that
// a policy the organization does not own names.
func (s *Service) checkServiceAttributes(ctx context.Context, f *zitiFabric, attrs []string) error {
	for _, a := range attrs {
		a = strings.TrimSpace(a)
		if zitiManagedServiceAttrs[a] {
			return refuseRole(http.StatusForbidden, "attribute %q is managed by OpenIDX", a)
		}
		claimed, err := zitiServiceNameClaimed(ctx, s.db, f.orgID, a)
		if err != nil {
			return err
		}
		if claimed || f.grantedElsewhere(a, func(p ZitiServicePolicyInfo) []string { return p.ServiceRoles }) {
			return refuseRole(http.StatusForbidden, "attribute %q is another organization's or the install's", a)
		}
	}
	return nil
}

// checkInterceptAddress refuses an intercept address that a service the
// organization does not own already intercepts: clients that may dial both
// would have their traffic for it captured by whichever the tunneler picks.
func (s *Service) checkInterceptAddress(ctx context.Context, f *zitiFabric, address string) error {
	data, status, err := s.ziti().MgmtRequest("GET", "/edge/management/v1/configs?limit=500", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("controller answered %d listing configs", status)
	}
	var resp struct {
		Data []struct {
			ID   string `json:"id"`
			Data struct {
				Addresses []string `json:"addresses"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}
	intercepting := map[string]bool{}
	for _, cfg := range resp.Data {
		for _, a := range cfg.Data.Addresses {
			if strings.EqualFold(strings.TrimSpace(a), address) {
				intercepting[cfg.ID] = true
			}
		}
	}
	for _, svc := range f.services {
		for _, cfg := range svc.Configs {
			if intercepting[cfg] && f.serviceOrg[svc.ID] != f.orgID {
				return refuseRole(http.StatusConflict, "intercept address %q is another organization's or the install's", address)
			}
		}
	}
	return nil
}

// zitiPolicyRolesAllowed decides whether the caller may write a service policy
// with these roles, and writes the refusal otherwise. An install administrator
// may write any.
func (s *Service) zitiPolicyRolesAllowed(c *gin.Context, serviceRoles, identityRoles []string) bool {
	view, ok := s.zitiViewFor(c)
	if !ok {
		return false
	}
	if view.install {
		return true
	}
	f, err := s.loadZitiFabric(c.Request.Context(), view.orgID, true)
	if err == nil {
		if err = f.checkServiceRoles(serviceRoles); err == nil {
			err = f.checkIdentityRoles(identityRoles)
		}
	}
	if err != nil {
		s.writeZitiRoleError(c, "check the policy's roles", err)
		return false
	}
	return true
}

// zitiIdentityAttributesAllowed decides whether the caller may set these
// attributes on the identity with controller id zitiID ("" for a new one), and
// writes the refusal otherwise. An install administrator may set any.
func (s *Service) zitiIdentityAttributesAllowed(c *gin.Context, zitiID string, next []string) bool {
	view, ok := s.zitiViewFor(c)
	if !ok {
		return false
	}
	if view.install {
		return true
	}
	ctx := c.Request.Context()
	var current []string
	var err error
	if zitiID != "" {
		current, err = s.ziti().GetIdentityRoleAttributes(ctx, zitiID)
	}
	var f *zitiFabric
	if err == nil {
		f, err = s.loadZitiFabric(ctx, view.orgID, false)
	}
	if err == nil {
		err = f.checkIdentityAttributes(current, next)
	}
	if err != nil {
		s.writeZitiRoleError(c, "check the identity's attributes", err)
		return false
	}
	return true
}

// checkNewServiceRoles checks what Add Service will create for an organization:
// the Dial policy's identity roles, the service's attributes and its intercept
// address.
func (s *Service) checkNewServiceRoles(ctx context.Context, orgID string, dialRoles, attrs []string, intercept string) error {
	f, err := s.loadZitiFabric(ctx, orgID, true)
	if err != nil {
		return err
	}
	if err := f.checkIdentityRoles(dialRoles); err != nil {
		return err
	}
	if err := s.checkServiceAttributes(ctx, f, attrs); err != nil {
		return err
	}
	return s.checkInterceptAddress(ctx, f, strings.TrimSpace(intercept))
}
