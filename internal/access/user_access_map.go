// Package access — cross-pillar user access map (IAM ⇄ PAM ⇄ Ziti).
//
// OpenIDX's three pillars (IAM identity, PAM privileged access, Ziti zero-trust
// network) all live in one Postgres, so "everything this user can reach" is a
// set of JOINs rather than a multi-vendor integration. This file serves the
// admin-side correlation view: one endpoint that, for a single user, returns
// their IAM grants (roles/groups/sessions), their PAM surface (vault grants,
// active checkouts, JIT elevations, privileged sessions — including whether a
// session rides a Ziti-overlaid route), their Ziti surface (identity,
// enrolled devices, dial policies and the services those resolve to), and the
// recent unified audit trail across all three sources.
//
// Registered admin-only in RegisterRoutes (see service.go); every query
// carries an explicit org predicate on top of the FORCE-RLS belt.
package access

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// AccessMapUser is the identity header of the access map.
type AccessMapUser struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// AccessMapIAM is the IAM pillar: what the user is and holds.
type AccessMapIAM struct {
	Roles           []NamedRef `json:"roles"`
	Groups          []NamedRef `json:"groups"`
	ActiveSessions  int64      `json:"active_sessions"`
	ActiveAPIKeys   int64      `json:"active_api_keys"`
	PendingRequests int64      `json:"pending_access_requests"`
}

// NamedRef is a compact id+name reference.
type NamedRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AccessMapVaultGrant is one vault secret the user can act on, and via which
// principal path (direct user grant or one of their roles).
type AccessMapVaultGrant struct {
	SecretID   string     `json:"secret_id"`
	SecretName string     `json:"secret_name"`
	SecretType string     `json:"secret_type"`
	Actions    []string   `json:"actions"`
	Via        string     `json:"via"` // "user" or "role:<name>"
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// AccessMapCheckout is an active credential lease.
type AccessMapCheckout struct {
	ID         string     `json:"id"`
	SecretName string     `json:"secret_name"`
	Mode       string     `json:"mode"`
	LeasedAt   time.Time  `json:"leased_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// AccessMapJITGrant is an active just-in-time role elevation.
type AccessMapJITGrant struct {
	ID        string    `json:"id"`
	RoleName  string    `json:"role_name"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AccessMapPrivSession is a privileged (Guacamole-brokered) session. OverZiti
// is the PAM⇄Ziti correlation: true when the session's route is Ziti-overlaid.
type AccessMapPrivSession struct {
	ID        string    `json:"id"`
	RouteName string    `json:"route_name"`
	Protocol  string    `json:"protocol"`
	StartedAt time.Time `json:"started_at"`
	OverZiti  bool      `json:"over_ziti"`
}

// AccessMapPAM is the PAM pillar: what privileged material the user can reach.
type AccessMapPAM struct {
	VaultGrants            []AccessMapVaultGrant  `json:"vault_grants"`
	ActiveCheckouts        []AccessMapCheckout    `json:"active_checkouts"`
	ActiveJITGrants        []AccessMapJITGrant    `json:"active_jit_grants"`
	ActiveSessions         []AccessMapPrivSession `json:"active_sessions"`
	Sessions30d            int64                  `json:"sessions_30d"`
	PendingSessionRequests int64                  `json:"pending_session_requests"`
	PendingCredRequests    int64                  `json:"pending_credential_requests"`
}

// AccessMapZitiIdentity mirrors the user's Ziti identity row.
type AccessMapZitiIdentity struct {
	ZitiID     string   `json:"ziti_id"`
	Name       string   `json:"name"`
	Enrolled   bool     `json:"enrolled"`
	Attributes []string `json:"attributes"`
}

// AccessMapDevice is an endpoint agent enrolled by this user.
type AccessMapDevice struct {
	AgentID          string     `json:"agent_id"`
	Platform         string     `json:"platform"`
	Status           string     `json:"status"`
	ComplianceStatus string     `json:"compliance_status"`
	ZitiIdentityID   string     `json:"ziti_identity_id,omitempty"`
	LastSeenAt       *time.Time `json:"last_seen_at,omitempty"`
}

// AccessMapDialPolicy is a Ziti Dial service-policy that applies to the user's
// identity, with the services it resolves to (where the local mirror can).
type AccessMapDialPolicy struct {
	Name     string   `json:"name"`
	Services []string `json:"services"`
}

// AccessMapZiti is the Ziti pillar: the user's network identity and reach.
type AccessMapZiti struct {
	Identity          *AccessMapZitiIdentity `json:"identity"` // nil = not synced
	Devices           []AccessMapDevice      `json:"devices"`
	DialPolicies      []AccessMapDialPolicy  `json:"dial_policies"`
	ReachableServices []string               `json:"reachable_services"`
	TrustedDevice     bool                   `json:"trusted_device"`
}

// AccessMapEvent is one unified audit event (openidx / ziti / guacamole).
type AccessMapEvent struct {
	Source    string    `json:"source"`
	EventType string    `json:"event_type"`
	ActorIP   string    `json:"actor_ip,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// UserAccessMap is the full cross-pillar correlation for one user.
type UserAccessMap struct {
	User        AccessMapUser    `json:"user"`
	IAM         AccessMapIAM     `json:"iam"`
	PAM         AccessMapPAM     `json:"pam"`
	Ziti        AccessMapZiti    `json:"ziti"`
	Activity    []AccessMapEvent `json:"activity"`
	GeneratedAt time.Time        `json:"generated_at"`
}

// handleUserAccessMap returns the cross-pillar access map for one user.
// GET /api/v1/access/users/:id/access-map (admin)
func (s *Service) handleUserAccessMap(c *gin.Context) {
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.Param("id")

	m, err := s.buildUserAccessMap(ctx, org.ID, userID)
	if err != nil {
		if err == errAccessMapUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		s.logger.Error("handleUserAccessMap: aggregation failed",
			zap.String("user_id", userID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build access map"})
		return
	}

	c.JSON(http.StatusOK, m)
}

// errAccessMapUserNotFound distinguishes "no such user in this org" from a
// query failure so the handler can 404 instead of 500.
var errAccessMapUserNotFound = &accessMapError{"user not found"}

type accessMapError struct{ msg string }

func (e *accessMapError) Error() string { return e.msg }

// buildUserAccessMap aggregates the three pillars for one user. The user row
// is resolved first (also the org-membership check); every subsequent query is
// keyed by the verified (user, org) pair.
func (s *Service) buildUserAccessMap(ctx context.Context, orgID, userID string) (*UserAccessMap, error) {
	m := &UserAccessMap{GeneratedAt: time.Now().UTC()}

	// --- Identity header (and org-membership gate) ---
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, username, email, enabled, created_at, last_login_at
		   FROM users WHERE id = $1 AND org_id = $2`, userID, orgID).
		Scan(&m.User.ID, &m.User.Username, &m.User.Email, &m.User.Enabled,
			&m.User.CreatedAt, &m.User.LastLoginAt)
	if err != nil {
		return nil, errAccessMapUserNotFound
	}

	if err := s.collectIAMPillar(ctx, orgID, userID, &m.IAM); err != nil {
		return nil, err
	}
	if err := s.collectPAMPillar(ctx, orgID, userID, &m.PAM); err != nil {
		return nil, err
	}
	if err := s.collectZitiPillar(ctx, orgID, userID, &m.Ziti); err != nil {
		return nil, err
	}

	// --- Cross-pillar activity (unified audit: openidx + ziti + guacamole) ---
	// unified_audit_events has no org_id column; scoping is inherited from the
	// org-verified user_id key above.
	//orgscope:ignore unified_audit_events is keyed by the org-verified user_id resolved above
	rows, err := s.db.Pool.Query(ctx,
		`SELECT source, event_type, COALESCE(actor_ip, ''), created_at
		   FROM unified_audit_events
		  WHERE user_id = $1
		  ORDER BY created_at DESC
		  LIMIT 25`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m.Activity = []AccessMapEvent{}
	for rows.Next() {
		var e AccessMapEvent
		if err := rows.Scan(&e.Source, &e.EventType, &e.ActorIP, &e.CreatedAt); err != nil {
			return nil, err
		}
		m.Activity = append(m.Activity, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return m, nil
}

// collectIAMPillar fills roles, groups, live sessions, API keys, and pending
// access requests.
func (s *Service) collectIAMPillar(ctx context.Context, orgID, userID string, out *AccessMapIAM) error {
	out.Roles = []NamedRef{}
	out.Groups = []NamedRef{}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT r.id, r.name
		   FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		  WHERE ur.user_id = $1 AND ur.org_id = $2 ORDER BY r.name`, userID, orgID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ref NamedRef
		if err := rows.Scan(&ref.ID, &ref.Name); err != nil {
			rows.Close()
			return err
		}
		out.Roles = append(out.Roles, ref)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = s.db.Pool.Query(ctx,
		`SELECT g.id, g.name
		   FROM group_memberships gm JOIN groups g ON g.id = gm.group_id
		  WHERE gm.user_id = $1 AND gm.org_id = $2 ORDER BY g.name`, userID, orgID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ref NamedRef
		if err := rows.Scan(&ref.ID, &ref.Name); err != nil {
			rows.Close()
			return err
		}
		out.Groups = append(out.Groups, ref)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions
		  WHERE user_id = $1 AND org_id = $2
		    AND (revoked IS NULL OR revoked = false) AND expires_at > NOW()`,
		userID, orgID).Scan(&out.ActiveSessions)
	if err != nil {
		return err
	}
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM api_keys
		  WHERE user_id = $1 AND org_id = $2 AND status = 'active'`,
		userID, orgID).Scan(&out.ActiveAPIKeys)
	if err != nil {
		return err
	}
	return s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM access_requests
		  WHERE requester_id = $1 AND org_id = $2 AND status = 'pending'`,
		userID, orgID).Scan(&out.PendingRequests)
}

// collectPAMPillar fills vault grants (direct + role-mediated), active
// checkouts, JIT elevations, and privileged sessions with their Ziti overlay
// flag — the PAM side of the cross-pillar correlation.
func (s *Service) collectPAMPillar(ctx context.Context, orgID, userID string, out *AccessMapPAM) error {
	out.VaultGrants = []AccessMapVaultGrant{}
	out.ActiveCheckouts = []AccessMapCheckout{}
	out.ActiveJITGrants = []AccessMapJITGrant{}
	out.ActiveSessions = []AccessMapPrivSession{}

	// Vault grants: direct user grants plus grants on any of the user's roles.
	rows, err := s.db.Pool.Query(ctx,
		`SELECT vs.id, vs.name, vs.type, vg.actions, 'user' AS via, vg.expires_at
		   FROM vault_access_grants vg
		   JOIN vault_secrets vs ON vs.id = vg.secret_id
		  WHERE vg.org_id = $2 AND vg.principal_type = 'user' AND vg.principal_id = $1
		    AND (vg.expires_at IS NULL OR vg.expires_at > NOW())
		 UNION ALL
		 SELECT vs.id, vs.name, vs.type, vg.actions, 'role:' || r.name, vg.expires_at
		   FROM vault_access_grants vg
		   JOIN vault_secrets vs ON vs.id = vg.secret_id
		   JOIN roles r          ON r.id  = vg.principal_id
		   JOIN user_roles ur    ON ur.role_id = r.id AND ur.user_id = $1 AND ur.org_id = $2
		  WHERE vg.org_id = $2 AND vg.principal_type = 'role'
		    AND (vg.expires_at IS NULL OR vg.expires_at > NOW())
		 ORDER BY 2`, userID, orgID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var g AccessMapVaultGrant
		if err := rows.Scan(&g.SecretID, &g.SecretName, &g.SecretType, &g.Actions, &g.Via, &g.ExpiresAt); err != nil {
			rows.Close()
			return err
		}
		if g.Actions == nil {
			g.Actions = []string{}
		}
		out.VaultGrants = append(out.VaultGrants, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Active credential leases.
	rows, err = s.db.Pool.Query(ctx,
		`SELECT vc.id, vs.name, vc.mode, vc.leased_at, vc.expires_at
		   FROM vault_checkouts vc
		   JOIN vault_secrets vs ON vs.id = vc.secret_id
		  WHERE vc.org_id = $2 AND vc.principal_id = $1 AND vc.status = 'active'
		  ORDER BY vc.leased_at DESC`, userID, orgID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var co AccessMapCheckout
		if err := rows.Scan(&co.ID, &co.SecretName, &co.Mode, &co.LeasedAt, &co.ExpiresAt); err != nil {
			rows.Close()
			return err
		}
		out.ActiveCheckouts = append(out.ActiveCheckouts, co)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Active JIT role elevations.
	rows, err = s.db.Pool.Query(ctx,
		`SELECT id, role_name, expires_at FROM jit_grants
		  WHERE user_id = $1 AND org_id = $2 AND status = 'active' AND expires_at > NOW()
		  ORDER BY expires_at`, userID, orgID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var j AccessMapJITGrant
		if err := rows.Scan(&j.ID, &j.RoleName, &j.ExpiresAt); err != nil {
			rows.Close()
			return err
		}
		out.ActiveJITGrants = append(out.ActiveJITGrants, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Privileged sessions, correlated with the Ziti overlay: a session is
	// "over Ziti" when its connection's route is Ziti-enabled.
	rows, err = s.db.Pool.Query(ctx,
		`SELECT gs.id, COALESCE(pr.name, ''), COALESCE(gc.protocol, ''),
		        gs.started_at, COALESCE(pr.ziti_enabled, false)
		   FROM guacamole_sessions gs
		   LEFT JOIN guacamole_connections gc ON gc.id = gs.connection_id
		   LEFT JOIN proxy_routes pr          ON pr.id = gc.route_id
		  WHERE gs.user_id = $1 AND gs.org_id = $2 AND gs.status = 'active'
		  ORDER BY gs.started_at DESC`, userID, orgID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ps AccessMapPrivSession
		if err := rows.Scan(&ps.ID, &ps.RouteName, &ps.Protocol, &ps.StartedAt, &ps.OverZiti); err != nil {
			rows.Close()
			return err
		}
		out.ActiveSessions = append(out.ActiveSessions, ps)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM guacamole_sessions
		  WHERE user_id = $1 AND org_id = $2 AND started_at > NOW() - INTERVAL '30 days'`,
		userID, orgID).Scan(&out.Sessions30d)
	if err != nil {
		return err
	}
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM guacamole_session_requests
		  WHERE requester_id = $1 AND org_id = $2 AND status = 'pending'
		    AND (expires_at IS NULL OR expires_at > NOW())`,
		userID, orgID).Scan(&out.PendingSessionRequests)
	if err != nil {
		return err
	}
	return s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM access_requests
		  WHERE requester_id = $1 AND org_id = $2
		    AND resource_type = 'vault_credential' AND status = 'pending'`,
		userID, orgID).Scan(&out.PendingCredRequests)
}

// collectZitiPillar fills the user's Ziti identity, enrolled devices, the Dial
// policies that apply to their identity, and the services those resolve to.
func (s *Service) collectZitiPillar(ctx context.Context, orgID, userID string, out *AccessMapZiti) error {
	out.Devices = []AccessMapDevice{}
	out.DialPolicies = []AccessMapDialPolicy{}
	out.ReachableServices = []string{}

	// The user's Ziti identity (nil when the 30s sync hasn't run or user is new).
	var ident AccessMapZitiIdentity
	var attrsJSON []byte
	err := s.db.Pool.QueryRow(ctx,
		`SELECT ziti_id, name, enrolled, attributes
		   FROM ziti_identities WHERE user_id = $1 AND org_id = $2`,
		userID, orgID).Scan(&ident.ZitiID, &ident.Name, &ident.Enrolled, &attrsJSON)
	if err == nil {
		if len(attrsJSON) > 0 {
			_ = json.Unmarshal(attrsJSON, &ident.Attributes)
		}
		if ident.Attributes == nil {
			ident.Attributes = []string{}
		}
		out.Identity = &ident
	}

	// Devices: endpoint agents this user enrolled. enrolled_agents has no
	// org_id column; the JOIN back to the org-verified user provides scoping.
	//orgscope:ignore enrolled_agents is scoped through the org-verified enrolled_by_user_id join
	rows, err := s.db.Pool.Query(ctx,
		`SELECT ea.agent_id, COALESCE(ea.platform, ''), ea.status,
		        ea.compliance_status, COALESCE(ea.ziti_identity_id, ''), ea.last_seen_at
		   FROM enrolled_agents ea
		  WHERE ea.enrolled_by_user_id = $1
		  ORDER BY ea.enrolled_at DESC`, userID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var d AccessMapDevice
		if err := rows.Scan(&d.AgentID, &d.Platform, &d.Status, &d.ComplianceStatus, &d.ZitiIdentityID, &d.LastSeenAt); err != nil {
			rows.Close()
			return err
		}
		out.Devices = append(out.Devices, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Trusted device flag (feeds the #device-trusted attribute in the sync).
	err = s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM known_devices
		                WHERE user_id = $1 AND org_id = $2 AND trusted = true)`,
		userID, orgID).Scan(&out.TrustedDevice)
	if err != nil {
		return err
	}

	// Dial policies that apply to this identity, resolved against the local
	// service mirror. Without a synced identity there is nothing to match.
	if out.Identity == nil {
		return nil
	}

	type policyRow struct {
		name          string
		identityRoles []string
		serviceRoles  []string
	}
	var policies []policyRow
	rows, err = s.db.Pool.Query(ctx,
		`SELECT name, identity_roles, service_roles
		   FROM ziti_service_policies
		  WHERE org_id = $1 AND policy_type = 'Dial'
		  ORDER BY name`, orgID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var p policyRow
		var identJSON, svcJSON []byte
		if err := rows.Scan(&p.name, &identJSON, &svcJSON); err != nil {
			rows.Close()
			return err
		}
		_ = json.Unmarshal(identJSON, &p.identityRoles)
		_ = json.Unmarshal(svcJSON, &p.serviceRoles)
		policies = append(policies, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Local service mirror for resolving @id / #all service roles.
	svcByZitiID := map[string]string{}
	var allServices []string
	rows, err = s.db.Pool.Query(ctx,
		`SELECT ziti_id, name FROM ziti_services
		  WHERE org_id = $1 AND enabled = true ORDER BY name`, orgID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var zid, name string
		if err := rows.Scan(&zid, &name); err != nil {
			rows.Close()
			return err
		}
		svcByZitiID[zid] = name
		allServices = append(allServices, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	reachable := map[string]bool{}
	for _, p := range policies {
		if !policyAppliesToIdentity(p.identityRoles, ident.ZitiID, ident.Attributes) {
			continue
		}
		resolved := resolveServiceRoles(p.serviceRoles, svcByZitiID, allServices)
		out.DialPolicies = append(out.DialPolicies, AccessMapDialPolicy{Name: p.name, Services: resolved})
		for _, svc := range resolved {
			reachable[svc] = true
		}
	}
	for svc := range reachable {
		out.ReachableServices = append(out.ReachableServices, svc)
	}
	sort.Strings(out.ReachableServices)

	return nil
}

// policyAppliesToIdentity implements OpenZiti role-attribute matching for the
// local mirror: `#all` matches everyone, `@<ziti_id>` pins a specific
// identity, and `#attr` matches when the identity carries that role attribute.
func policyAppliesToIdentity(identityRoles []string, zitiID string, attrs []string) bool {
	attrSet := make(map[string]bool, len(attrs))
	for _, a := range attrs {
		attrSet[strings.TrimPrefix(a, "#")] = true
	}
	for _, role := range identityRoles {
		switch {
		case role == "#all":
			return true
		case strings.HasPrefix(role, "@"):
			if strings.TrimPrefix(role, "@") == zitiID {
				return true
			}
		case strings.HasPrefix(role, "#"):
			if attrSet[strings.TrimPrefix(role, "#")] {
				return true
			}
		}
	}
	return false
}

// resolveServiceRoles maps a policy's service_roles onto service names using
// the local mirror. `#all` expands to every enabled service, `@id` resolves
// via ziti_services.ziti_id, and `#tag` references (service attributes are not
// mirrored locally) are surfaced as-is so the caller still sees the intent.
func resolveServiceRoles(serviceRoles []string, svcByZitiID map[string]string, allServices []string) []string {
	var resolved []string
	seen := map[string]bool{}
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			resolved = append(resolved, name)
		}
	}
	for _, role := range serviceRoles {
		switch {
		case role == "#all":
			for _, name := range allServices {
				add(name)
			}
		case strings.HasPrefix(role, "@"):
			if name, ok := svcByZitiID[strings.TrimPrefix(role, "@")]; ok {
				add(name)
			}
		case strings.HasPrefix(role, "#"):
			add(role) // unresolvable tag reference — keep the intent visible
		}
	}
	if resolved == nil {
		resolved = []string{}
	}
	return resolved
}

// verifyOrgUser confirms a user id belongs to the given org (used by the
// kill-switch handler before mutating anything).
func (s *Service) verifyOrgUser(ctx context.Context, orgID, userID string) (username string, enabled bool, err error) {
	err = s.db.Pool.QueryRow(ctx,
		`SELECT username, enabled FROM users WHERE id = $1 AND org_id = $2`,
		userID, orgID).Scan(&username, &enabled)
	return username, enabled, err
}
