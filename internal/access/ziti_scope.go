package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// WHAT ONE CALLER MAY SEE OF THE OPENZITI CONTROLLER.
//
// One controller serves every organization on an install. Its services,
// identities, policies, configs, terminators and sessions carry no tenant, so
// a route that relays one of its collections relays every organization's, and
// several of them name internal addresses: a host.v1 config's host and port, a
// terminator's address, a router's hostname.
//
// Which organization owns what is recorded in three mirror tables under the
// RLS belt: ziti_services (by controller id, and by name, which the controller
// keeps unique), ziti_identities and ziti_service_policies. A route that
// relays the controller does one of two things with that:
//
//   - It shows an install administrator (middleware.IsInstallAdministrator,
//     the rule behind requirePlatformAdmin) the whole controller, and anyone
//     else the part their organization owns: its services, the configs and
//     terminators of those services, its policies, and the sessions between
//     its identities and its services. An object no organization owns is the
//     install's, and only an install administrator sees it.
//   - Or it serves something that belongs to no organization -- the edge
//     routers, the edge-router and authentication policies, the JWT signers,
//     the fabric metrics, the AI ledger -- and the route itself needs an
//     install administrator (requirePlatformAdmin).
//
// A session needs both of its ends in the organization: one whose identity is
// another organization's names that organization's user, and one whose
// service is another's names that organization's service.

// zitiView is one caller's view of the controller: all of it, or one
// organization's part.
type zitiView struct {
	install bool
	orgID   string
}

// zitiViewFor decides the caller's view. When it cannot, it has written the
// refusal and returns false; it never falls back to either view.
func (s *Service) zitiViewFor(c *gin.Context) (*zitiView, bool) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return nil, false
	}
	install, err := middleware.IsInstallAdministrator(c, s.db)
	if err != nil {
		s.logger.Error("could not decide whether the caller administers the install; refusing",
			logsafe.String("user_id", c.GetString("user_id")), zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "platform administrator check unavailable"})
		return nil, false
	}
	return &zitiView{install: install, orgID: org.ID}, true
}

// ownedZitiServices returns the controller ids and the names of the
// organization's services.
func (s *Service) ownedZitiServices(ctx context.Context, orgID string) (ids, names map[string]bool, err error) {
	rows, err := s.db.Pool.Query(ctx, `SELECT ziti_id, name FROM ziti_services WHERE org_id = $1`, orgID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	ids, names = map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, nil, err
		}
		ids[id], names[name] = true, true
	}
	return ids, names, rows.Err()
}

// ownedZitiIdentities returns the controller ids of the organization's
// identities.
func (s *Service) ownedZitiIdentities(ctx context.Context, orgID string) (map[string]bool, error) {
	return s.ownedZitiIDs(ctx, `SELECT ziti_id FROM ziti_identities WHERE org_id = $1`, orgID)
}

// ownedZitiPolicies returns the controller ids of the organization's service
// policies.
func (s *Service) ownedZitiPolicies(ctx context.Context, orgID string) (map[string]bool, error) {
	return s.ownedZitiIDs(ctx, `SELECT ziti_id FROM ziti_service_policies WHERE org_id = $1`, orgID)
}

func (s *Service) ownedZitiIDs(ctx context.Context, query, orgID string) (map[string]bool, error) {
	rows, err := s.db.Pool.Query(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// ownedZitiConfigs returns the ids of the configs the organization's services
// use, as the controller's services list them.
func (s *Service) ownedZitiConfigs(ctx context.Context, orgID string) (map[string]bool, error) {
	ids, _, err := s.ownedZitiServices(ctx, orgID)
	if err != nil {
		return nil, err
	}
	services, err := s.ziti().ListServices(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, svc := range services {
		if !ids[svc.ID] {
			continue
		}
		for _, cfg := range svc.Configs {
			out[cfg] = true
		}
	}
	return out, nil
}

// ownsZitiService reports whether the controller service with this id is one
// of the organization's.
func (s *Service) ownsZitiService(ctx context.Context, orgID, zitiID string) (bool, error) {
	var owned bool
	err := s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM ziti_services WHERE ziti_id = $1 AND org_id = $2)`, zitiID, orgID).Scan(&owned)
	return owned, err
}

// ownsZitiIdentity reports whether the controller identity with this id is one
// of the organization's.
func (s *Service) ownsZitiIdentity(ctx context.Context, orgID, zitiID string) (bool, error) {
	var owned bool
	err := s.db.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM ziti_identities WHERE ziti_id = $1 AND org_id = $2)`, zitiID, orgID).Scan(&owned)
	return owned, err
}

// ownsZitiSession reports whether the controller session with this id runs
// between one of the organization's identities and one of its services. A
// session the controller does not know is nobody's.
func (s *Service) ownsZitiSession(ctx context.Context, orgID, id string) (bool, error) {
	data, status, err := s.ziti().MgmtRequest("GET", "/edge/management/v1/sessions/"+url.PathEscape(id), nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return false, nil
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("controller answered %d reading session", status)
	}
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return false, err
	}
	identity, service := zitiSessionEnds(resp.Data)
	if identity.ID == "" || service.ID == "" {
		return false, nil
	}
	ownIdentity, err := s.ownsZitiIdentity(ctx, orgID, identity.ID)
	if err != nil || !ownIdentity {
		return false, err
	}
	return s.ownsZitiService(ctx, orgID, service.ID)
}

// ownsZitiTerminator reports whether the controller terminator with this id
// hosts one of the organization's services.
func (s *Service) ownsZitiTerminator(ctx context.Context, orgID, id string) (bool, error) {
	data, status, err := s.ziti().MgmtRequest("GET", "/edge/management/v1/terminators/"+url.PathEscape(id), nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return false, nil
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("controller answered %d reading terminator", status)
	}
	var resp struct {
		Data zitiTerminator `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return false, err
	}
	if resp.Data.serviceID() == "" {
		return false, nil
	}
	return s.ownsZitiService(ctx, orgID, resp.Data.serviceID())
}

// zitiEntityRef is the {id, name} reference the controller embeds for a
// related object.
type zitiEntityRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// zitiSessionEnds reads the identity and the service of one controller session.
// The controller has placed the identity in three spellings over its versions:
// an embedded reference, a bare identityId, and inside the API session.
func zitiSessionEnds(raw json.RawMessage) (identity, service zitiEntityRef) {
	var entry struct {
		Identity   *zitiEntityRef `json:"identity"`
		IdentityID string         `json:"identityId"`
		Service    *zitiEntityRef `json:"service"`
		ServiceID  string         `json:"serviceId"`
		APISession struct {
			Identity   *zitiEntityRef `json:"identity"`
			IdentityID string         `json:"identityId"`
		} `json:"apiSession"`
	}
	if json.Unmarshal(raw, &entry) != nil {
		return
	}
	switch {
	case entry.Identity != nil && entry.Identity.ID != "":
		identity = *entry.Identity
	case entry.IdentityID != "":
		identity = zitiEntityRef{ID: entry.IdentityID, Name: entry.IdentityID}
	case entry.APISession.Identity != nil && entry.APISession.Identity.ID != "":
		identity = *entry.APISession.Identity
	case entry.APISession.IdentityID != "":
		identity = zitiEntityRef{ID: entry.APISession.IdentityID, Name: entry.APISession.IdentityID}
	}
	switch {
	case entry.Service != nil && entry.Service.ID != "":
		service = *entry.Service
	case entry.ServiceID != "":
		service = zitiEntityRef{ID: entry.ServiceID, Name: entry.ServiceID}
	}
	return
}
