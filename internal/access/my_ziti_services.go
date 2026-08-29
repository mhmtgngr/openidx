package access

import (
	"context"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// MyZitiService is one zero-trust (OpenZiti) service the calling user can reach,
// enriched with the connection details a user needs to make sense of it. It
// intentionally speaks plain language (no overlay vocabulary).
type MyZitiService struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

// MyZitiServicesResponse is the payload of GET /my/ziti/services.
type MyZitiServicesResponse struct {
	Linked   bool            `json:"linked"`   // has a synced Ziti identity
	Enrolled bool            `json:"enrolled"` // a device has completed enrollment
	Services []MyZitiService `json:"services"`
}

// handleMyZitiServices returns the OpenZiti services the CALLER can reach —
// the self-service counterpart to the admin access map's Ziti pillar. It reuses
// collectZitiPillar to resolve the caller's Dial-policy reach, then enriches the
// service names with host/port/protocol from the local service mirror so the
// user sees where each app lives, not just its name.
func (s *Service) handleMyZitiServices(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		// Dev-mode convenience, mirroring handleGetMyZitiIdentity.
		userID = c.Query("user_id")
	}
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	resp, err := s.myZitiServices(c.Request.Context(), org.ID, userID)
	if err != nil {
		s.logger.Error("my/ziti/services: aggregation failed",
			zap.String("user_id", scrubLogValue(userID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load zero-trust apps"})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// myZitiServices computes the caller's reachable Ziti services and enriches them
// with connection details. Split out from the handler so it is unit-testable.
func (s *Service) myZitiServices(ctx context.Context, orgID, userID string) (*MyZitiServicesResponse, error) {
	resp := &MyZitiServicesResponse{Services: []MyZitiService{}}

	var pillar AccessMapZiti
	if err := s.collectZitiPillar(ctx, orgID, userID, &pillar); err != nil {
		return nil, err
	}
	if pillar.Identity != nil {
		resp.Linked = true
		resp.Enrolled = pillar.Identity.Enrolled
	}
	if len(pillar.ReachableServices) == 0 {
		return resp, nil
	}

	// Enrich the reachable service names with connection details from the local
	// mirror. A name with no mirror row still surfaces (name-only) so the user
	// isn't shown fewer apps than they can actually dial.
	details := map[string]MyZitiService{}
	rows, err := s.db.Pool.Query(ctx,
		`SELECT name, COALESCE(description, ''), COALESCE(host, ''), COALESCE(port, 0), COALESCE(protocol, '')
		   FROM ziti_services
		  WHERE org_id = $1 AND name = ANY($2)`, orgID, pillar.ReachableServices)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d MyZitiService
		if err := rows.Scan(&d.Name, &d.Description, &d.Host, &d.Port, &d.Protocol); err != nil {
			return nil, err
		}
		details[d.Name] = d
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, name := range pillar.ReachableServices {
		if d, ok := details[name]; ok {
			resp.Services = append(resp.Services, d)
		} else {
			resp.Services = append(resp.Services, MyZitiService{Name: name})
		}
	}
	sort.Slice(resp.Services, func(i, j int) bool { return resp.Services[i].Name < resp.Services[j].Name })
	return resp, nil
}
