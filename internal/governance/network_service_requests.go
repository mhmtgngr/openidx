package governance

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A network service is a governance request type, resource_type
// 'network_service'. The service is one of the organization's Ziti services,
// named by its id in the service mirror (ziti_services). Fulfilling the request
// queues the time-bound attribute jit-<request-id> for the requester's overlay
// identity, and the access service adds it and writes a Dial policy that opens
// the requested service to that attribute alone. The expiry sweep queues the
// attribute's removal, and the access service deletes the policy with it
// (internal/access/network_grant_worker.go).
//
// A request with no window would open the dial for good, so one is required,
// as for a PAM entry or a vault credential.

var (
	refuseNetworkServiceNotFound = &requestRefusal{http.StatusNotFound, "network_service_not_found",
		"network service not found"}
	refuseNetworkServiceDuration = &requestRefusal{http.StatusBadRequest, "network_service_duration_required",
		"a network service request needs a duration: the dial it opens ends with it"}
)

// checkNetworkServiceRequest validates a network_service request and returns
// the service's name, which goes on the request in place of whatever the
// requester typed. A service of another organization, a disabled one and one
// that does not exist answer the same 404.
func (s *Service) checkNetworkServiceRequest(ctx context.Context, orgID, serviceID, duration string) (string, *requestRefusal, error) {
	if _, err := uuid.Parse(serviceID); err != nil {
		return "", refuseNetworkServiceNotFound, nil
	}
	var name string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT name FROM ziti_services WHERE id = $1 AND org_id = $2 AND COALESCE(enabled, true)`,
		serviceID, orgID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", refuseNetworkServiceNotFound, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("read the network service: %w", err)
	}
	if duration == "" {
		return "", refuseNetworkServiceDuration, nil
	}
	return name, nil, nil
}
