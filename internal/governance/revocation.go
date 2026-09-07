package governance

import (
	"context"

	"github.com/openidx/openidx/internal/jitgrant"
)

// revokeResourceAssignment removes a single (user, resource) grant.
//
// The implementation moved to internal/jitgrant, which is a leaf package the
// access, identity and portal services can import too. It used to be
// unexported here, and that is exactly why the kill switch, the lifecycle
// sweep and deprovisioning each wrote their own revocation -- against
// jit_grants, a table nothing in the product writes. This wrapper stays
// because governance calls it from four places and the shorter name reads
// better at those call sites.
func revokeResourceAssignment(ctx context.Context, q jitgrant.Execer, resourceType, userID, resourceID, orgID string) error {
	return jitgrant.Revoke(ctx, q, resourceType, userID, resourceID, orgID)
}
