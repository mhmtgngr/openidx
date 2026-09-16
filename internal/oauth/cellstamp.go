package oauth

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/celldir"
	"github.com/openidx/openidx/internal/common/logsafe"
)

// tokenCell returns the cell to stamp into an access token minted for org, or
// "" when this install is not celled and the claim should be omitted entirely.
//
// WHY THIS IS NOT JUST s.cellID, WHICH IS WHAT IT WAS. s.cellID is the cell
// that MINTED the token. Stamping that catches a token carried from one cell to
// another -- and it cannot catch a LOGIN that reached the wrong cell, which is
// the same misrouting arriving one step earlier. An eu-1 issuer serving a us-1
// tenant would stamp cell=eu-1; every eu-1 guard then compares eu-1 against
// eu-1, finds them equal, and serves the request from a database that does not
// hold that tenant. That is the confident 404 the 421 exists to replace,
// reaching it through the one door the guard cannot watch.
//
// So the stamp is the tenant's HOME cell when the directory knows one. A guard
// in the wrong cell then refuses the first request rather than the hundredth,
// and the refusal names a real disagreement instead of agreeing with itself.
//
// THE FALLBACKS ARE THE INTERESTING PART, and both land on today's behaviour:
//
//   - Not celled (CELL_ID empty, which is every install today): no lookup, no
//     claim. Nothing about a single-cell deployment changes, including the
//     query cost -- the directory is not read at all.
//   - Celled but this tenant has no placement: stamp the serving cell. A
//     directory is filled in over a migration, not in one transaction, and a
//     tenant that has not been placed yet is being served here by definition.
//   - Celled and the lookup FAILED: stamp the serving cell, and log. This is
//     deliberate and it is the plan's own acceptance criterion for task 4.1 --
//     "directory down 10 min, zero effect for existing tenants". An issuer that
//     refused to mint because the directory was unreachable would convert a
//     directory outage into an authentication outage, which is a strictly worse
//     failure than the one it was guarding against. The cost is that during
//     such an outage a misrouted login is stamped the way it is today; the log
//     line is what keeps that distinguishable afterwards.
func (s *Service) tokenCell(ctx context.Context, orgID string) string {
	return cellStamp(ctx, s.db.Pool, s.cellID, s.logger, orgID)
}

// cellStamp is tokenCell with its dependencies passed in, so the decision can
// be driven against a real directory and a broken one without standing up a
// Service. The rules it encodes are the ones documented on tokenCell.
func cellStamp(ctx context.Context, q celldir.Querier, serving string, logger *zap.Logger, orgID string) string {
	if serving == "" {
		return ""
	}
	home, ok, err := celldir.HomeCell(ctx, q, orgID)
	if ok {
		return home
	}
	if err != nil && !errors.Is(err, celldir.ErrNotPlaced) && logger != nil {
		// Not ErrNotPlaced: that one is ordinary and would be noise on every
		// token minted for a tenant nobody has placed yet.
		logger.Warn("tenant directory unreadable; stamping the serving cell",
			logsafe.String("org_id", orgID),
			zap.String("serving_cell", serving),
			zap.Error(err))
	}
	return serving
}
