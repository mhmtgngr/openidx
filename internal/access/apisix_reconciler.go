package access

import (
	"context"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// apisixAdmin is the subset of the Admin client the reconciler needs (fakeable).
type apisixAdmin interface {
	PutRoute(ctx context.Context, name string, body []byte) error
	DeleteRoute(ctx context.Context, name string) error
	ListRouteNames(ctx context.Context) ([]string, error)
}

// APISIXReconciler converges APISIX routes to the BrowZer-enabled proxy_routes.
// Replaces the nginx public-vhost generator when APISIX owns the edge.
type APISIXReconciler struct {
	db     *database.PostgresDB
	logger *zap.Logger
	client apisixAdmin
	tm     *BrowZerTargetManager // for queryBrowZerRoutes
	opts   apisixRouteOpts
}

func NewAPISIXReconciler(db *database.PostgresDB, log *zap.Logger, client apisixAdmin, tm *BrowZerTargetManager, opts apisixRouteOpts) *APISIXReconciler {
	return &APISIXReconciler{db: db, logger: log.With(zap.String("component", "apisix-reconciler")), client: client, tm: tm, opts: opts}
}

// Client exposes the underlying Admin API client (the health doctor reads route
// names through it). Returns the apisixAdmin seam; may be nil.
func (r *APISIXReconciler) Client() apisixAdmin { return r.client }

// Reconcile loads the desired edge state and converges APISIX.
//
// Two sources, one pass. The BrowZer routes are the ones this reconciler was
// written for; the pool-backed routes are the other half of upstream pools, and
// they were the reason the feature did nothing: BuildEdgeRoutesForPools existed,
// was tested, and was called by nobody, so a pool could never reach the data
// plane even if somebody had inserted one by hand.
//
// A failure to read the pools does not abandon the BrowZer routes. They are two
// independent sets of desired state, and dropping a live app's route because a
// pool query failed would turn a new feature's fault into an outage of an old
// one. The pass converges what it could read and says what it could not.
func (rec *APISIXReconciler) Reconcile(ctx context.Context) error {
	ctx = orgctx.WithBypassRLS(ctx)
	browzer, err := rec.tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return err
	}
	objs := buildBrowZerAPISIXRoutes(browzer, rec.opts)

	pooled, perr := BuildEdgeRoutesForPools(ctx, rec.db, rec.logger)
	if perr != nil {
		// Not fatal, but not silent: with the pool set unread, every
		// oidx-route-* object would look undesired, so the pass must not prune
		// and must say why it is converging only half the edge.
		rec.logger.Error("could not read upstream pools; leaving pool-backed routes as they are this pass",
			zap.Error(perr))
		return rec.applyRoutes(ctx, objs, prunePrefixes(browzerRoutePrefix))
	}
	objs = append(objs, pooled...)
	return rec.applyRoutes(ctx, objs, prunePrefixes(browzerRoutePrefix, edgeRoutePrefix))
}

// applyRoutes PUTs every desired route and prunes generated routes that are no
// longer desired. The prune set is computed from the FULL desired set (what the
// DB says should exist), NOT from which PUTs happened to succeed: a transient
// PUT failure on a still-desired route must never make it a prune target, and
// an all-PUTs-fail pass must never delete still-desired routes. Failed PUTs are
// logged and re-converge on the next pass.
//
// prunable names which generated prefixes this pass is entitled to delete. A
// pass that could not read one of the two sources passes only the prefix it did
// read, so an unread source is left alone rather than pruned to nothing.
func (rec *APISIXReconciler) applyRoutes(ctx context.Context, objs []apisixRoute, prunable []string) error {
	desiredNames := make([]string, 0, len(objs))
	for _, o := range objs {
		desiredNames = append(desiredNames, o.name)
		if err := rec.client.PutRoute(ctx, o.name, o.body); err != nil {
			rec.logger.Warn("PUT route failed (will retry next reconcile)", zap.String("name", o.name), zap.Error(err))
		}
	}
	existing, err := rec.client.ListRouteNames(ctx)
	if err != nil {
		return err
	}
	for _, name := range staleGeneratedRouteNames(existing, desiredNames, prunable) {
		if err := rec.client.DeleteRoute(ctx, name); err != nil {
			rec.logger.Warn("DELETE stale route failed", zap.String("name", name), zap.Error(err))
		}
	}
	return nil
}
