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

// Reconcile loads the desired BrowZer routes and converges APISIX.
func (rec *APISIXReconciler) Reconcile(ctx context.Context) error {
	ctx = orgctx.WithBypassRLS(ctx)
	desired, err := rec.tm.queryBrowZerRoutes(ctx)
	if err != nil {
		return err
	}
	return rec.applyRoutes(ctx, desired)
}

// applyRoutes PUTs the desired routes and prunes stale browzer-* routes.
func (rec *APISIXReconciler) applyRoutes(ctx context.Context, desired []browzerRouteInfo) error {
	objs := buildBrowZerAPISIXRoutes(desired, rec.opts)
	desiredNames := make([]string, 0, len(objs))
	for _, o := range objs {
		if err := rec.client.PutRoute(ctx, o.name, o.body); err != nil {
			rec.logger.Warn("PUT route failed", zap.String("name", o.name), zap.Error(err))
			continue
		}
		desiredNames = append(desiredNames, o.name)
	}
	existing, err := rec.client.ListRouteNames(ctx)
	if err != nil {
		return err
	}
	for _, name := range staleBrowZerRouteNames(existing, desiredNames) {
		if err := rec.client.DeleteRoute(ctx, name); err != nil {
			rec.logger.Warn("DELETE stale route failed", zap.String("name", name), zap.Error(err))
		}
	}
	return nil
}
