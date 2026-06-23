package access

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// HostingMode constants determine how an access-proxy route is terminated.
const (
	// HostingModeIdentity — access-proxy is the terminator; it injects identity
	// headers before forwarding to the upstream.
	HostingModeIdentity = "identity"
	// HostingModeDirect — edge router hosts via host.v1 (Phase 2). Used
	// automatically for all BrowZer routes.
	HostingModeDirect = "direct"
)

// DesiredRoute is the reconciler's view of a ziti-enabled proxy_route.
type DesiredRoute struct {
	ServiceName    string
	ToURL          string
	HostingMode    string
	BrowZerEnabled bool
}

// EffectiveMode resolves the hosting mode, forcing "direct" for BrowZer routes
// and defaulting empty to "identity".
func (r DesiredRoute) EffectiveMode() string {
	if r.BrowZerEnabled {
		return HostingModeDirect
	}
	if r.HostingMode == HostingModeDirect {
		return HostingModeDirect
	}
	return HostingModeIdentity
}

// ZitiReconciler converges Ziti to the DB's desired state. One worker, a
// coalescing trigger channel, and a periodic safety-net tick — so concurrent
// mutation races cannot happen (the reconciler is the only mutator of Ziti).
type ZitiReconciler struct {
	db       *database.PostgresDB
	logger   *zap.Logger
	provider *ZitiProvider // source of the live ZitiManager
	period   time.Duration

	trigger chan struct{}         // coalescing: buffered size 1
	runOnce func(context.Context) // overridable in tests; defaults to reconcileOnce (added in a later task)
	mu      sync.Mutex            // serializes runs
	status  map[string]string     // serviceName -> "synced" | "error: ..."
}

// NewZitiReconciler creates a ZitiReconciler with a 30-second safety-net
// period. Call Start(ctx) to begin the reconcile loop.
func NewZitiReconciler(db *database.PostgresDB, logger *zap.Logger, provider *ZitiProvider) *ZitiReconciler {
	rec := &ZitiReconciler{
		db:       db,
		logger:   logger.With(zap.String("component", "ziti-reconciler")),
		provider: provider,
		period:   30 * time.Second,
		trigger:  make(chan struct{}, 1),
		status:   make(map[string]string),
	}
	rec.runOnce = rec.reconcileOnce
	return rec
}

// Enqueue requests a reconcile; coalesces (non-blocking send to a size-1 chan).
func (rec *ZitiReconciler) Enqueue() {
	select {
	case rec.trigger <- struct{}{}:
	default:
	}
}

// Start launches the single worker: drains triggers and ticks periodically.
func (rec *ZitiReconciler) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(rec.period)
		defer ticker.Stop()
		rec.runLocked(ctx) // initial reconcile
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rec.runLocked(ctx)
			case <-rec.trigger:
				rec.runLocked(ctx)
			}
		}
	}()
}

func (rec *ZitiReconciler) runLocked(ctx context.Context) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.runOnce(ctx)
}

// loadDesiredRoutes reads all ziti-enabled routes from the DB (install-wide; RLS bypassed).
func (rec *ZitiReconciler) loadDesiredRoutes(ctx context.Context) ([]DesiredRoute, error) {
	ctx = orgctx.WithBypassRLS(ctx)
	rows, err := rec.db.Pool.Query(ctx,
		//orgscope:ignore install-wide Ziti reconcile; keyed by globally-unique ziti_service_name across all orgs
		`SELECT ziti_service_name, to_url, COALESCE(hosting_mode,'identity'), COALESCE(browzer_enabled,false)
		 FROM proxy_routes
		 WHERE ziti_enabled = true AND enabled = true
		   AND ziti_service_name IS NOT NULL AND ziti_service_name != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DesiredRoute
	for rows.Next() {
		var d DesiredRoute
		if err := rows.Scan(&d.ServiceName, &d.ToURL, &d.HostingMode, &d.BrowZerEnabled); err != nil {
			rec.logger.Warn("reconciler: scan route failed", zap.Error(err))
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

// reconcileOnce is implemented in a later task (Task 7). Stub for now.
// TODO(Task 7): replace this body with the real convergence logic that calls
// loadDesiredRoutes, lists live Ziti services, and ensures/deletes as needed.
func (rec *ZitiReconciler) reconcileOnce(ctx context.Context) {}
