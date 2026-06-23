package access

import (
	"context"
	"fmt"
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

	trigger  chan struct{}         // coalescing: buffered size 1
	runOnce  func(context.Context) // overridable in tests; defaults to reconcileOnce
	mu       sync.Mutex            // serializes runs
	statusMu sync.Mutex            // protects status map
	status   map[string]string     // serviceName -> "synced" | "error: ..."
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
	// Surface mid-iteration errors (e.g. a dropped connection) so a partial read
	// isn't mistaken for the full desired set.
	return out, rows.Err()
}

// ensureService makes sure the Ziti service exists with its role attribute.
// Idempotent: looks up by name, creates the service via CreateService if absent
// (controller-only — the reconciler must NOT write back to proxy_routes/ziti_services;
// the DB is the source of truth), tolerating a create race, then ensures the
// service-name role attribute is set.
func (rec *ZitiReconciler) ensureService(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	if existing, _ := zm.GetServiceByName(d.ServiceName); existing != nil {
		return rec.ensureServiceAttr(ctx, zm, existing.ID, d.ServiceName)
	}
	// Service does not exist; create it. Use the minimal management-API path
	// (controller-only — the reconciler must NOT write back to proxy_routes/
	// ziti_services; the DB is the source of truth). Direct mode attaches a fixed
	// host.v1 config so the edge router hosts the service itself; identity mode
	// uses a bare service that the access-proxy terminates via SDK Listen.
	var err error
	switch d.EffectiveMode() {
	case HostingModeDirect:
		host, port := parseHostPort(d.ToURL)
		cfgID, cerr := zm.CreateHostV1ConfigFixed(ctx, d.ServiceName+"-host", host, port)
		if cerr != nil {
			return cerr
		}
		_, err = zm.createServiceWithConfigID(ctx, d.ServiceName, []string{d.ServiceName}, cfgID)
	default:
		_, err = zm.CreateService(ctx, d.ServiceName, []string{d.ServiceName})
	}
	if err != nil {
		// Tolerate a race where another actor created it between our GET and POST.
		if again, _ := zm.GetServiceByName(d.ServiceName); again == nil {
			return err
		}
	}
	svc, gerr := zm.GetServiceByName(d.ServiceName)
	if gerr != nil || svc == nil {
		return gerr
	}
	return rec.ensureServiceAttr(ctx, zm, svc.ID, d.ServiceName)
}

// ensureServiceAttr ensures the service carries its name as a role attribute.
func (rec *ZitiReconciler) ensureServiceAttr(ctx context.Context, zm *ZitiManager, svcID, name string) error {
	attrs, err := zm.GetServiceRoleAttributes(ctx, svcID)
	if err != nil {
		return err
	}
	for _, a := range attrs {
		if a == name {
			return nil
		}
	}
	return zm.PatchServiceRoleAttributes(ctx, svcID, append(attrs, name))
}

// ensurePolicies creates bind/dial/service-edge-router policies for identity mode.
// CreateServicePolicy returns an error (often a 400) when the policy already exists;
// that is the idempotent no-op path, so we tolerate and debug-log those errors.
// ensurePolicies ensures the bind/dial/service-edge-router policies for the
// route. Phase 1 = identity mode: Bind is granted to #access-proxy-clients (the
// access-proxy hosts the terminator). Phase 2 (direct mode) must instead grant
// Bind to the edge-router identities so the router hosts via host.v1 — do NOT
// reuse this identity-mode policy set for direct routes.
func (rec *ZitiReconciler) ensurePolicies(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	svcRole := "#" + d.ServiceName
	bindIdentity := "#access-proxy-clients"
	dialIdentity := "#access-proxy-clients"
	if d.EffectiveMode() == HostingModeDirect {
		// The router hosts the service via host.v1, so Bind goes to the routers;
		// BrowZer clients (synced users) dial via #browzer-users.
		if err := zm.EnsureRouterRoleAttribute(ctx); err != nil {
			rec.logger.Debug("tag routers (may already be tagged)", zap.Error(err))
		}
		bindIdentity = "#ziti-routers"
		dialIdentity = "#browzer-users"
	}
	if _, err := zm.CreateServicePolicy(ctx, "openidx-bind-"+d.ServiceName, "Bind",
		[]string{svcRole}, []string{bindIdentity}); err != nil {
		rec.logger.Debug("bind policy (may already exist)", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	if _, err := zm.CreateServicePolicy(ctx, "openidx-dial-"+d.ServiceName, "Dial",
		[]string{svcRole}, []string{dialIdentity}); err != nil {
		rec.logger.Debug("dial policy (may already exist)", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	if err := zm.EnsureServiceEdgeRouterPolicy(ctx, "openidx-serp-"+d.ServiceName,
		[]string{svcRole}, []string{"#all"}); err != nil {
		rec.logger.Debug("serp (may already exist)", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	return nil
}

// ensureHosting starts hosting for the route. identity mode uses SDK Listen
// (HostService, idempotent). direct mode relies on the host.v1 config created
// in ensureService and the router Bind created in ensurePolicies, so there is
// nothing further to do here — the edge router hosts the service itself.
func (rec *ZitiReconciler) ensureHosting(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	switch d.EffectiveMode() {
	case HostingModeIdentity:
		host, port := parseHostPort(d.ToURL)
		return zm.HostService(d.ServiceName, host, port)
	case HostingModeDirect:
		return nil // router hosts via host.v1; see ensureService/ensurePolicies
	default:
		return fmt.Errorf("unknown hosting mode for service %s", d.ServiceName)
	}
}

func (rec *ZitiReconciler) setStatus(svc, s string) {
	rec.statusMu.Lock()
	defer rec.statusMu.Unlock()
	rec.status[svc] = s
}

// reconcileRoute converges one route, error-isolated, recording per-object status.
func (rec *ZitiReconciler) reconcileRoute(ctx context.Context, zm *ZitiManager, d DesiredRoute) {
	steps := []func(context.Context, *ZitiManager, DesiredRoute) error{
		rec.ensureService, rec.ensurePolicies, rec.ensureHosting,
	}
	for _, step := range steps {
		if err := step(ctx, zm, d); err != nil {
			rec.setStatus(d.ServiceName, "error: "+err.Error())
			rec.logger.Warn("reconcile route failed", zap.String("svc", d.ServiceName), zap.Error(err))
			return
		}
	}
	rec.setStatus(d.ServiceName, "synced")
}

// reconcileOnce loads desired routes and converges each. No live manager → skip.
func (rec *ZitiReconciler) reconcileOnce(ctx context.Context) {
	zm := rec.provider.Get()
	if zm == nil || !zm.IsInitialized() {
		rec.logger.Debug("reconcile skipped: no live Ziti manager")
		return
	}
	desired, err := rec.loadDesiredRoutes(ctx)
	if err != nil {
		rec.logger.Warn("reconcile: load desired failed", zap.Error(err))
		return
	}
	for _, d := range desired {
		rec.reconcileRoute(ctx, zm, d)
	}
	rec.logger.Info("reconcile pass complete", zap.Int("routes", len(desired)))
}
