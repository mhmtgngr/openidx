package access

import (
	"context"
	"fmt"
	"net"
	"strconv"
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
	// HostingModeDirect — the edge router hosts the service via a fixed host.v1
	// config. Used automatically for all BrowZer routes.
	HostingModeDirect = "direct"
	// HostingModeHop — the edge router hosts a per-app service whose host.v1
	// points at the shared TLS hop nginx; the hop SNI-demuxes and rewrites the
	// HTTP Host for Host-routed/https upstreams the BrowZer runtime cannot
	// address directly (it sends a fixed "Host: unknown"). REQUIRES an https
	// upstream: SNI demux only works when the runtime does WASM-TLS, so a
	// non-https hop route is misconfigured and is skipped (with a warning).
	HostingModeHop = "hop"
)

// isRouterHosted reports whether the edge router hosts the service itself via a
// host.v1 config (direct and hop). The two differ only in the host.v1 target:
// direct points at the route's to_url, hop points at the shared hop nginx addr.
func isRouterHosted(mode string) bool {
	return mode == HostingModeDirect || mode == HostingModeHop
}

// DesiredRoute is the reconciler's view of a ziti-enabled proxy_route.
type DesiredRoute struct {
	ServiceName    string
	ToURL          string
	HostingMode    string
	BrowZerEnabled bool
	// HopPort is the per-app hop listen port (base + sorted-index, via
	// assignHopPorts). For hop routes the host.v1 target is hopHost:HopPort so the
	// hop demuxes by PORT (the runtime sends no SNI). Stamped in reconcileOnce.
	HopPort int
}

// EffectiveMode resolves the hosting mode. An explicit "hop" hosting_mode wins
// over all other rules (including the BrowZer→direct promotion). BrowZer routes
// without an explicit mode are forced to "direct". Everything else defaults to
// "identity".
func (r DesiredRoute) EffectiveMode() string {
	if r.HostingMode == HostingModeHop {
		return HostingModeHop
	}
	if r.BrowZerEnabled {
		return HostingModeDirect
	}
	if r.HostingMode == HostingModeDirect {
		return HostingModeDirect
	}
	return HostingModeIdentity
}

// ParseHopAddr splits a "host:port" hop address, defaulting the port to 8095
// when absent/unparseable, so the reconciler's host.v1 target and the hop
// nginx listen port are always derived identically.
func ParseHopAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 8095
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p == 0 {
		return host, 8095
	}
	return host, p
}

// ZitiReconciler converges Ziti to the DB's desired state. One worker, a
// coalescing trigger channel, and a periodic safety-net tick — so concurrent
// mutation races cannot happen (the reconciler is the only mutator of Ziti).
type ZitiReconciler struct {
	db       *database.PostgresDB
	logger   *zap.Logger
	provider *ZitiProvider // source of the live ZitiManager
	period   time.Duration
	hopAddr  string // host:basePort of the shared hop nginx (parsed into hopHost + base)
	hopHost  string // host portion of hopAddr; cached by reconcileOnce for ensureService

	trigger  chan struct{}         // coalescing: buffered size 1
	runOnce  func(context.Context) // overridable in tests; defaults to reconcileOnce
	mu       sync.Mutex            // serializes runs
	statusMu sync.Mutex            // protects status map
	status   map[string]string     // serviceName -> "synced" | "error: ..."
}

// NewZitiReconciler creates a ZitiReconciler with a 30-second safety-net
// period. Call Start(ctx) to begin the reconcile loop.
func NewZitiReconciler(db *database.PostgresDB, logger *zap.Logger, provider *ZitiProvider, hopAddr string) *ZitiReconciler {
	rec := &ZitiReconciler{
		db:       db,
		logger:   logger.With(zap.String("component", "ziti-reconciler")),
		provider: provider,
		period:   30 * time.Second,
		hopAddr:  hopAddr,
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
		// identity mode is never valid for a BrowZer route — the BrowZer runtime
		// dials as #browzer-users, which identity-mode policies don't grant
		// (BrowZer error 1003). EffectiveMode auto-corrects it to direct; warn so
		// operators see the divergence and pick hop explicitly for external/HTTPS
		// upstreams (direct does end-to-end WASM TLS the browser must trust).
		if d.BrowZerEnabled && d.HostingMode == HostingModeIdentity {
			rec.logger.Warn("BrowZer route stored as identity mode; auto-correcting to router-hosted (direct) — set hosting_mode=hop for external/HTTPS upstreams",
				zap.String("svc", d.ServiceName),
				zap.String("effective_mode", d.EffectiveMode()))
		}
		out = append(out, d)
	}
	// Surface mid-iteration errors (e.g. a dropped connection) so a partial read
	// isn't mistaken for the full desired set.
	return out, rows.Err()
}

// hostV1Target returns the address/port the route's host.v1 config should point
// at. Direct mode targets the route's to_url; hop mode targets the shared hop
// nginx at the route's per-app port (stamped in reconcileOnce via assignHopPorts),
// falling back to the base hop addr if HopPort wasn't stamped.
func (rec *ZitiReconciler) hostV1Target(d DesiredRoute) (string, int) {
	if d.EffectiveMode() == HostingModeHop {
		h, base := ParseHopAddr(rec.hopAddr)
		if rec.hopHost != "" {
			h = rec.hopHost
		}
		p := d.HopPort
		if p == 0 {
			p = base
		}
		return h, p
	}
	return parseHostPort(d.ToURL)
}

// ensureService makes sure the Ziti service exists with its role attribute.
// Idempotent: looks up by name, creates the service via CreateService if absent
// (controller-only — the reconciler must NOT write back to proxy_routes/ziti_services;
// the DB is the source of truth), tolerating a create race, then ensures the
// service-name role attribute is set.
func (rec *ZitiReconciler) ensureService(ctx context.Context, zm *ZitiManager, d DesiredRoute) error {
	if existing, _ := zm.GetServiceByName(d.ServiceName); existing != nil {
		// Converge the host.v1 config of an EXISTING router-hosted service too: the
		// per-app hop port reshuffles when the hop-route set changes (sorted index),
		// so a previously-created config can drift. CreateHostV1ConfigFixed patches
		// the target in place (same config id, still attached), so the route
		// self-heals without manual deletion.
		if isRouterHosted(d.EffectiveMode()) {
			host, port := rec.hostV1Target(d)
			cfgID, cerr := zm.CreateHostV1ConfigFixed(ctx, d.ServiceName+"-host", host, port)
			if cerr != nil {
				return cerr
			}
			// Attach the config to the service if it isn't already — a service
			// created elsewhere (e.g. the feature-manager's SDK-mode toggle) exists
			// without it, so the router can't host it (→ 502 via a stale SDK terminator).
			if aerr := zm.EnsureServiceConfig(ctx, existing.ID, cfgID); aerr != nil {
				return aerr
			}
		}
		return rec.ensureServiceAttr(ctx, zm, existing.ID, d.ServiceName)
	}
	// Service does not exist; create it. Use the minimal management-API path
	// (controller-only — the reconciler must NOT write back to proxy_routes/
	// ziti_services; the DB is the source of truth). Direct mode attaches a fixed
	// host.v1 config so the edge router hosts the service itself; identity mode
	// uses a bare service that the access-proxy terminates via SDK Listen.
	var err error
	switch {
	case isRouterHosted(d.EffectiveMode()):
		host, port := rec.hostV1Target(d)
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
	if isRouterHosted(d.EffectiveMode()) {
		// The router hosts the service via host.v1, so Bind goes to the routers;
		// BrowZer clients (synced users) dial via #browzer-users.
		if err := zm.EnsureRouterRoleAttribute(ctx); err != nil {
			// A persistent failure here means the #ziti-routers Bind matches no
			// router, so the service silently has no host — warn, don't bury it.
			rec.logger.Warn("failed to tag routers with #ziti-routers", zap.Error(err))
		}
		bindIdentity = "#ziti-routers"
		dialIdentity = "#browzer-users"
	}
	// Use EnsureServicePolicy (upsert) rather than CreateServicePolicy so a
	// hosting-mode transition self-heals: a route Ziti-provisioned in identity
	// mode and later flipped to router-hosted (e.g. BrowZer enabled afterwards)
	// has its stale #access-proxy-clients Bind/Dial corrected to
	// #ziti-routers/#browzer-users. Plain create-if-exists left them stale,
	// surfacing as BrowZer error 1003 (service not dialable by #browzer-users).
	if _, err := zm.EnsureServicePolicy(ctx, "openidx-bind-"+d.ServiceName, "Bind",
		[]string{svcRole}, []string{bindIdentity}); err != nil {
		rec.logger.Warn("bind policy converge failed", zap.String("svc", d.ServiceName), zap.Error(err))
	}
	if _, err := zm.EnsureServicePolicy(ctx, "openidx-dial-"+d.ServiceName, "Dial",
		[]string{svcRole}, []string{dialIdentity}); err != nil {
		rec.logger.Warn("dial policy converge failed", zap.String("svc", d.ServiceName), zap.Error(err))
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
	switch {
	case d.EffectiveMode() == HostingModeIdentity:
		host, port := parseHostPort(d.ToURL)
		return zm.HostService(d.ServiceName, host, port)
	case isRouterHosted(d.EffectiveMode()):
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
	// Stamp each hop route's per-app listen port (base + sorted-index). The hop
	// nginx config uses the SAME assignHopPorts over the same service names, so a
	// route's host.v1 port and the hop's listen port are always identical.
	host, base := ParseHopAddr(rec.hopAddr)
	rec.hopHost = host
	var hopNames []string
	for _, d := range desired {
		if d.EffectiveMode() == HostingModeHop {
			hopNames = append(hopNames, d.ServiceName)
		}
	}
	ports := assignHopPorts(hopNames, base)
	for i := range desired {
		if desired[i].EffectiveMode() == HostingModeHop {
			desired[i].HopPort = ports[desired[i].ServiceName]
		}
	}
	for _, d := range desired {
		rec.reconcileRoute(ctx, zm, d)
	}
	rec.logger.Info("reconcile pass complete", zap.Int("routes", len(desired)))
}
